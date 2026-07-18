//! Neo X full-node executable based on Reth.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::Typed2718;
use alloy_primitives::{eip191_hash_message, Address, Bytes, Signature, B256, U256, U64};
use clap::Parser;
use futures::{Stream, StreamExt};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned, RpcModule};
use reth_chain_state::CanonStateSubscriptions;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_ethereum_cli::interface::Cli;
use reth_neox_antimev::{is_envelope, DkgKeyStore};
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_evm::{
    policy_storage_key, KEY_MANAGEMENT_PROXY_ADDRESS, POLICY_ENVELOPE_FEE_SLOT,
    POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_node::{
    cli_components, read_dkg_state, run_beacon_sync, BeaconSyncContext, DbftSigner, NeoXNode,
    NeoXSidecarStore,
};
use reth_provider::{BlockReaderIdExt, StateProvider, StateProviderFactory};
use reth_rpc_eth_api::helpers::{EthFees, EthTransactions};
use reth_rpc_server_types::RethRpcModule;
use reth_transaction_pool::{
    EthPoolTransaction, PoolTransaction, PoolTx, TransactionOrigin, TransactionValidationOutcome,
    ValidatingPool,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Neo X validator-only node arguments.
#[derive(Debug, Clone, Default, clap::Parser)]
struct NeoXNodeArgs {
    /// Path to a mode-0600 raw 32-byte or hex secp256k1 validator private key.
    #[arg(long = "validator.ecdsa-key", value_name = "FILE")]
    ecdsa_key: Option<PathBuf>,

    /// Path to a mode-0600 raw 32-byte or hex private share for the active DKG round.
    #[arg(long = "validator.dkg-key", value_name = "FILE", requires = "ecdsa_key")]
    dkg_key: Option<PathBuf>,

    /// Path to a mode-0600 raw 32-byte or hex reshared key for preceding-round Envelopes.
    #[arg(long = "validator.previous-dkg-key", value_name = "FILE", requires = "dkg_key")]
    previous_dkg_key: Option<PathBuf>,

    /// Directory containing mode-0600 `<round>.key` DKG shares, reloaded on round changes.
    #[arg(
        long = "validator.dkg-key-dir",
        value_name = "DIR",
        requires = "ecdsa_key",
        conflicts_with_all = ["dkg_key", "previous_dkg_key"]
    )]
    dkg_key_dir: Option<PathBuf>,

    /// Authenticated encrypted DKG state, including message key and current/previous shares.
    #[arg(
        long = "validator.dkg-keystore",
        value_name = "FILE",
        requires_all = ["ecdsa_key", "dkg_password_file"],
        conflicts_with_all = ["dkg_key", "previous_dkg_key", "dkg_key_dir"]
    )]
    dkg_keystore: Option<PathBuf>,

    /// Mode-0600 file containing the DKG keystore password; a trailing newline is removed.
    #[arg(long = "validator.dkg-password-file", value_name = "FILE", requires = "dkg_keystore")]
    dkg_password_file: Option<PathBuf>,

    /// Create and bind a fresh encrypted DKG keystore before launching the node.
    #[arg(long = "validator.dkg-init", requires = "dkg_keystore")]
    dkg_init: bool,

    /// Cache locally submitted secret transactions for Neo X Anti-MEV Envelope construction.
    #[arg(long = "txpool.amevcache")]
    amev_cache: bool,
}

impl NeoXNodeArgs {
    fn load_signer(&self) -> eyre::Result<Option<DbftSigner>> {
        let Some(path) = self.ecdsa_key.as_ref() else { return Ok(None) };
        let mut secret = read_private_key(path)?;
        let signer = DbftSigner::from_secret(&secret);
        secret.fill(0);
        let signer = signer?;
        let mut signer = if let Some(path) = self.dkg_key.as_ref() {
            let mut private_share = read_private_key(path)?;
            let result = signer.with_dkg_private_share(private_share);
            private_share.fill(0);
            result?
        } else {
            signer
        };
        if let Some(path) = self.previous_dkg_key.as_ref() {
            let mut private_share = read_private_key(path)?;
            let result = signer.with_previous_dkg_private_share(private_share);
            private_share.fill(0);
            signer = result?;
        }
        if let Some(path) = self.dkg_keystore.as_ref() {
            let password_path =
                self.dkg_password_file.as_ref().expect("clap requires a DKG password file");
            let password = read_password_file(password_path)?;
            let mut store = if self.dkg_init {
                DkgKeyStore::create_encrypted_for_validator(path, &password, signer.account())?
            } else {
                DkgKeyStore::load_encrypted(path, &password)?
            };
            let was_unbound = store.validator_address().is_none();
            store.bind_validator_address(signer.account())?;
            if was_unbound {
                store.save_encrypted(path, &password)?;
            }
            if let Some(current) = store.current_private_share() {
                signer = signer.with_dkg_private_share(*current.as_bytes())?;
            }
            if let Some(previous) = store.previous_private_share() {
                signer = signer.with_previous_dkg_private_share(*previous.as_bytes())?;
            }
            info!(
                target: "neox_reth::dkg",
                path = %path.display(),
                round = store.round(),
                validator = %signer.account(),
                message_public_key = %alloy_primitives::hex::encode_prefixed(store.message_public_key()),
                initialized = self.dkg_init,
                "Loaded encrypted Neo X DKG keystore"
            );
        }
        Ok(Some(signer))
    }
}

const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

fn read_password_file(path: &Path) -> eyre::Result<Zeroizing<Vec<u8>>> {
    let metadata = private_regular_file_metadata(path, "password")?;
    if metadata.len() == 0 || metadata.len() > MAX_PASSWORD_FILE_BYTES {
        eyre::bail!(
            "password file {} must contain between 1 and {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display()
        )
    }
    let mut password = Zeroizing::new(std::fs::read(path).map_err(|error| {
        eyre::eyre!("failed to read password file {}: {error}", path.display())
    })?);
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        eyre::bail!("password file {} contains only a newline", path.display())
    }
    Ok(password)
}

fn private_regular_file_metadata(path: &Path, kind: &str) -> eyre::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        eyre::eyre!("failed to inspect {kind} file {}: {error}", path.display())
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        eyre::bail!("refusing non-regular {kind} file {}", path.display())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            eyre::bail!(
                "refusing {kind} file {} with permissions {:o}; use chmod 600",
                path.display(),
                mode & 0o777
            )
        }
    }
    Ok(metadata)
}

fn read_private_key(path: &Path) -> eyre::Result<[u8; 32]> {
    private_regular_file_metadata(path, "key")?;
    let mut encoded = std::fs::read(path)
        .map_err(|error| eyre::eyre!("failed to read key file {}: {error}", path.display()))?;
    if encoded.len() == 32 {
        return Ok(encoded.try_into().expect("checked raw key length"))
    }
    let result = (|| {
        let encoded = std::str::from_utf8(&encoded)
            .map_err(|_| {
                eyre::eyre!("key file {} is neither raw bytes nor UTF-8 hex", path.display())
            })?
            .trim();
        let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
        if encoded.len() != 64 {
            eyre::bail!("key file {} must contain exactly 32 bytes", path.display())
        }
        let mut key = [0_u8; 32];
        alloy_primitives::hex::decode_to_slice(encoded, &mut key)
            .map_err(|_| eyre::eyre!("key file {} contains invalid hex", path.display()))?;
        Ok(key)
    })();
    encoded.fill(0);
    result
}

fn install_dkg_round_keys(
    provider: &impl StateProviderFactory,
    signer: &DbftSigner,
    directory: &Path,
    installed_round: Option<u64>,
) -> eyre::Result<Option<u64>> {
    let state = provider.latest()?;
    let dkg = read_dkg_state(state.as_ref())?;
    if installed_round == Some(dkg.current.round) {
        return Ok(None)
    }
    let current_path = directory.join(format!("{}.key", dkg.current.round));
    let mut current = read_private_key(&current_path)?;
    let mut previous = if let Some(previous) = dkg.previous.as_ref() {
        Some(read_private_key(&directory.join(format!("{}.key", previous.round)))?)
    } else {
        None
    };
    let result = signer.replace_dkg_private_shares(current, previous);
    current.fill(0);
    if let Some(previous) = previous.as_mut() {
        previous.fill(0);
    }
    result?;
    Ok(Some(dkg.current.round))
}

async fn run_dkg_key_reload<Provider, Notifications>(
    provider: Provider,
    signer: DbftSigner,
    directory: PathBuf,
    mut canonical: Notifications,
) where
    Provider: StateProviderFactory,
    Notifications: Stream + Unpin,
{
    let mut installed_round = None;
    loop {
        match install_dkg_round_keys(&provider, &signer, &directory, installed_round) {
            Ok(Some(round)) => {
                installed_round = Some(round);
                info!(target: "neox_reth::dkg", round, directory = %directory.display(), "Installed Neo X DKG round key files");
            }
            Ok(None) => {}
            Err(error) => {
                warn!(target: "neox_reth::dkg", %error, directory = %directory.display(), "Failed to install Neo X DKG round key files");
            }
        }
        if canonical.next().await.is_none() {
            return
        }
    }
}

fn policy_rpc_error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        -32000,
        format!("failed to read Neo X Policy state: {error}"),
        None::<()>,
    )
}

fn rpc_error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, error.to_string(), None::<()>)
}

fn latest_policy_slot(provider: &impl StateProviderFactory, slot: u64) -> RpcResult<U256> {
    provider
        .latest()
        .map_err(policy_rpc_error)?
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())
        .map(|value| value.unwrap_or_default())
        .map_err(policy_rpc_error)
}

fn policy_gas_price(standard_price: U256, base_fee: u64, minimum_tip: U256) -> U256 {
    if minimum_tip.is_zero() {
        standard_price
    } else {
        minimum_tip.saturating_add(U256::from(base_fee))
    }
}

const AMEV_CACHE_MAX_ENTRIES: usize = 5_120;
const AMEV_CACHE_LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);

#[derive(Debug, Clone)]
struct CachedTransaction {
    raw: Bytes,
    inserted_at: Instant,
}

#[derive(Debug)]
struct AntiMevCache {
    entries: Mutex<HashMap<(Address, u64), CachedTransaction>>,
    max_entries: usize,
    lifetime: Duration,
}

impl Default for AntiMevCache {
    fn default() -> Self {
        Self::new(AMEV_CACHE_MAX_ENTRIES, AMEV_CACHE_LIFETIME)
    }
}

impl AntiMevCache {
    fn new(max_entries: usize, lifetime: Duration) -> Self {
        Self { entries: Mutex::new(HashMap::new()), max_entries, lifetime }
    }

    fn insert(&self, sender: Address, nonce: u64, raw: Bytes) {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|error| error.into_inner());
        entries.retain(|_, cached| now.duration_since(cached.inserted_at) <= self.lifetime);
        let key = (sender, nonce);
        if !entries.contains_key(&key) && entries.len() >= self.max_entries {
            let oldest =
                entries.iter().min_by_key(|(_, cached)| cached.inserted_at).map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, CachedTransaction { raw, inserted_at: now });
    }

    fn get(&self, sender: Address, nonce: u64) -> Option<Bytes> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|error| error.into_inner());
        entries.retain(|_, cached| now.duration_since(cached.inserted_at) <= self.lifetime);
        entries.get(&(sender, nonce)).map(|cached| cached.raw.clone())
    }

    fn remove(&self, sender: Address, nonce: u64) {
        self.entries.lock().unwrap_or_else(|error| error.into_inner()).remove(&(sender, nonce));
    }
}

#[derive(Debug)]
enum CacheSubmission {
    Cached(B256),
    Forward(Bytes),
}

async fn validate_cache_submission<Pool>(
    pool: &Pool,
    cache: &AntiMevCache,
    raw: Bytes,
) -> Result<CacheSubmission, ErrorObjectOwned>
where
    Pool: ValidatingPool,
    PoolTx<Pool>: EthPoolTransaction,
{
    let transaction =
        <PoolTx<Pool> as PoolTransaction>::recover_raw_transaction(&raw).map_err(rpc_error)?;
    let recipient = transaction.kind().to().copied();
    let cacheable_type = matches!(transaction.ty(), 0..=2);
    if !cacheable_type ||
        is_envelope(transaction.ty(), recipient, transaction.input()) ||
        recipient == Some(KEY_MANAGEMENT_PROXY_ADDRESS)
    {
        return Ok(CacheSubmission::Forward(raw))
    }

    let sender = transaction.sender();
    let nonce = transaction.nonce();
    let hash = *transaction.hash();
    match ValidatingPool::validate(pool, TransactionOrigin::Local, transaction).await {
        TransactionValidationOutcome::Valid { .. } => {
            cache.insert(sender, nonce, raw);
            Ok(CacheSubmission::Cached(hash))
        }
        TransactionValidationOutcome::Invalid(_, error) => Err(rpc_error(error)),
        TransactionValidationOutcome::Error(_, error) => Err(rpc_error(error)),
    }
}

fn recover_cache_request_sender(nonce: u64, raw_signature: &[u8]) -> RpcResult<Address> {
    if raw_signature.len() != 65 {
        return Err(ErrorObjectOwned::owned(-32000, "signature length must be 65 bytes", None::<()>))
    }
    let signature = Signature::try_from(raw_signature).map_err(rpc_error)?;
    signature
        .recover_address_from_prehash(&eip191_hash_message(nonce.to_string().as_bytes()))
        .map_err(|error| {
            ErrorObjectOwned::owned(
                -32000,
                format!("signature verification failed: {error}"),
                None::<()>,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn dkg_key_requires_validator_identity() {
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-reth", "--validator.dkg-key", "dkg.key"]).is_err()
        );
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.previous-dkg-key",
            "previous.key",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-password-file",
            "password",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
            "--validator.dkg-password-file",
            "password",
            "--validator.dkg-key",
            "dkg.key",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
            "--validator.dkg-password-file",
            "password",
            "--validator.dkg-init",
        ])
        .is_ok());
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-reth", "--validator.dkg-key-dir", "keys"]).is_err()
        );
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-reth",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-key",
            "dkg.key",
            "--validator.dkg-key-dir",
            "keys",
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn reads_mode_0600_hex_key_and_rejects_open_permissions() {
        use std::{io::Write, os::unix::fs::PermissionsExt};

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "0x{}", "11".repeat(32)).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_key(file.path()).unwrap(), [0x11; 32]);

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_key(file.path()).unwrap_err().to_string().contains("chmod 600"));
    }

    #[cfg(unix)]
    #[test]
    fn reads_password_newline_and_rejects_symlinks() {
        use std::{
            io::Write,
            os::unix::fs::{symlink, PermissionsExt},
        };

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "validator-password").unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(file.path()).unwrap().as_slice(), b"validator-password");

        let link = file.path().with_extension("link");
        symlink(file.path(), &link).unwrap();
        assert!(read_password_file(&link).unwrap_err().to_string().contains("non-regular"));
    }

    #[cfg(unix)]
    #[test]
    fn initializes_and_reloads_validator_bound_dkg_keystore() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let validator_key = directory.path().join("validator.key");
        let password_file = directory.path().join("password");
        let keystore = directory.path().join("dkg.json");
        std::fs::write(&validator_key, [1_u8; 32]).unwrap();
        std::fs::write(&password_file, b"test validator password\n").unwrap();
        std::fs::set_permissions(&validator_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let initialized = NeoXNodeArgs {
            ecdsa_key: Some(validator_key.clone()),
            dkg_keystore: Some(keystore.clone()),
            dkg_password_file: Some(password_file.clone()),
            dkg_init: true,
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .unwrap()
        .unwrap();
        assert!(keystore.is_file());
        assert_eq!(std::fs::metadata(&keystore).unwrap().permissions().mode() & 0o777, 0o600);

        let restored = NeoXNodeArgs {
            ecdsa_key: Some(validator_key),
            dkg_keystore: Some(keystore.clone()),
            dkg_password_file: Some(password_file),
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .unwrap()
        .unwrap();
        assert_eq!(restored.account(), initialized.account());
        assert!(NeoXNodeArgs {
            ecdsa_key: Some(directory.path().join("validator.key")),
            dkg_keystore: Some(keystore),
            dkg_password_file: Some(directory.path().join("password")),
            dkg_init: true,
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .is_err());
    }

    #[test]
    fn policy_minimum_tip_overrides_the_standard_gas_oracle() {
        assert_eq!(policy_gas_price(U256::from(7), 20, U256::from(30)), U256::from(50));
        assert_eq!(policy_gas_price(U256::from(7), 20, U256::ZERO), U256::from(7));
    }

    #[test]
    fn anti_mev_cache_replaces_nonce_and_evicts_oldest_entry() {
        let cache = AntiMevCache::new(2, Duration::from_secs(60));
        let first = Address::repeat_byte(1);
        let second = Address::repeat_byte(2);
        cache.insert(first, 0, Bytes::from_static(&[1]));
        cache.insert(first, 0, Bytes::from_static(&[2]));
        assert_eq!(cache.get(first, 0), Some(Bytes::from_static(&[2])));

        cache.insert(second, 0, Bytes::from_static(&[3]));
        cache.insert(second, 1, Bytes::from_static(&[4]));
        assert_eq!(cache.get(first, 0), None);
        assert_eq!(cache.get(second, 0), Some(Bytes::from_static(&[3])));
        assert_eq!(cache.get(second, 1), Some(Bytes::from_static(&[4])));
    }

    #[test]
    fn recovers_geth_compatible_personal_sign_nonce() {
        use k256::ecdsa::SigningKey;

        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let key = SigningKey::from_bytes((&secret).into()).unwrap();
        let hash = eip191_hash_message(b"42");
        let (signature, recovery_id) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
        let mut raw = [0_u8; 65];
        raw[..64].copy_from_slice(&signature.to_bytes());
        raw[64] = recovery_id.to_byte();

        let expected: Address = "7e5f4552091a69125d5dfcb7b8c2659029395bdf".parse().unwrap();
        assert_eq!(recover_cache_request_sender(42, &raw).unwrap(), expected);
        raw[64] += 27;
        assert_eq!(recover_cache_request_sender(42, &raw).unwrap(), expected);
    }
}

/// Built-in and file-backed Neo X chain-spec parser.
#[derive(Debug, Clone, Default)]
struct NeoXChainSpecParser;

impl ChainSpecParser for NeoXChainSpecParser {
    type ChainSpec = NeoXChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] =
        &["mainnet", "testnet", "neox-mainnet", "neox-testnet"];

    fn parse(value: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        match value {
            "mainnet" | "neox-mainnet" => Ok(NeoXChainSpec::mainnet()?),
            "testnet" | "neox-testnet" => Ok(NeoXChainSpec::testnet()?),
            custom => Ok(Arc::new(NeoXChainSpec::from_genesis(parse_genesis(custom)?)?)),
        }
    }
}

fn main() {
    reth_cli_util::sigsegv_handler::install();
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        // SAFETY: this runs before the CLI initializes worker threads.
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    if let Err(error) =
        Cli::<NeoXChainSpecParser, NeoXNodeArgs>::parse().run_with_components::<NeoXNode>(
        cli_components,
        async move |builder, validator_args| {
            info!(target: "neox_reth::cli", "Launching Neo X full node");
            let signer = validator_args.load_signer()?;
            let enable_amev_cache = validator_args.amev_cache;
            let dkg_key_directory = validator_args.dkg_key_dir.clone();
            if let Some(signer) = signer.as_ref() {
                info!(target: "neox_reth::cli", account = %signer.account(), "Loaded Neo X validator identity");
            }
            let chain_spec = Arc::clone(&builder.config().chain);
            let sidecar_store = NeoXSidecarStore::open(
                builder.config().datadir().data_dir().join("neox-sidecars"),
            )?;
            let neox_node = NeoXNode::new(Arc::clone(&chain_spec)).with_sidecar_store();
            let beacon = neox_node.beacon_protocol().clone();
            let dbft = neox_node.dbft_protocol().clone();
            let events = neox_node
                .take_beacon_events()
                .expect("Neo X beacon receiver must be taken exactly once");
            let dbft_events = neox_node
                .take_dbft_events()
                .expect("Neo X dBFT receiver must be taken exactly once");
            let handle = builder
                .node(neox_node)
                .extend_rpc_modules(move |ctx| {
                    let amev_cache = enable_amev_cache.then(|| Arc::new(AntiMevCache::default()));
                    let mut module = RpcModule::new((
                        ctx.registry.eth_api().clone(),
                        ctx.provider().clone(),
                        ctx.pool().clone(),
                        amev_cache,
                    ));
                    module.register_async_method::<RpcResult<U256>, _, _>(
                        "eth_gasPrice",
                        |_, rpc, _| async move {
                            let (eth_api, provider, _, _) = rpc.as_ref();
                            let minimum_tip =
                                latest_policy_slot(provider, POLICY_MIN_GAS_TIP_CAP_SLOT)?;
                            if minimum_tip.is_zero() {
                                return EthFees::gas_price(eth_api)
                                    .await
                                    .map_err(policy_rpc_error)
                            }
                            let base_fee = provider
                                .latest_header()
                                .map_err(policy_rpc_error)?
                                .and_then(|header| header.base_fee_per_gas())
                                .unwrap_or_default();
                            Ok(policy_gas_price(U256::ZERO, base_fee, minimum_tip))
                        },
                    )?;
                    module.register_async_method::<RpcResult<U256>, _, _>(
                        "eth_envelopeFee",
                        |_, rpc, _| async move {
                            latest_policy_slot(&rpc.as_ref().1, POLICY_ENVELOPE_FEE_SLOT)
                        },
                    )?;
                    module.register_async_method::<RpcResult<U256>, _, _>(
                        "eth_maxEnvelopeGas",
                        |_, rpc, _| async move {
                            latest_policy_slot(
                                &rpc.as_ref().1,
                                POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT,
                            )
                        },
                    )?;
                    module.register_async_method::<RpcResult<Option<Bytes>>, _, _>(
                        "eth_getCachedTransaction",
                        |params, rpc, _| async move {
                            let (nonce, signature): (U64, Bytes) = params.parse()?;
                            let nonce = nonce.to::<u64>();
                            let sender = recover_cache_request_sender(nonce, &signature)?;
                            let (_, provider, _, cache) = rpc.as_ref();
                            let Some(cache) = cache else { return Ok(None) };

                            let state_nonce = provider
                                .latest()
                                .map_err(policy_rpc_error)?
                                .basic_account(&sender)
                                .map_err(policy_rpc_error)?
                                .map(|account| account.nonce)
                                .unwrap_or_default();
                            if nonce < state_nonce {
                                cache.remove(sender, nonce);
                                return Ok(None)
                            }
                            Ok(cache.get(sender, nonce))
                        },
                    )?;
                    if enable_amev_cache {
                        module.register_async_method::<RpcResult<B256>, _, _>(
                            "eth_sendRawTransaction",
                            |params, rpc, _| async move {
                                let raw: Bytes = params.one()?;
                                let (eth_api, _, pool, cache) = rpc.as_ref();
                                let cache = cache.as_ref().expect("enabled cache is installed");
                                match validate_cache_submission(pool, cache, raw).await? {
                                    CacheSubmission::Cached(hash) => {
                                        info!(target: "neox_reth::rpc", %hash, "Cached Anti-MEV secret transaction");
                                        Err(ErrorObjectOwned::owned(
                                            -32000,
                                            "transaction cached",
                                            None::<()>,
                                        ))
                                    }
                                    CacheSubmission::Forward(raw) => {
                                        EthTransactions::send_raw_transaction(eth_api, raw)
                                            .await
                                            .map_err(rpc_error)
                                    }
                                }
                            },
                        )?;
                        info!(target: "neox_reth::rpc", "Enabled Neo X Anti-MEV transaction cache");
                    }
                    ctx.modules.add_or_replace_if_module_configured(
                        RethRpcModule::Eth,
                        module,
                    )?;
                    info!(target: "neox_reth::rpc", "Installed Neo X Policy RPC methods");
                    Ok(())
                })
                .launch()
                .await?;
            let canonical = handle.node.provider.clone().canonical_state_stream();
            let dkg_canonical = handle.node.provider.clone().canonical_state_stream();
            let engine = handle.node.consensus_engine_handle().clone();
            let pool = handle.node.pool.clone();
            let provider = handle.node.provider.clone();
            if let (Some(dkg_signer), Some(directory)) =
                (signer.clone(), dkg_key_directory)
            {
                handle.node.task_executor.spawn_critical_task(
                    "neox dkg key reload",
                    run_dkg_key_reload(
                        provider.clone(),
                        dkg_signer,
                        directory,
                        dkg_canonical,
                    ),
                );
            }
            handle.node.task_executor.spawn_critical_task(
                "neox beacon sync",
                run_beacon_sync(BeaconSyncContext {
                    events,
                    dbft_events,
                    canonical,
                    beacon,
                    dbft,
                    engine,
                    pool,
                    provider,
                    chain_spec,
                    signer,
                    sidecar_store,
                }),
            );
            handle.wait_for_node_exit().await
        },
    ) {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}
