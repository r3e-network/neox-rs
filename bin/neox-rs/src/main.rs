//! Neo X full-node executable based on Reth.

mod dkg_runtime;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::{BlockNumHash, Typed2718};
use alloy_primitives::{eip191_hash_message, Address, Bytes, Signature, B256, U256, U64};
use clap::Parser;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned, RpcModule};
use reth_chain_state::{CanonStateNotification, CanonStateNotifications, CanonStateSubscriptions};
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_ethereum_cli::interface::Cli;
use reth_ethereum_primitives::EthPrimitives;
use reth_neox_antimev::{
    is_envelope, verify_aggregated_dkg_share, DkgKeyStore, DkgMessagePrivateKey,
};
use reth_neox_chainspec::{NeoXChainSpec, NEOX_MAINNET_CHAIN_ID, NEOX_TESTNET_CHAIN_ID};
use reth_neox_evm::{
    policy_storage_key, NeoXEvmConfig, KEY_MANAGEMENT_PROXY_ADDRESS, POLICY_ENVELOPE_FEE_SLOT,
    POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_node::{
    cli_components, read_dkg_canonical_round, read_dkg_state, read_governance_validator_set,
    run_beacon_sync, BeaconSyncContext, DbftSigner, DkgCanonicalRound, DkgProofArtifact, DkgProver,
    DkgProverArtifacts, DkgShareEpoch, DkgStateError, NeoXNode, NeoXSidecarStore,
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
use tokio::sync::{
    broadcast::error::{RecvError, TryRecvError},
    oneshot,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::dkg_runtime::{run_dkg_runtime, DkgRuntimeConfig};

/// Neo X validator-only node arguments.
#[derive(Debug, Clone, clap::Parser)]
struct NeoXNodeArgs {
    /// Acknowledge that validator mode on the public Neo X networks is experimental and not a
    /// stable validator-release qualification.
    #[arg(long = "validator.experimental")]
    experimental_validator: bool,

    /// Path to a mode-0600 raw 32-byte or hex secp256k1 validator private key.
    ///
    /// Validator mode forces the engine persistence threshold and memory block buffer target to
    /// zero, bounds persistence backpressure to one block, and disables persistence suppression.
    #[arg(long = "validator.ecdsa-key", value_name = "FILE")]
    ecdsa_key: Option<PathBuf>,

    /// Path to a mode-0600 raw 32-byte or hex private share for the active DKG round.
    #[arg(long = "validator.dkg-key", value_name = "FILE", requires = "ecdsa_key")]
    dkg_key: Option<PathBuf>,

    /// Path to a mode-0600 raw 32-byte or hex reshared key for preceding-round Envelopes.
    #[arg(long = "validator.previous-dkg-key", value_name = "FILE", requires = "dkg_key")]
    previous_dkg_key: Option<PathBuf>,

    /// Directory containing mode-0600 `<round>.key` DKG shares. Shares are PVSS-verified and
    /// head-bound; canonical reorgs or notification gaps disable this legacy mode. Use
    /// `dkg-keystore` for automatic branch-safe recovery.
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
        requires_all = ["ecdsa_key", "dkg_password_file", "dkg_prover"],
        conflicts_with_all = ["dkg_key", "previous_dkg_key", "dkg_key_dir"]
    )]
    dkg_keystore: Option<PathBuf>,

    /// Mode-0600 file containing the DKG keystore password; a trailing newline is removed.
    #[arg(long = "validator.dkg-password-file", value_name = "FILE", requires = "dkg_keystore")]
    dkg_password_file: Option<PathBuf>,

    /// Create and bind a fresh encrypted DKG keystore before launching the node.
    #[arg(long = "validator.dkg-init", requires = "dkg_keystore")]
    dkg_init: bool,

    /// Mode-0600 message private key already registered for a migrating validator.
    #[arg(
        long = "validator.dkg-message-key",
        value_name = "FILE",
        requires_all = ["dkg_keystore", "dkg_init"]
    )]
    dkg_message_key: Option<PathBuf>,

    /// Absolute path to the pinned Neo X DKG encryption/Groth16 helper executable.
    #[arg(long = "validator.dkg-prover", value_name = "FILE", requires = "dkg_keystore")]
    dkg_prover: Option<PathBuf>,

    /// JSON manifest containing absolute ZK-v1 R1CS/proving-key paths and SHA-256 digests.
    #[arg(long = "validator.dkg-prover-manifest", value_name = "FILE", requires = "dkg_prover")]
    dkg_prover_manifest: Option<PathBuf>,

    /// Deployed `KeyManagement` verifier version: 0 for proofless legacy, 1 for Groth16.
    #[arg(
        long = "validator.dkg-zk-version",
        default_value_t = 1,
        value_parser = clap::value_parser!(u64).range(0..=1)
    )]
    dkg_zk_version: u64,

    /// Cache locally submitted secret transactions for Neo X Anti-MEV Envelope construction.
    #[arg(long = "txpool.amevcache")]
    amev_cache: bool,
}

impl Default for NeoXNodeArgs {
    fn default() -> Self {
        Self {
            experimental_validator: false,
            ecdsa_key: None,
            dkg_key: None,
            previous_dkg_key: None,
            dkg_key_dir: None,
            dkg_keystore: None,
            dkg_password_file: None,
            dkg_init: false,
            dkg_message_key: None,
            dkg_prover: None,
            dkg_prover_manifest: None,
            dkg_zk_version: 1,
            amev_cache: false,
        }
    }
}

impl NeoXNodeArgs {
    fn load_validator(&self, chain_id: u64) -> eyre::Result<Option<LoadedValidator>> {
        let Some(path) = self.ecdsa_key.as_ref() else { return Ok(None) };
        if matches!(chain_id, NEOX_MAINNET_CHAIN_ID | NEOX_TESTNET_CHAIN_ID) &&
            !self.experimental_validator
        {
            eyre::bail!(
                "validator mode on public Neo X chains is experimental; pass \
                 --validator.experimental to acknowledge that this is not a stable validator release"
            );
        }
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
        let dkg_runtime = if let Some(path) = self.dkg_keystore.as_ref() {
            if self.dkg_zk_version == 1 && self.dkg_prover_manifest.is_none() {
                eyre::bail!(
                    "--validator.dkg-prover-manifest is required when \
                     --validator.dkg-zk-version=1"
                );
            }
            let password_path =
                self.dkg_password_file.as_ref().expect("clap requires a DKG password file");
            let password = read_password_file(password_path)?;
            let mut store = if self.dkg_init {
                if let Some(message_key_path) = self.dkg_message_key.as_ref() {
                    let mut encoded = read_private_key(message_key_path)?;
                    let message_key = DkgMessagePrivateKey::new(encoded);
                    encoded.fill(0);
                    DkgKeyStore::create_encrypted_for_validator_with_message_key(
                        path,
                        &password,
                        signer.account(),
                        message_key?,
                    )?
                } else {
                    DkgKeyStore::create_encrypted_for_validator(path, &password, signer.account())?
                }
            } else {
                DkgKeyStore::load_encrypted(path, &password)?
            };
            let was_unbound = store.validator_address().is_none();
            store.bind_validator_address(signer.account())?;
            if was_unbound {
                store.save_encrypted(path, &password)?;
            }
            // Managed keystore shares are installed only after the DKG runtime has reconciled the
            // current canonical state. Loading persisted shares here would allow a validator to
            // sign with an orphaned round during startup or immediately after a reorg.
            let prover_path = self.dkg_prover.as_ref().expect("clap requires a DKG prover");
            let prover = load_dkg_prover(prover_path, self.dkg_prover_manifest.as_deref())?;
            info!(
                target: "neox_rs::dkg",
                path = %path.display(),
                round = store.round(),
                validator = %signer.account(),
                message_public_key = %alloy_primitives::hex::encode_prefixed(store.message_public_key()),
                initialized = self.dkg_init,
                "Loaded encrypted Neo X DKG keystore"
            );
            Some(DkgRuntimeConfig {
                signer: signer.clone(),
                store,
                keystore_path: path.clone(),
                password,
                prover,
                zk_version: self.dkg_zk_version,
                chain_id,
            })
        } else {
            None
        };
        Ok(Some(LoadedValidator { signer, dkg_runtime }))
    }

    #[cfg(test)]
    fn load_signer(&self) -> eyre::Result<Option<DbftSigner>> {
        self.load_validator(47_763).map(|loaded| loaded.map(|loaded| loaded.signer))
    }
}

struct LoadedValidator {
    signer: DbftSigner,
    dkg_runtime: Option<DkgRuntimeConfig>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DkgProverManifest {
    one: DkgProverArtifactManifest,
    two: DkgProverArtifactManifest,
    seven: DkgProverArtifactManifest,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DkgProverArtifactManifest {
    r1cs_path: PathBuf,
    r1cs_sha256: String,
    proving_key_path: PathBuf,
    proving_key_sha256: String,
}

const MAX_DKG_PROVER_MANIFEST_BYTES: u64 = 64 * 1024;

fn load_dkg_prover(executable: &Path, manifest: Option<&Path>) -> eyre::Result<DkgProver> {
    let mut prover = DkgProver::new(executable)?;
    if let Some(path) = manifest {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            eyre::eyre!("failed to inspect DKG prover manifest {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            eyre::bail!("refusing non-regular DKG prover manifest {}", path.display());
        }
        if metadata.len() == 0 || metadata.len() > MAX_DKG_PROVER_MANIFEST_BYTES {
            eyre::bail!(
                "DKG prover manifest {} must contain between 1 and {MAX_DKG_PROVER_MANIFEST_BYTES} bytes",
                path.display()
            );
        }
        let encoded = std::fs::read(path).map_err(|error| {
            eyre::eyre!("failed to read DKG prover manifest {}: {error}", path.display())
        })?;
        let manifest: DkgProverManifest = serde_json::from_slice(&encoded).map_err(|error| {
            eyre::eyre!("invalid DKG prover manifest {}: {error}", path.display())
        })?;
        prover = prover.with_artifacts(DkgProverArtifacts::new(
            manifest.one.decode("one-message")?,
            manifest.two.decode("two-message")?,
            manifest.seven.decode("seven-message")?,
        ));
    }
    Ok(prover)
}

impl DkgProverArtifactManifest {
    fn decode(self, name: &str) -> eyre::Result<DkgProofArtifact> {
        let r1cs_sha256 = self
            .r1cs_sha256
            .parse::<B256>()
            .map_err(|error| eyre::eyre!("invalid {name} R1CS SHA-256 digest: {error}"))?;
        let proving_key_sha256 = self
            .proving_key_sha256
            .parse::<B256>()
            .map_err(|error| eyre::eyre!("invalid {name} proving-key SHA-256 digest: {error}"))?;
        Ok(DkgProofArtifact::new(
            self.r1cs_path,
            r1cs_sha256,
            self.proving_key_path,
            proving_key_sha256,
        )?)
    }
}

const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

fn read_password_file(path: &Path) -> eyre::Result<Zeroizing<Vec<u8>>> {
    let metadata = private_regular_file_metadata(path, "password")?;
    if metadata.len() == 0 || metadata.len() > MAX_PASSWORD_FILE_BYTES {
        eyre::bail!(
            "password file {} must contain between 1 and {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display()
        );
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
        eyre::bail!("password file {} contains only a newline", path.display());
    }
    Ok(password)
}

fn private_regular_file_metadata(path: &Path, kind: &str) -> eyre::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        eyre::eyre!("failed to inspect {kind} file {}: {error}", path.display())
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        eyre::bail!("refusing non-regular {kind} file {}", path.display());
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
            );
        }
    }
    Ok(metadata)
}

fn read_private_key(path: &Path) -> eyre::Result<[u8; 32]> {
    private_regular_file_metadata(path, "key")?;
    let mut encoded = std::fs::read(path)
        .map_err(|error| eyre::eyre!("failed to read key file {}: {error}", path.display()))?;
    if encoded.len() == 32 {
        // Copy out and wipe the source buffer rather than `try_into`, which would move the bytes
        // into the returned array and drop the heap `Vec` without zeroizing it — leaving the raw
        // private key in freed heap. This matches the hex path's `encoded.fill(0)` below.
        let mut key = [0_u8; 32];
        key.copy_from_slice(&encoded);
        encoded.fill(0);
        return Ok(key)
    }
    let result = (|| {
        let encoded = std::str::from_utf8(&encoded)
            .map_err(|_| {
                eyre::eyre!("key file {} is neither raw bytes nor UTF-8 hex", path.display())
            })?
            .trim();
        let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
        if encoded.len() != 64 {
            eyre::bail!("key file {} must contain exactly 32 bytes", path.display());
        }
        let mut key = [0_u8; 32];
        alloy_primitives::hex::decode_to_slice(encoded, &mut key)
            .map_err(|_| eyre::eyre!("key file {} contains invalid hex", path.display()))?;
        Ok(key)
    })();
    encoded.fill(0);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DkgRoundKeyLoad {
    Inactive,
    Installed { round: u64 },
}

#[derive(Debug)]
struct CanonicalDkgPvssInputs<'a> {
    current: Vec<&'a [u8]>,
    previous: Option<Vec<&'a [u8]>>,
}

fn canonical_dkg_pvss_inputs(
    canonical: &DkgCanonicalRound,
    has_previous: bool,
) -> CanonicalDkgPvssInputs<'_> {
    CanonicalDkgPvssInputs {
        current: canonical.shares.iter().map(|entry| entry.pvss.as_ref()).collect(),
        previous: has_previous
            .then(|| canonical.reshares.iter().map(|entry| entry.pvss.as_ref()).collect()),
    }
}

fn install_dkg_round_keys(
    provider: &impl StateProviderFactory,
    signer: &DbftSigner,
    directory: &Path,
    canonical_head: B256,
) -> eyre::Result<DkgRoundKeyLoad> {
    let state = provider.state_by_block_hash(canonical_head)?;
    let dkg = match read_dkg_state(state.as_ref()) {
        Ok(dkg) => dkg,
        Err(DkgStateError::MissingCurrentRound) => return Ok(DkgRoundKeyLoad::Inactive),
        Err(error) => return Err(error.into()),
    };
    let validators = read_governance_validator_set(state.as_ref())?;
    let validator_index = validators
        .original
        .iter()
        .position(|validator| *validator == signer.account())
        .and_then(|index| u64::try_from(index + 1).ok())
        .ok_or_else(|| {
            eyre::eyre!("validator {} is absent from canonical Governance order", signer.account())
        })?;
    let canonical = read_dkg_canonical_round(state.as_ref(), dkg.current.round)?;
    let pvsses = canonical_dkg_pvss_inputs(&canonical, dkg.previous.is_some());

    let current =
        Zeroizing::new(read_private_key(&directory.join(format!("{}.key", dkg.current.round)))?);
    verify_aggregated_dkg_share(validator_index, &current, &pvsses.current)?;
    let previous = if let Some(previous) = dkg.previous.as_ref() {
        let secret =
            Zeroizing::new(read_private_key(&directory.join(format!("{}.key", previous.round)))?);
        verify_aggregated_dkg_share(
            validator_index,
            &secret,
            pvsses.previous.as_ref().expect("previous DKG inputs requested"),
        )?;
        Some(secret)
    } else {
        None
    };

    let current_epoch =
        DkgShareEpoch::new(dkg.current.round, dkg.current.global_public_key, canonical_head);
    let previous_epoch = dkg.previous.as_ref().map(|previous| {
        DkgShareEpoch::new(previous.round, previous.global_public_key, canonical_head)
    });
    let previous = previous.as_ref().zip(previous_epoch).map(|(secret, epoch)| (**secret, epoch));
    signer.replace_canonical_dkg_private_shares(Some((*current, current_epoch)), previous)?;
    Ok(DkgRoundKeyLoad::Installed { round: dkg.current.round })
}

fn ensure_canonical_dkg_mapping(
    provider: &(impl BlockReaderIdExt<Header = alloy_consensus::Header> + ?Sized),
    heads: impl IntoIterator<Item = BlockNumHash>,
) -> eyre::Result<()> {
    for BlockNumHash { number, hash } in heads {
        let actual = provider.block_hash(number)?;
        if actual != Some(hash) {
            eyre::bail!(
                "canonical DKG block {hash} at height {number} is detached; canonical mapping contains {actual:?}"
            );
        }
    }
    Ok(())
}

fn canonical_dkg_head(
    provider: &(impl BlockReaderIdExt<Header = alloy_consensus::Header> + ?Sized),
) -> eyre::Result<BlockNumHash> {
    let info = provider.chain_info()?;
    let head = BlockNumHash { number: info.best_number, hash: info.best_hash };
    ensure_canonical_dkg_mapping(provider, [head])?;
    Ok(head)
}

#[derive(Debug)]
enum DkgRoundKeyReloadError {
    Fence(eyre::Report),
    Load(eyre::Report),
}

fn reload_dkg_round_keys_at_head(
    provider: &(impl BlockReaderIdExt<Header = alloy_consensus::Header> + StateProviderFactory),
    signer: &DbftSigner,
    directory: &Path,
    head: BlockNumHash,
    fence: &[BlockNumHash],
) -> Result<DkgRoundKeyLoad, DkgRoundKeyReloadError> {
    ensure_canonical_dkg_mapping(provider, fence.iter().copied())
        .map_err(DkgRoundKeyReloadError::Fence)?;
    let loaded = install_dkg_round_keys(provider, signer, directory, head.hash)
        .map_err(DkgRoundKeyReloadError::Load)?;
    ensure_canonical_dkg_mapping(provider, fence.iter().copied())
        .map_err(DkgRoundKeyReloadError::Fence)?;
    Ok(loaded)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DkgCommitContinuityError {
    Empty,
    StartsAtGenesis,
    HeightOverflow { previous: u64 },
    Height { expected: u64, actual: u64 },
    Parent { height: u64, expected: B256, actual: B256 },
}

impl std::fmt::Display for DkgCommitContinuityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty canonical Commit notification"),
            Self::StartsAtGenesis => {
                formatter.write_str("canonical Commit notification unexpectedly starts at genesis")
            }
            Self::HeightOverflow { previous } => {
                write!(formatter, "canonical Commit height overflows after {previous}")
            }
            Self::Height { expected, actual } => write!(
                formatter,
                "noncontiguous canonical Commit height: expected {expected}, got {actual}"
            ),
            Self::Parent { height, expected, actual } => write!(
                formatter,
                "canonical Commit block {height} has parent {actual}, expected {expected}"
            ),
        }
    }
}

fn next_canonical_dkg_head(
    mut previous: BlockNumHash,
    blocks: impl IntoIterator<Item = (u64, B256, B256)>,
) -> Result<BlockNumHash, DkgCommitContinuityError> {
    let mut seen = false;
    for (number, parent_hash, hash) in blocks {
        let expected = previous
            .number
            .checked_add(1)
            .ok_or(DkgCommitContinuityError::HeightOverflow { previous: previous.number })?;
        if number != expected {
            return Err(DkgCommitContinuityError::Height { expected, actual: number })
        }
        if parent_hash != previous.hash {
            return Err(DkgCommitContinuityError::Parent {
                height: number,
                expected: previous.hash,
                actual: parent_hash,
            })
        }
        previous = BlockNumHash { number, hash };
        seen = true;
    }
    seen.then_some(previous).ok_or(DkgCommitContinuityError::Empty)
}

fn standalone_canonical_dkg_segment_tip(
    blocks: &[(u64, B256, B256)],
) -> Result<BlockNumHash, DkgCommitContinuityError> {
    let (number, parent_hash, _) = blocks.first().ok_or(DkgCommitContinuityError::Empty)?;
    let previous = number.checked_sub(1).ok_or(DkgCommitContinuityError::StartsAtGenesis)?;
    next_canonical_dkg_head(
        BlockNumHash { number: previous, hash: *parent_hash },
        blocks.iter().copied(),
    )
}

#[derive(Debug)]
enum DkgCommitReload {
    Installed { head: BlockNumHash, round: u64 },
    Inactive { head: BlockNumHash },
    Retry { head: BlockNumHash, error: String },
}

fn reconcile_dkg_commit(
    provider: &(impl BlockReaderIdExt<Header = alloy_consensus::Header> + StateProviderFactory),
    signer: &DbftSigner,
    directory: &Path,
    previous: BlockNumHash,
    blocks: &[(u64, B256, B256)],
) -> Result<DkgCommitReload, String> {
    let head = next_canonical_dkg_head(previous, blocks.iter().copied())
        .map_err(|error| error.to_string())?;
    let fence = std::iter::once(previous)
        .chain(blocks.iter().map(|(number, _, hash)| BlockNumHash { number: *number, hash: *hash }))
        .collect::<Vec<_>>();
    match reload_dkg_round_keys_at_head(provider, signer, directory, head, &fence) {
        Ok(DkgRoundKeyLoad::Installed { round }) => Ok(DkgCommitReload::Installed { head, round }),
        Ok(DkgRoundKeyLoad::Inactive) => Ok(DkgCommitReload::Inactive { head }),
        Err(DkgRoundKeyReloadError::Load(error)) => {
            Ok(DkgCommitReload::Retry { head, error: error.to_string() })
        }
        Err(DkgRoundKeyReloadError::Fence(error)) => Err(error.to_string()),
    }
}

fn clear_dkg_round_keys(signer: &DbftSigner, directory: &Path, reason: &str) {
    if let Err(error) = signer.replace_optional_dkg_private_shares(None, None) {
        warn!(target: "neox_rs::dkg", %error, %reason, directory = %directory.display(), "Failed to clear Neo X DKG round keys");
    }
}

fn disable_dkg_key_reload(signer: &DbftSigner, directory: &Path, reason: &str) {
    clear_dkg_round_keys(signer, directory, reason);
    warn!(target: "neox_rs::dkg", %reason, directory = %directory.display(), "Permanently disabled legacy Neo X DKG key-directory reload for this process");
}

fn record_dkg_commit_reload(
    signer: &DbftSigner,
    directory: &Path,
    outcome: DkgCommitReload,
    last_head: &mut BlockNumHash,
    retry: &mut bool,
) {
    match outcome {
        DkgCommitReload::Installed { head, round } => {
            *last_head = head;
            *retry = false;
            info!(target: "neox_rs::dkg", round, height = head.number, hash = %head.hash, directory = %directory.display(), "Installed canonical and PVSS-verified Neo X DKG round key files");
        }
        DkgCommitReload::Inactive { head } => {
            *last_head = head;
            *retry = false;
            clear_dkg_round_keys(signer, directory, "canonical DKG has no settled round");
        }
        DkgCommitReload::Retry { head, error } => {
            *last_head = head;
            *retry = true;
            clear_dkg_round_keys(signer, directory, &error);
            warn!(target: "neox_rs::dkg", %error, height = head.number, hash = %head.hash, directory = %directory.display(), "Failed to load PVSS-verified Neo X DKG round keys; retrying this canonical tip");
        }
    }
}

async fn run_dkg_key_reload<Provider>(
    provider: Provider,
    signer: DbftSigner,
    directory: PathBuf,
    mut canonical: CanonStateNotifications<EthPrimitives>,
    startup_ready: oneshot::Sender<Result<(), String>>,
) where
    Provider: BlockReaderIdExt<Header = alloy_consensus::Header> + StateProviderFactory,
{
    let startup_snapshot = match canonical_dkg_head(&provider) {
        Ok(head) => head,
        Err(error) => {
            disable_dkg_key_reload(&signer, &directory, &error.to_string());
            let _ = startup_ready.send(Ok(()));
            return
        }
    };
    let mut last_head = startup_snapshot;
    let mut retry = false;
    match reload_dkg_round_keys_at_head(
        &provider,
        &signer,
        &directory,
        startup_snapshot,
        &[startup_snapshot],
    ) {
        Ok(DkgRoundKeyLoad::Installed { round }) => {
            info!(target: "neox_rs::dkg", round, height = startup_snapshot.number, hash = %startup_snapshot.hash, directory = %directory.display(), "Installed initial canonical and PVSS-verified Neo X DKG round key files");
        }
        Ok(DkgRoundKeyLoad::Inactive) => {
            clear_dkg_round_keys(&signer, &directory, "canonical DKG has no settled round");
            info!(target: "neox_rs::dkg", height = startup_snapshot.number, hash = %startup_snapshot.hash, directory = %directory.display(), "Neo X DKG has no settled round; legacy key reload is watching canonical commits");
        }
        Err(DkgRoundKeyReloadError::Load(error)) => {
            retry = true;
            clear_dkg_round_keys(&signer, &directory, &error.to_string());
            warn!(target: "neox_rs::dkg", %error, height = startup_snapshot.number, hash = %startup_snapshot.hash, directory = %directory.display(), "Initial Neo X DKG key load failed closed; node startup may continue while this canonical tip is retried");
        }
        Err(DkgRoundKeyReloadError::Fence(error)) => {
            disable_dkg_key_reload(&signer, &directory, &error.to_string());
            let _ = startup_ready.send(Ok(()));
            return
        }
    }

    // The receiver is subscribed before the initial snapshot. Consume its buffered prefix before
    // releasing readiness so notifications already represented by that snapshot are not applied
    // twice, while any later commits are reconciled strictly in order.
    loop {
        let notification = match canonical.try_recv() {
            Ok(notification) => notification,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Closed) => {
                disable_dkg_key_reload(
                    &signer,
                    &directory,
                    "canonical notification channel closed during initial reconciliation",
                );
                let _ = startup_ready.send(Ok(()));
                return
            }
            Err(TryRecvError::Lagged(skipped)) => {
                let reason = format!(
                    "canonical notification receiver lagged by {skipped} events during initial reconciliation"
                );
                disable_dkg_key_reload(&signer, &directory, &reason);
                let _ = startup_ready.send(Ok(()));
                return
            }
        };
        let CanonStateNotification::Commit { new } = notification else {
            disable_dkg_key_reload(
                &signer,
                &directory,
                "canonical reorg observed during initial DKG key reconciliation",
            );
            let _ = startup_ready.send(Ok(()));
            return
        };
        let blocks = new
            .headers()
            .map(|header| (header.number(), header.parent_hash(), header.hash()))
            .collect::<Vec<_>>();
        let segment_tip = match standalone_canonical_dkg_segment_tip(&blocks) {
            Ok(tip) => tip,
            Err(error) => {
                disable_dkg_key_reload(&signer, &directory, &error.to_string());
                let _ = startup_ready.send(Ok(()));
                return
            }
        };
        if segment_tip.number <= startup_snapshot.number {
            let heads = blocks
                .iter()
                .map(|(number, _, hash)| BlockNumHash { number: *number, hash: *hash });
            if let Err(error) = ensure_canonical_dkg_mapping(&provider, heads) {
                disable_dkg_key_reload(&signer, &directory, &error.to_string());
                let _ = startup_ready.send(Ok(()));
                return
            }
            continue
        }
        match reconcile_dkg_commit(&provider, &signer, &directory, last_head, &blocks) {
            Ok(outcome) => {
                record_dkg_commit_reload(&signer, &directory, outcome, &mut last_head, &mut retry);
            }
            Err(reason) => {
                disable_dkg_key_reload(&signer, &directory, &reason);
                let _ = startup_ready.send(Ok(()));
                return
            }
        }
    }
    let _ = startup_ready.send(Ok(()));

    loop {
        let notification = if retry {
            tokio::time::timeout(Duration::from_secs(1), canonical.recv()).await.ok()
        } else {
            Some(canonical.recv().await)
        };
        let Some(notification) = notification else {
            match reload_dkg_round_keys_at_head(
                &provider,
                &signer,
                &directory,
                last_head,
                &[last_head],
            ) {
                Ok(DkgRoundKeyLoad::Installed { round }) => {
                    retry = false;
                    info!(target: "neox_rs::dkg", round, height = last_head.number, hash = %last_head.hash, directory = %directory.display(), "Installed retried canonical and PVSS-verified Neo X DKG round key files");
                }
                Ok(DkgRoundKeyLoad::Inactive) => {
                    retry = false;
                    clear_dkg_round_keys(&signer, &directory, "canonical DKG has no settled round");
                }
                Err(DkgRoundKeyReloadError::Load(error)) => {
                    clear_dkg_round_keys(&signer, &directory, &error.to_string());
                    warn!(target: "neox_rs::dkg", %error, height = last_head.number, hash = %last_head.hash, directory = %directory.display(), "Failed to retry PVSS-verified Neo X DKG round keys");
                }
                Err(DkgRoundKeyReloadError::Fence(error)) => {
                    disable_dkg_key_reload(&signer, &directory, &error.to_string());
                    return
                }
            }
            continue
        };
        let notification = match notification {
            Ok(notification) => notification,
            Err(RecvError::Lagged(skipped)) => {
                let reason = format!("canonical notification receiver lagged by {skipped} events");
                disable_dkg_key_reload(&signer, &directory, &reason);
                return
            }
            Err(RecvError::Closed) => {
                disable_dkg_key_reload(
                    &signer,
                    &directory,
                    "canonical notification channel closed",
                );
                return
            }
        };
        let CanonStateNotification::Commit { new } = notification else {
            disable_dkg_key_reload(
                &signer,
                &directory,
                "canonical reorg observed by legacy DKG key reload",
            );
            return
        };
        let blocks = new
            .headers()
            .map(|header| (header.number(), header.parent_hash(), header.hash()))
            .collect::<Vec<_>>();
        match reconcile_dkg_commit(&provider, &signer, &directory, last_head, &blocks) {
            Ok(outcome) => {
                record_dkg_commit_reload(&signer, &directory, outcome, &mut last_head, &mut retry);
            }
            Err(reason) => {
                disable_dkg_key_reload(&signer, &directory, &reason);
                return
            }
        }
    }
}

/// JSON-RPC error code Neo X custom methods return for server-side rejections.
const POLICY_RPC_ERROR_CODE: i32 = -32000;

fn policy_rpc_error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        POLICY_RPC_ERROR_CODE,
        format!("failed to read Neo X Policy state: {error}"),
        None::<()>,
    )
}

fn rpc_error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(POLICY_RPC_ERROR_CODE, error.to_string(), None::<()>)
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
        return Err(rpc_error("signature length must be 65 bytes"))
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
    use reth_neox_node::DkgStoredContribution;

    #[cfg(target_os = "linux")]
    fn trusted_test_prover(directory: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        const ELF64_HEADER_LEN: usize = 64;
        const ELF64_PROGRAM_HEADER_LEN: usize = 56;
        const IMAGE_BASE: u64 = 0x40_0000;

        #[cfg(target_arch = "x86_64")]
        const ELF_MACHINE: u16 = 62;
        #[cfg(target_arch = "x86_64")]
        const EXIT_SUCCESS: &[u8] = &[0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
        #[cfg(target_arch = "aarch64")]
        const ELF_MACHINE: u16 = 183;
        #[cfg(target_arch = "aarch64")]
        const EXIT_SUCCESS: &[u8] =
            &[0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4];
        #[cfg(target_arch = "riscv64")]
        const ELF_MACHINE: u16 = 243;
        #[cfg(target_arch = "riscv64")]
        const EXIT_SUCCESS: &[u8] =
            &[0x13, 0x05, 0x00, 0x00, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00];

        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let code_offset = ELF64_HEADER_LEN + ELF64_PROGRAM_HEADER_LEN;
        let image_len = code_offset + EXIT_SUCCESS.len();
        let mut elf = vec![0_u8; image_len];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&ELF_MACHINE.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&(IMAGE_BASE + code_offset as u64).to_le_bytes());
        elf[32..40].copy_from_slice(&(ELF64_HEADER_LEN as u64).to_le_bytes());
        elf[52..54].copy_from_slice(&(ELF64_HEADER_LEN as u16).to_le_bytes());
        elf[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_LEN as u16).to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());

        let program = &mut elf[ELF64_HEADER_LEN..code_offset];
        program[..4].copy_from_slice(&1_u32.to_le_bytes());
        program[4..8].copy_from_slice(&5_u32.to_le_bytes());
        program[16..24].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        program[24..32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        program[32..40].copy_from_slice(&(image_len as u64).to_le_bytes());
        program[40..48].copy_from_slice(&(image_len as u64).to_le_bytes());
        program[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[code_offset..].copy_from_slice(EXIT_SUCCESS);

        let prover = directory.join("prover");
        std::fs::write(&prover, elf).unwrap();
        std::fs::set_permissions(&prover, std::fs::Permissions::from_mode(0o700)).unwrap();
        prover
    }

    #[test]
    fn dkg_key_requires_validator_identity() {
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-rs", "--validator.dkg-key", "dkg.key"]).is_err()
        );
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.previous-dkg-key",
            "previous.key",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-password-file",
            "password",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
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
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
            "--validator.dkg-password-file",
            "password",
            "--validator.dkg-prover",
            "/tmp/dkg-prover",
            "--validator.dkg-init",
        ])
        .is_ok());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.dkg-message-key",
            "message.key",
        ])
        .is_err());
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-keystore",
            "dkg.json",
            "--validator.dkg-password-file",
            "password",
            "--validator.dkg-prover",
            "/tmp/dkg-prover",
            "--validator.dkg-init",
            "--validator.dkg-message-key",
            "message.key",
        ])
        .is_ok());
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-rs", "--validator.dkg-zk-version", "2",]).is_err()
        );
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-rs", "--validator.dkg-key-dir", "keys"]).is_err()
        );
        assert!(NeoXNodeArgs::try_parse_from([
            "neox-rs",
            "--validator.ecdsa-key",
            "validator.key",
            "--validator.dkg-key",
            "dkg.key",
            "--validator.dkg-key-dir",
            "keys",
        ])
        .is_err());
    }

    #[test]
    fn public_validator_requires_experimental_acknowledgement() {
        let args = NeoXNodeArgs {
            ecdsa_key: Some(PathBuf::from("unused-validator.key")),
            ..NeoXNodeArgs::default()
        };

        let error = match args.load_validator(NEOX_MAINNET_CHAIN_ID) {
            Ok(_) => panic!("public validator startup unexpectedly passed without acknowledgement"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--validator.experimental"));
    }

    #[test]
    fn validator_mode_forces_immediate_engine_persistence() {
        let mut cli = Cli::<NeoXChainSpecParser, NeoXNodeArgs>::try_parse_from([
            "neox-rs",
            "node",
            "--validator.ecdsa-key",
            "validator.key",
            "--engine.persistence-threshold",
            "9",
            "--engine.memory-block-buffer-target",
            "4",
            "--engine.persistence-backpressure-threshold",
            "10",
            "--engine.suppress-persistence-during-build",
        ])
        .unwrap();

        assert_eq!(
            enforce_validator_engine_persistence(&mut cli),
            Some(ValidatorEngineOverride {
                configured_persistence_threshold: 9,
                configured_memory_block_buffer_target: 4,
                configured_persistence_backpressure_threshold: 10,
                configured_suppress_persistence_during_build: true,
            })
        );
        let command = cli.as_node_command_mut().unwrap();
        assert_eq!(command.engine.persistence_threshold, 0);
        assert_eq!(command.engine.memory_block_buffer_target(), 0);
        assert_eq!(command.engine.persistence_backpressure_threshold(), 1);
        assert!(!command.engine.suppress_persistence_during_build);
        command.engine.validate().unwrap();
        assert_eq!(command.engine.tree_config().persistence_threshold(), 0);
        assert_eq!(command.engine.tree_config().memory_block_buffer_target(), 0);
        assert_eq!(command.engine.tree_config().persistence_backpressure_threshold(), 1);
        assert!(!command.engine.tree_config().suppress_persistence_during_build());
    }

    #[test]
    fn full_node_preserves_configured_engine_persistence() {
        let mut cli = Cli::<NeoXChainSpecParser, NeoXNodeArgs>::try_parse_from([
            "neox-rs",
            "node",
            "--engine.persistence-threshold",
            "9",
            "--engine.memory-block-buffer-target",
            "4",
        ])
        .unwrap();

        assert_eq!(enforce_validator_engine_persistence(&mut cli), None);
        let command = cli.as_node_command_mut().unwrap();
        assert_eq!(command.engine.persistence_threshold, 9);
        assert_eq!(command.engine.memory_block_buffer_target(), 4);
    }

    #[test]
    fn validator_mode_normalizes_upstream_engine_defaults() {
        let mut cli = Cli::<NeoXChainSpecParser, NeoXNodeArgs>::try_parse_from([
            "neox-rs",
            "node",
            "--validator.ecdsa-key",
            "validator.key",
        ])
        .unwrap();

        let configured = enforce_validator_engine_persistence(&mut cli).unwrap();
        assert!(configured.configured_persistence_threshold > 0);
        assert!(configured.configured_memory_block_buffer_target > 0);
        let command = cli.as_node_command_mut().unwrap();
        assert_eq!(command.engine.persistence_threshold, 0);
        assert_eq!(command.engine.memory_block_buffer_target, Some(0));
        assert_eq!(command.engine.persistence_backpressure_threshold, Some(1));
        assert!(!command.engine.suppress_persistence_during_build);
        command.engine.validate().unwrap();
    }

    #[tokio::test]
    async fn validator_startup_readiness_detects_stopped_beacon_sync() {
        let (_startup_ready_tx, startup_ready_rx) = oneshot::channel();
        let mut beacon_sync = tokio::spawn(async {});

        let error =
            wait_for_validator_startup(startup_ready_rx, &mut beacon_sync, "Neo X DKG runtime")
                .await
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("Neo X beacon sync stopped before Neo X DKG runtime became ready"));
    }

    #[tokio::test]
    async fn validator_startup_readiness_accepts_reconciled_component() {
        let (startup_ready_tx, startup_ready_rx) = oneshot::channel();
        startup_ready_tx.send(Ok(())).unwrap();
        let mut beacon_sync = tokio::spawn(std::future::pending::<()>());

        wait_for_validator_startup(startup_ready_rx, &mut beacon_sync, "Neo X DKG runtime")
            .await
            .unwrap();

        beacon_sync.abort();
    }

    #[test]
    fn selects_current_shares_and_same_round_reshares_for_legacy_keys() {
        let contribution = |sender_index, marker: &'static [u8]| DkgStoredContribution {
            round: 8,
            sender_index,
            pvss: Bytes::from_static(marker),
            messages: Vec::new(),
        };
        let canonical = DkgCanonicalRound {
            round: 8,
            shares: vec![contribution(1, b"current-1"), contribution(2, b"current-2")],
            reshares: vec![contribution(1, b"previous-1"), contribution(2, b"previous-2")],
        };

        let inputs = canonical_dkg_pvss_inputs(&canonical, true);
        assert_eq!(inputs.current, vec![b"current-1".as_slice(), b"current-2".as_slice()]);
        assert_eq!(inputs.previous, Some(vec![b"previous-1".as_slice(), b"previous-2".as_slice()]));
        assert!(canonical_dkg_pvss_inputs(&canonical, false).previous.is_none());
    }

    #[test]
    fn canonical_dkg_commits_require_strict_height_and_parent_continuity() {
        let h10 = B256::repeat_byte(10);
        let h11 = B256::repeat_byte(11);
        let h12 = B256::repeat_byte(12);
        let h13 = B256::repeat_byte(13);
        let previous = BlockNumHash { number: 10, hash: h10 };
        let blocks = [(11, h10, h11), (12, h11, h12)];

        let tip = next_canonical_dkg_head(previous, blocks).unwrap();
        assert_eq!(tip, BlockNumHash { number: 12, hash: h12 });
        assert_eq!(
            next_canonical_dkg_head(tip, [(13, h12, h13)]).unwrap(),
            BlockNumHash { number: 13, hash: h13 }
        );
        assert_eq!(next_canonical_dkg_head(previous, []), Err(DkgCommitContinuityError::Empty));
        assert_eq!(
            next_canonical_dkg_head(previous, [(12, h10, h12)]),
            Err(DkgCommitContinuityError::Height { expected: 11, actual: 12 })
        );
        assert_eq!(
            next_canonical_dkg_head(previous, [(11, B256::repeat_byte(99), h11)]),
            Err(DkgCommitContinuityError::Parent {
                height: 11,
                expected: h10,
                actual: B256::repeat_byte(99),
            })
        );
        assert_eq!(
            next_canonical_dkg_head(previous, [(11, h10, h11), (13, h11, h13)]),
            Err(DkgCommitContinuityError::Height { expected: 12, actual: 13 })
        );
        assert_eq!(
            next_canonical_dkg_head(previous, [(11, h10, h11), (12, B256::repeat_byte(99), h12)],),
            Err(DkgCommitContinuityError::Parent {
                height: 12,
                expected: h11,
                actual: B256::repeat_byte(99),
            })
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn initializes_and_reloads_validator_bound_dkg_keystore() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let validator_key = directory.path().join("validator.key");
        let password_file = directory.path().join("password");
        let keystore = directory.path().join("dkg.json");
        let prover = trusted_test_prover(directory.path());
        std::fs::write(&validator_key, [1_u8; 32]).unwrap();
        std::fs::write(&password_file, b"test validator password\n").unwrap();
        std::fs::set_permissions(&validator_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let initialized = NeoXNodeArgs {
            experimental_validator: true,
            ecdsa_key: Some(validator_key.clone()),
            dkg_keystore: Some(keystore.clone()),
            dkg_password_file: Some(password_file.clone()),
            dkg_init: true,
            dkg_prover: Some(prover.clone()),
            dkg_zk_version: 0,
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .unwrap()
        .unwrap();
        assert!(keystore.is_file());
        assert_eq!(std::fs::metadata(&keystore).unwrap().permissions().mode() & 0o777, 0o600);
        let missing_manifest = NeoXNodeArgs {
            experimental_validator: true,
            ecdsa_key: Some(validator_key.clone()),
            dkg_keystore: Some(keystore.clone()),
            dkg_password_file: Some(password_file.clone()),
            dkg_prover: Some(prover.clone()),
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .unwrap_err();
        assert!(missing_manifest.to_string().contains("dkg-prover-manifest"));

        let restored = NeoXNodeArgs {
            experimental_validator: true,
            ecdsa_key: Some(validator_key),
            dkg_keystore: Some(keystore.clone()),
            dkg_password_file: Some(password_file),
            dkg_prover: Some(prover.clone()),
            dkg_zk_version: 0,
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .unwrap()
        .unwrap();
        assert_eq!(restored.account(), initialized.account());
        assert!(NeoXNodeArgs {
            experimental_validator: true,
            ecdsa_key: Some(directory.path().join("validator.key")),
            dkg_keystore: Some(keystore),
            dkg_password_file: Some(directory.path().join("password")),
            dkg_init: true,
            dkg_prover: Some(prover),
            dkg_zk_version: 0,
            ..NeoXNodeArgs::default()
        }
        .load_signer()
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn imports_registered_message_identity_into_new_dkg_keystore() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let validator_key = directory.path().join("validator.key");
        let message_key = directory.path().join("message.key");
        let password_file = directory.path().join("password");
        let keystore = directory.path().join("dkg.json");
        let prover = trusted_test_prover(directory.path());
        std::fs::write(&validator_key, [1_u8; 32]).unwrap();
        let mut encoded_message_key = [0_u8; 32];
        encoded_message_key[31] = 9;
        std::fs::write(&message_key, encoded_message_key).unwrap();
        std::fs::write(&password_file, b"test validator password\n").unwrap();
        for path in [&validator_key, &message_key, &password_file] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = NeoXNodeArgs {
            experimental_validator: true,
            ecdsa_key: Some(validator_key),
            dkg_keystore: Some(keystore),
            dkg_password_file: Some(password_file),
            dkg_init: true,
            dkg_message_key: Some(message_key),
            dkg_prover: Some(prover),
            dkg_zk_version: 0,
            ..NeoXNodeArgs::default()
        }
        .load_validator(47_763)
        .unwrap()
        .unwrap();
        let runtime = loaded.dkg_runtime.unwrap();
        let expected = DkgMessagePrivateKey::new(encoded_message_key).unwrap().public_key();
        assert_eq!(runtime.store.message_public_key(), expected);
        assert_eq!(runtime.store.validator_address(), Some(loaded.signer.account()));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatorEngineOverride {
    configured_persistence_threshold: u64,
    configured_memory_block_buffer_target: u64,
    configured_persistence_backpressure_threshold: u64,
    configured_suppress_persistence_during_build: bool,
}

fn enforce_validator_engine_persistence(
    cli: &mut Cli<NeoXChainSpecParser, NeoXNodeArgs>,
) -> Option<ValidatorEngineOverride> {
    let command = cli.as_node_command_mut()?;
    command.ext.ecdsa_key.as_ref()?;

    let requested = ValidatorEngineOverride {
        configured_persistence_threshold: command.engine.persistence_threshold,
        configured_memory_block_buffer_target: command.engine.memory_block_buffer_target(),
        configured_persistence_backpressure_threshold: command
            .engine
            .persistence_backpressure_threshold(),
        configured_suppress_persistence_during_build: command
            .engine
            .suppress_persistence_during_build,
    };
    command.engine.persistence_threshold = 0;
    command.engine.memory_block_buffer_target = Some(0);
    command.engine.persistence_backpressure_threshold = Some(1);
    command.engine.suppress_persistence_during_build = false;
    Some(requested)
}

async fn wait_for_validator_startup(
    startup_ready: oneshot::Receiver<Result<(), String>>,
    beacon_sync: &mut tokio::task::JoinHandle<()>,
    component: &'static str,
) -> eyre::Result<()> {
    tokio::select! {
        readiness = startup_ready => match readiness {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                eyre::bail!("{component} failed initial canonical reconciliation: {error}");
            }
            Err(_) => {
                eyre::bail!("{component} stopped before initial canonical reconciliation");
            }
        },
        result = beacon_sync => match result {
            Ok(()) => {
                eyre::bail!("Neo X beacon sync stopped before {component} became ready");
            }
            Err(error) => {
                eyre::bail!("Neo X beacon sync task failed before {component} became ready: {error}");
            }
        },
    }
}

fn main() {
    reth_cli_util::sigsegv_handler::install();
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        // SAFETY: this runs before the CLI initializes worker threads.
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }

    let mut cli = Cli::<NeoXChainSpecParser, NeoXNodeArgs>::parse();
    let validator_engine_override = enforce_validator_engine_persistence(&mut cli);

    if let Err(error) = cli.run_with_components::<NeoXNode>(
        cli_components,
        async move |builder, validator_args| {
            if let Some(requested) = validator_engine_override {
                warn!(
                    target: "neox_rs::cli",
                    configured_persistence_threshold = requested.configured_persistence_threshold,
                    configured_memory_block_buffer_target =
                        requested.configured_memory_block_buffer_target,
                    configured_persistence_backpressure_threshold =
                        requested.configured_persistence_backpressure_threshold,
                    configured_suppress_persistence_during_build =
                        requested.configured_suppress_persistence_during_build,
                    persistence_threshold = 0,
                    memory_block_buffer_target = 0,
                    persistence_backpressure_threshold = 1,
                    "Validator mode queues every canonical block for persistence immediately"
                );
            }
            info!(target: "neox_rs::cli", "Launching Neo X full node");
            let chain_spec = Arc::clone(&builder.config().chain);
            let loaded_validator = validator_args.load_validator(chain_spec.inner.chain.id())?;
            let (signer, dkg_runtime) = match loaded_validator {
                Some(loaded) => (Some(loaded.signer), loaded.dkg_runtime),
                None => (None, None),
            };
            let enable_amev_cache = validator_args.amev_cache;
            let dkg_key_directory = validator_args.dkg_key_dir.clone();
            if let Some(signer) = signer.as_ref() {
                info!(target: "neox_rs::cli", account = %signer.account(), "Loaded Neo X validator identity");
            }
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
                                        info!(target: "neox_rs::rpc", %hash, "Cached Anti-MEV secret transaction");
                                        Err(rpc_error("transaction cached"))
                                    }
                                    CacheSubmission::Forward(raw) => {
                                        EthTransactions::send_raw_transaction(eth_api, raw)
                                            .await
                                            .map_err(rpc_error)
                                    }
                                }
                            },
                        )?;
                        info!(target: "neox_rs::rpc", "Enabled Neo X Anti-MEV transaction cache");
                    }
                    ctx.modules.add_or_replace_if_module_configured(
                        RethRpcModule::Eth,
                        module,
                    )?;
                    info!(target: "neox_rs::rpc", "Installed Neo X Policy RPC methods");
                    Ok(())
                })
                .launch()
                .await?;
            let canonical = handle.node.provider.clone().canonical_state_stream();
            let dkg_canonical = handle.node.provider.clone().subscribe_to_canonical_state();
            let engine = handle.node.consensus_engine_handle().clone();
            let pool = handle.node.pool.clone();
            let provider = handle.node.provider.clone();
            let mut beacon_sync = handle.node.task_executor.spawn_critical_task(
                "neox beacon sync",
                run_beacon_sync(BeaconSyncContext {
                    events,
                    dbft_events,
                    canonical,
                    beacon,
                    dbft,
                    engine,
                    pool: pool.clone(),
                    provider: provider.clone(),
                    chain_spec: Arc::clone(&chain_spec),
                    signer: signer.clone(),
                    sidecar_store,
                }),
            );
            if let (Some(dkg_signer), Some(directory)) =
                (signer.clone(), dkg_key_directory)
            {
                let (startup_ready_tx, startup_ready_rx) = oneshot::channel();
                handle.node.task_executor.spawn_critical_task(
                    "neox dkg key reload",
                    run_dkg_key_reload(
                        provider.clone(),
                        dkg_signer,
                        directory,
                        dkg_canonical,
                        startup_ready_tx,
                    ),
                );
                wait_for_validator_startup(
                    startup_ready_rx,
                    &mut beacon_sync,
                    "Neo X DKG key reload",
                )
                .await?;
            }
            if let Some(dkg_runtime) = dkg_runtime {
                let (startup_ready_tx, startup_ready_rx) = oneshot::channel();
                handle.node.task_executor.spawn_critical_task(
                    "neox dkg runtime",
                    run_dkg_runtime(
                        provider.clone(),
                        pool.clone(),
                        NeoXEvmConfig::new(Arc::clone(&chain_spec)),
                        dkg_runtime,
                        provider.clone().canonical_state_stream(),
                        startup_ready_tx,
                    ),
                );
                wait_for_validator_startup(
                    startup_ready_rx,
                    &mut beacon_sync,
                    "Neo X DKG runtime",
                )
                .await?;
            }
            handle.wait_for_node_exit().await
        },
    ) {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}
