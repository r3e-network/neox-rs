//! Neo X full-node executable based on Reth.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use clap::Parser;
use reth_chain_state::CanonStateSubscriptions;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_ethereum_cli::interface::Cli;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_node::{
    cli_components, run_beacon_sync, BeaconSyncContext, DbftSigner, NeoXNode, NeoXSidecarStore,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::info;

/// Neo X validator-only node arguments.
#[derive(Debug, Clone, Default, clap::Parser)]
struct NeoXNodeArgs {
    /// Path to a mode-0600 raw 32-byte or hex secp256k1 validator private key.
    #[arg(long = "validator.ecdsa-key", value_name = "FILE")]
    ecdsa_key: Option<PathBuf>,

    /// Path to a mode-0600 raw 32-byte or hex private share for the active DKG round.
    #[arg(long = "validator.dkg-key", value_name = "FILE", requires = "ecdsa_key")]
    dkg_key: Option<PathBuf>,
}

impl NeoXNodeArgs {
    fn load_signer(&self) -> eyre::Result<Option<DbftSigner>> {
        let Some(path) = self.ecdsa_key.as_ref() else { return Ok(None) };
        let mut secret = read_private_key(path)?;
        let signer = DbftSigner::from_secret(&secret);
        secret.fill(0);
        let signer = signer?;
        let signer = if let Some(path) = self.dkg_key.as_ref() {
            let mut private_share = read_private_key(path)?;
            let result = signer.with_dkg_private_share(private_share);
            private_share.fill(0);
            result?
        } else {
            signer
        };
        Ok(Some(signer))
    }
}

fn read_private_key(path: &Path) -> eyre::Result<[u8; 32]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|error| {
            eyre::eyre!("failed to inspect key file {}: {error}", path.display())
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            eyre::bail!(
                "refusing key file {} with permissions {:o}; use chmod 600",
                path.display(),
                mode & 0o777
            )
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn dkg_key_requires_validator_identity() {
        assert!(
            NeoXNodeArgs::try_parse_from(["neox-reth", "--validator.dkg-key", "dkg.key"]).is_err()
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
            let handle = builder.node(neox_node).launch().await?;
            let canonical = handle.node.provider.clone().canonical_state_stream();
            let engine = handle.node.consensus_engine_handle().clone();
            let pool = handle.node.pool.clone();
            let provider = handle.node.provider.clone();
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
