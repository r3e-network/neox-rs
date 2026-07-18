//! Neo X full-node executable based on Reth.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use clap::Parser;
use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_ethereum_cli::interface::Cli;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_node::{cli_components, NeoXNode};
use std::sync::Arc;
use tracing::info;

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

    if let Err(error) = Cli::<NeoXChainSpecParser>::parse().run_with_components::<NeoXNode>(
        cli_components,
        async move |builder, _| {
            info!(target: "neox_reth::cli", "Launching Neo X full node");
            let handle = builder.node(NeoXNode::default()).launch().await?;
            handle.wait_for_node_exit().await
        },
    ) {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}
