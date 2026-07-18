//! Neo X chain specification primitives.
//!
//! This crate is the first compatibility boundary between upstream Reth and the Neo X protocol.
//! It intentionally contains no node services: parsing the canonical genesis configuration and
//! representing Neo X hardforks must be stable before execution or consensus is layered on top.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod config;
mod hardfork;
mod spec;

pub use config::{DbftConfig, NeoXGenesisConfig};
pub use hardfork::NeoXHardfork;
pub use spec::{NeoXChainSpec, NeoXChainSpecError};

/// Canonical Neo X `MainNet` genesis JSON vendored from the compatibility baseline.
pub const NEOX_MAINNET_GENESIS_JSON: &str = include_str!("../res/genesis_mainnet.json");

/// Canonical Neo X T4 `TestNet` genesis JSON vendored from the compatibility baseline.
pub const NEOX_TESTNET_GENESIS_JSON: &str = include_str!("../res/genesis_testnet.json");

/// Neo X `MainNet` chain ID.
pub const NEOX_MAINNET_CHAIN_ID: u64 = 47_763;

/// Neo X T4 `TestNet` chain ID.
pub const NEOX_TESTNET_CHAIN_ID: u64 = 12_227_332;

/// Number of active dBFT validators on Neo X.
pub const NEOX_VALIDATOR_COUNT: usize = 7;

/// Block production period configured by the canonical Neo X genesis files.
pub const NEOX_BLOCK_PERIOD_SECS: u64 = 5;

/// Governance reward system contract used as the dBFT coinbase.
pub const GOVERNANCE_REWARD_ADDRESS: alloy_primitives::Address =
    alloy_primitives::address!("1212000000000000000000000000000000000003");

/// Canonical Neo X `MainNet` genesis block hash.
pub const NEOX_MAINNET_GENESIS_HASH: alloy_primitives::B256 =
    alloy_primitives::b256!("2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7");

/// Canonical Neo X T4 `TestNet` genesis block hash.
pub const NEOX_TESTNET_GENESIS_HASH: alloy_primitives::B256 =
    alloy_primitives::b256!("221f7d0a47dd80fe10f476625d62303947c9cd336113e119c64d919f0e9beb71");
