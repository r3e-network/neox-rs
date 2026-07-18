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

/// Official Neo X `MainNet` discovery bootnodes published in the node operator guide.
pub const NEOX_MAINNET_BOOTNODES: [&str; 2] = [
    "enode://92eec46dd8b67ea8d8999defe0bf2b43d4c4802ed42a430843fec97dafbdc9128849261bdf1a940d431fc61f06a1317f5fc7c0386e18a9bbf951d0ccd8bf4f98@34.42.6.58:30303",
    "enode://f289fb5c83ed39cf7d7aff2727afe70bf7951222c4a9aaef7bcbceef9fd0b53e4b6c9c0e08a50774dfd50d93e83b977932e4780934d379a6a0ac10cc44c6cfdb@34.87.188.162:30303",
];

/// Official Neo X T4 `TestNet` discovery bootnodes published in the node operator guide.
pub const NEOX_TESTNET_BOOTNODES: [&str; 2] = [
    "enode://60603db58ef8c90ed152531425910b0352e9304f04935d0f2b5ce149a8c70fb7a743a39020bb12161e56c17b34d9a6295b378436ac43a09b75bbdc954b48ca5d@34.42.6.58:30304",
    "enode://9d58aaeb46d51ab442cff90613e65e979fbd2084b46b25e46565b289baa007ea50e4abfad4e8655873e7f5a1f51b504df217a0d577fffa8278ad2105c0b8cfa9@34.87.188.162:30304",
];

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
