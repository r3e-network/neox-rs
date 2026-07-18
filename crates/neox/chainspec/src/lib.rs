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
