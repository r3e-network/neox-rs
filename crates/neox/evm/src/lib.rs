//! Neo X execution-layer extensions for Reth and revm.
//!
//! Neo X follows Ethereum execution rules with a small set of consensus-critical differences:
//! the DKG fork activates MCOPY and the Cancun/Prague cryptographic precompiles early, and native
//! system contracts govern fees, validator rotation, and Anti-MEV state.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod config;
mod executor;
mod factory;
mod system_contracts;

pub use config::NeoXEvmConfig;
pub use executor::{NeoXBlockExecutor, NeoXBlockExecutorFactory, NeoXExecutionError};
pub use factory::{NeoXEvmFactory, NeoXPrecompiles};
pub use system_contracts::*;
