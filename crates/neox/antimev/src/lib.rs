//! Neo X Anti-MEV Envelope parsing and threshold-cryptography primitives.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::undocumented_unsafe_blocks)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
mod dkg;
#[cfg(feature = "std")]
mod dkg_keystore;
#[cfg(feature = "std")]
mod dkg_state;
mod envelope;
mod field;
#[cfg(feature = "std")]
mod geth_keystore;
mod precommit;
mod tpke;

#[cfg(feature = "std")]
pub use dkg::*;
#[cfg(feature = "std")]
pub use dkg_keystore::*;
#[cfg(feature = "std")]
pub use dkg_state::*;
pub use envelope::*;
#[cfg(feature = "std")]
pub use geth_keystore::*;
pub use precommit::*;
pub use tpke::*;
