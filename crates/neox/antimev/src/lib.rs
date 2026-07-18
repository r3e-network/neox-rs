//! Neo X Anti-MEV Envelope parsing and threshold-cryptography primitives.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
mod dkg;
#[cfg(feature = "std")]
mod dkg_state;
mod envelope;
mod precommit;
mod tpke;

#[cfg(feature = "std")]
pub use dkg::*;
#[cfg(feature = "std")]
pub use dkg_state::*;
pub use envelope::*;
pub use precommit::*;
pub use tpke::*;
