//! Neo X Anti-MEV Envelope parsing and threshold-cryptography primitives.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

mod envelope;

pub use envelope::*;
