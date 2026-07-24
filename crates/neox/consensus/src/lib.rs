//! Neo X dBFT consensus primitives and validation.
//!
//! Consensus state-machine services are added only after byte-level compatibility is locked. This
//! crate begins with the header `extraData` format because genesis construction, header hashing,
//! block validation, light sync, and validator operation all depend on it.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod extra;
mod validation;

pub use extra::{
    bft_honest_node_count, next_consensus_hash, DbftExtra, DbftExtraError, DbftExtraPrefix,
    ExtraVersion, SignatureScheme, ECDSA_SIGNATURE_LEN, HASHABLE_EXTRA_V0_LEN,
    HASHABLE_EXTRA_V1_LEN, THRESHOLD_PUBLIC_KEY_LEN, THRESHOLD_SIGNATURE_LEN,
};
pub use validation::{
    ecdsa_seal_hash, threshold_seal_message, validate_ecdsa_header, validate_header,
    validate_parent_consensus, validate_proposal_primary, validate_threshold_points,
    validate_threshold_public_key, verify_ecdsa_signatures, verify_threshold_signature,
    DbftValidationError, VerifiedSeal, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN, TPKE_BLS_DST,
};
