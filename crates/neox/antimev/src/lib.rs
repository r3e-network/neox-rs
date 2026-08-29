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

// Explicit re-exports instead of globs so the public API surface stays reviewable: every name
// this crate exposes at its root is listed here, and adding or removing one is a visible diff.
#[cfg(feature = "std")]
pub use dkg::{
    decrypt_dkg_share_message, verify_aggregated_dkg_commitment,
    verify_aggregated_dkg_commitment_with_parameters, verify_aggregated_dkg_share,
    verify_aggregated_dkg_share_with_parameters, DkgMaterialError, DkgParameters, DkgPolynomial,
    DkgPvss, DkgPvssMaterial, DkgSecretScalar, NEOX_DKG_COMMITMENT_LEN, NEOX_DKG_ECIES_MESSAGE_LEN,
    NEOX_DKG_G1_LEN, NEOX_DKG_G2_LEN, NEOX_DKG_GENERATED_PVSS_LEN, NEOX_DKG_PARTICIPANTS,
    NEOX_DKG_THRESHOLD,
};
#[cfg(feature = "std")]
pub use dkg_keystore::DkgKeystoreError;
#[cfg(feature = "std")]
pub use dkg_state::{DkgEpochChange, DkgKeyStore, DkgMessagePrivateKey, DkgStateError};
pub use envelope::{
    encrypted_gas, encrypted_hash, is_envelope, is_envelope_data, is_envelope_policy, EnvelopeData,
    EnvelopeDecodeError, ENCRYPTED_DATA_GAS_LEN, ENCRYPTED_DATA_HASH_LEN, ENCRYPTED_DATA_PREFIX,
    ENCRYPTED_DATA_ROUND_LEN, ENVELOPE_TARGET, MIN_ENCRYPTED_GAS_LIMIT, MIN_ENCRYPTED_MESSAGE_LEN,
    MIN_ENVELOPE_DATA_LEN, TPKE_CIPHERTEXT_LEN,
};
#[cfg(feature = "std")]
pub use geth_keystore::GethDkgMigrationError;
pub use precommit::{
    decode_decryption_shares, encode_decryption_shares, DecryptionShareCodecError,
    MAX_DECRYPTION_SHARES_PER_BLOCK,
};
pub use tpke::{
    aggregate_and_decrypt, aggregate_and_decrypt_keys, aggregate_and_decrypt_keys_with_parameters,
    aggregate_and_verify_signature_shares, aggregate_and_verify_signature_shares_with_parameters,
    aggregate_signature_shares, global_public_key_from_commitment, public_key_from_private_key,
    sign_share, DecryptedKey, DecryptionShare, SignatureShare, ThresholdSignature, TpkeCiphertext,
    TpkeError, DECRYPTION_SHARE_LEN, G1_COMPRESSED_LEN, G1_EIP2537_LEN, G1_UNCOMPRESSED_LEN,
    G2_COMPRESSED_LEN, MAX_TPKE_DECRYPTION_CONTRIBUTIONS, MAX_TPKE_SIGNATURE_SHARES,
    NEOX_DKG_SCALER, SIGNATURE_SHARE_LEN, TPKE_PRIVATE_KEY_LEN, TPKE_SERIALIZED_LEN,
    TPKE_SIGNATURE_DST,
};
