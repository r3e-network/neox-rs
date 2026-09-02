//! Envelope ciphertext admission: this crate verifies a relation the reference client never checks.
//!
//! Neo X Geth defines `CipherText.Verify` in `crypto/tpke/encryption.go`, but no non-test call site
//! in the tree invokes it. Envelope admission instead rests on
//!
//! * `antimev.IsEnvelope` - receiver address, `0xffffffff` prefix, minimum length;
//! * `decodeEnvelopeData` - `CipherText.FromBytes`, which deserializes the three curve points and
//!   checks that they are on-curve and in-subgroup, but not that they agree on one scalar;
//! * `core/txpool/validation.go` - gas limit, encrypted gas and fee only.
//!
//! So a ciphertext whose `R` and G2 commitment encode *different* scalars is admitted as an
//! Envelope. This crate calls [`TpkeCiphertext::verify`] in two places and rejects it in both:
//!
//! * mempool admission, permanently - `NeoXPoolPolicyError::InvalidEnvelopeCiphertext`;
//! * proposal discovery - `AntiMevProposalError::InvalidCiphertext`, which `?`-propagates into
//!   `DbftProposalError::AntiMevProposal` and rejects the whole proposal.
//!
//! The vector here was produced by `antimev.TestCiphertextAdmission` in `bane-labs/go-ethereum`
//! (branch `bane-main`, commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`). That test also shows
//! the reference client can never decrypt the Envelope: `aggregateAndDecrypt` tries all
//! `C(7,5) = 21` quorums and every one fails, so the additional `PreCommits` that
//! `dbft.check.go` waits for can never arrive in a useful form.
//!
//! This is a **liveness** divergence, not a state fork. `AggregateAndDecrypt` verifies
//! `e(PK, commitment) * e(rpk, g2)` while `Verify` checks `e(R, g2) * e(g1, commitment)`; for
//! honest shares the two hold under the same condition, so no input exists that Geth decrypts and
//! this crate rejects. Both clients fail - Geth by waiting, this crate by refusing to admit.
//!
//! Reference-client side of the same vector:
//! `consensus/dbft.TestEnvelopeDecodeAcceptsUnverifiedCiphertext` proves `decodeEnvelopeData`
//! parses both Envelopes, and `antimev.TestCiphertextAdmission` proves `IsEnvelope` accepts both
//! and that aggregation fails for every quorum.

use alloy_primitives::hex;
use reth_neox_antimev::{EnvelopeData, TpkeCiphertext, TpkeError};

/// Envelope calldata carrying a well-formed ciphertext, for contrast.
const ENVELOPE_DATA_VALID: &str = "ffffffff000000010000520887d9ffa086c88b491f30dd663075feaf3659286979e20b64435f0a8fd945265793fba03e0bfc956e31ee8ea0bde3fa216b17d63decfe64438a9932f321e0bc9acc07e4a6415403c102e08271bd03b573b109cbdc42792e8933057a87ad554194f1bba4c2a90b51fc5cf0a1b13cae94e60ccb6bddfe09557b0e0a880d0f3c650fb8f8bde02928c51639a721235b63c6fa818d48a5e043fe4f756fa4bd654a3ddc20509000c1bf177474f23f48995119ba0bcbe7e695c5ac90a0599c8c851b400a5592aaa2e70f3f33fc1325dca280bc8dc3fe1a12fee8a0dcc5cd69bcfa4f8179203f32cc4feccac92640eecf8ce66943ff0caf43d10cd649c6a10be484d71ab139f1c5cd61b5af0ce2908cbe16dd009111ee590a2797c2c6e72253377a64d38aa2a204fa30dea5b46db49fea7dca93e52f6e9d137c81a8127333ff480c288d68f1d6018f5fdf029911235ad846a629b24101347a92db1ee33d3c0aca935dee9e";

/// Envelope calldata whose ciphertext has a broken pairing relation.
const ENVELOPE_DATA_INVALID: &str = "ffffffff000000010000520887d9ffa086c88b491f30dd663075feaf3659286979e20b64435f0a8fd945265793fba03e0bfc956e31ee8ea0bde3fa216b17d63decfe64438a9932f321e0bc9acc07e4a6415403c102e08271bd03b573b84a261128e5ff6d4a55b73544c2b418e701142c81f9a00c7dbe18bc3fd1bdb8796e127f3815c5c31978a959c6bc98c7b8f8bde02928c51639a721235b63c6fa818d48a5e043fe4f756fa4bd654a3ddc20509000c1bf177474f23f48995119ba0bcbe7e695c5ac90a0599c8c851b400a5592aaa2e70f3f33fc1325dca280bc8dc3fe1a12fee8a0dcc5cd69bcfa4f8179203f32cc4feccac92640eecf8ce66943ff0caf43d10cd649c6a10be484d71ab139f1c5cd61b5af0ce2908cbe16dd009111ee590a2797c2c6e72253377a64d38aa2a204fa30dea5b46db49fea7dca93e52f6e9d137c81a8127333ff480c288d68f1d6018f5fdf029911235ad846a629b24101347a92db1ee33d3c0aca935dee9e";

/// The untampered ciphertext, `M || R || commitment`.
const CIPHERTEXT_VALID: &str = "93fba03e0bfc956e31ee8ea0bde3fa216b17d63decfe64438a9932f321e0bc9acc07e4a6415403c102e08271bd03b573b109cbdc42792e8933057a87ad554194f1bba4c2a90b51fc5cf0a1b13cae94e60ccb6bddfe09557b0e0a880d0f3c650fb8f8bde02928c51639a721235b63c6fa818d48a5e043fe4f756fa4bd654a3ddc20509000c1bf177474f23f48995119ba0bcbe7e695c5ac90a0599c8c851b400a5592aaa2e70f3f33fc1325dca280bc8dc3fe1a12fee8a0dcc5cd69bcfa4f8179";

/// The tampered ciphertext: `R` was replaced by `R + G1`, so `e(R, g2) * e(g1, commitment) != 1`.
const CIPHERTEXT_INVALID: &str = "93fba03e0bfc956e31ee8ea0bde3fa216b17d63decfe64438a9932f321e0bc9acc07e4a6415403c102e08271bd03b573b84a261128e5ff6d4a55b73544c2b418e701142c81f9a00c7dbe18bc3fd1bdb8796e127f3815c5c31978a959c6bc98c7b8f8bde02928c51639a721235b63c6fa818d48a5e043fe4f756fa4bd654a3ddc20509000c1bf177474f23f48995119ba0bcbe7e695c5ac90a0599c8c851b400a5592aaa2e70f3f33fc1325dca280bc8dc3fe1a12fee8a0dcc5cd69bcfa4f8179";

/// DKG round both Envelopes declare.
const DKG_ROUND: u32 = 1;

/// Decodes a vector field.
fn unhex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector field is valid hex")
}

/// Deserialization agrees with the reference client: this crate's [`TpkeCiphertext::decode`] and
/// Geth's `CipherText.FromBytes` both accept all three curve points, because both only check that
/// the points are on-curve and in-subgroup.
///
/// The divergence therefore cannot be a parsing difference. It is a *checking* difference.
#[test]
fn deserialization_agrees_with_the_reference_client() {
    assert!(
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_VALID)).is_ok(),
        "the untampered ciphertext must deserialize"
    );
    assert!(
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_INVALID)).is_ok(),
        "the tampered ciphertext must deserialize too, exactly as Geth's FromBytes accepts it"
    );
}

/// The divergence proper: Geth admits this ciphertext as an Envelope and this crate rejects it.
///
/// Geth never calls `CipherText.Verify`, so a ciphertext whose `R` does not match its G2 commitment
/// is classified as an Envelope by `IsEnvelope` and parsed by `decodeEnvelopeData`. This crate
/// calls [`TpkeCiphertext::verify`] at mempool admission and at proposal discovery, both of which
/// reject it.
#[test]
fn reth_rejects_the_ciphertext_the_reference_client_admits() {
    let valid = TpkeCiphertext::decode(&unhex(CIPHERTEXT_VALID)).expect("valid ciphertext decodes");
    assert_eq!(valid.verify(), Ok(()), "the untampered ciphertext must verify");

    let invalid =
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_INVALID)).expect("tampered ciphertext decodes");
    assert_eq!(
        invalid.verify(),
        Err(TpkeError::InvalidCiphertextCommitment),
        "the tampered ciphertext must fail the pairing check Geth never runs"
    );
}

/// Full Envelope parsing agrees as well: only the pairing check differs.
///
/// Everything outside the ciphertext is byte-identical between the two Envelopes, so the pairing
/// relation is the sole thing separating them. This pins the divergence to one check instead of
/// leaving it ambiguous between "different parse rules" and "different checks".
#[test]
fn envelope_parsing_agrees_and_only_the_pairing_check_diverges() {
    // `EnvelopeData` borrows its input, so the decoded buffers need named bindings.
    let valid_bytes = unhex(ENVELOPE_DATA_VALID);
    let invalid_bytes = unhex(ENVELOPE_DATA_INVALID);
    let valid = EnvelopeData::decode(&valid_bytes).expect("valid Envelope parses");
    let invalid = EnvelopeData::decode(&invalid_bytes).expect("tampered Envelope parses");

    assert_eq!(valid.dkg_round, invalid.dkg_round);
    assert_eq!(valid.dkg_round, DKG_ROUND);
    assert_eq!(valid.encrypted_gas, invalid.encrypted_gas, "gas must be identical");
    assert_eq!(valid.encrypted_hash, invalid.encrypted_hash, "hash must be identical");
    assert_eq!(valid.encrypted_message, invalid.encrypted_message, "payload must be identical");
    assert_ne!(valid.encrypted_key, invalid.encrypted_key, "only the ciphertext may differ");

    assert_eq!(valid.encrypted_key.verify(), Ok(()));
    assert_eq!(
        invalid.encrypted_key.verify(),
        Err(TpkeError::InvalidCiphertextCommitment),
        "Geth parses this Envelope and this crate rejects it: the admission divergence"
    );
}
