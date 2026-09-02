"""Generate crates/neox/antimev/tests/geth_reshare_vectors.rs from the exported JSON.

Values are copied straight out of the reference-client vector file so no hand transcription can
introduce an error (a previous hand-copied constant was six bytes short and cost a debug cycle).
"""

import json
import pathlib

ROOT = pathlib.Path(r"D:\Git\neox-rs")
VEC = ROOT / "docs/neox/vectors/geth-reshare-vectors.json"
OUT = ROOT / "crates/neox/antimev/tests/geth_reshare_vectors.rs"

data = json.loads(VEC.read_text())

assert data["scaler"] == 360, data["scaler"]
assert data["participants"] == 7, data["participants"]
assert data["threshold"] == 5, data["threshold"]


def round_literal(round_key: str, const_name: str) -> str:
    rnd = data[round_key]
    lines = []
    lines.append(f"const {const_name}: Round = Round {{")
    lines.append(f'    name: "{round_key.replace("_round", "")}",')
    lines.append(f'    commitment: "{rnd["commitment"]}",')
    lines.append(f'    global_public_key: "{rnd["global_public_key"]}",')
    lines.append(f'    ciphertext: "{rnd["ciphertext"]}",')
    lines.append(f'    encrypted_message: "{rnd["encrypted_msg"]}",')
    lines.append(f'    plaintext: "{rnd["plaintext"]}",')
    lines.append("    shares: [")
    for p in rnd["shares"]:
        lines.append("        (")
        lines.append(f'            "{p["private_share"]}",')
        lines.append(f'            "{p["public_share"]}",')
        lines.append(f'            "{p["decryption_share"]}",')
        lines.append("        ),")
    lines.append("    ],")
    lines.append("};")
    return "\n".join(lines)


HEADER = '''//! Cross-implementation vectors for the previous/current round separation (DKG resharing).
//!
//! Neo X rotates the Anti-MEV committee through DKG resharing. After a rotation each keystore
//! holds two groups: `shared`, the new group that seals and opens current-round Envelopes, and
//! `reshared`, the group rebuilt from the previous round's aggregate commitment that can still
//! open Envelopes sealed before the rotation. The audit open item "current/previous mixing and
//! fallback" needs both groups captured from a single run so this crate can prove it keeps them
//! apart.
//!
//! These values come from `TestExportReshareVectors` in
//! `bane-labs/go-ethereum` (branch `bane-main`, commit
//! `f0e236838bb334c7c0d29eeca33533ed0cfda254`), which replays the deterministic 7-node /
//! 5-threshold privnet setup twice: an initial DKG, then an `OnSharePeriodStart(false)` +
//! `DKGReshare()` + `DKGShare()` round that passes the first round's aggregate commitment as
//! `lastRoundCmt` to `OnEpochChange` -- the exact path that builds Geth's `reshared` group. The
//! exporter touches no Geth protocol logic.
//!
//! As with the single-round vectors, the AES message key and nonce are randomised per run, so
//! these are *observed* values. What they prove is that this crate reproduces the reference
//! client's round separation: the previous-round Envelope opens with the previous-round group, the
//! current-round Envelope opens with the current-round group, and every cross-round combination is
//! rejected.

use alloy_primitives::hex;
use reth_neox_antimev::{
    aggregate_and_decrypt, global_public_key_from_commitment, public_key_from_private_key,
    DecryptionShare, TpkeCiphertext, TpkeError, DECRYPTION_SHARE_LEN, NEOX_DKG_PARTICIPANTS,
    NEOX_DKG_SCALER, NEOX_DKG_THRESHOLD, TPKE_PRIVATE_KEY_LEN, TPKE_SERIALIZED_LEN,
};

/// Committee scaler the reference client computed for its fixed 5-of-7 committee.
const SCALER: u64 = 360;

/// One complete DKG round: the on-chain aggregate commitment, the global key it implies, one
/// sealed Envelope, and the per-validator material the reference client recorded for that round.
struct Round {
    /// Short label used in assertion messages.
    name: &'static str,
    /// EIP-2537 padded aggregate commitment (`KeyManagement` wire format).
    commitment: &'static str,
    /// Compressed global TPKE public key derived from that commitment.
    global_public_key: &'static str,
    /// `M || R || commitment` as serialized by Geth.
    ciphertext: &'static str,
    /// AES-256-CBC ciphertext of `plaintext` under the recovered key.
    encrypted_message: &'static str,
    /// The plaintext that must come back out.
    plaintext: &'static str,
    /// `(private share, public share, decryption share)` for validators 1..=7.
    shares: [(&'static str, &'static str, &'static str); NEOX_DKG_PARTICIPANTS],
}

'''


BODY = '''
fn unhex<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("vector hex decodes");
    <[u8; N]>::try_from(decoded.as_slice()).expect("vector has the expected length")
}

/// Decodes the round's ciphertext and asserts it passes the commitment proof on its own.
fn ciphertext(round: &Round) -> TpkeCiphertext {
    let encoded = hex::decode(round.ciphertext).expect("ciphertext hex decodes");
    assert_eq!(encoded.len(), TPKE_SERIALIZED_LEN, "{}: ciphertext length", round.name);
    let decoded = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");
    decoded.verify().expect("ciphertext commitment is consistent");
    decoded
}

/// Builds the `(index, share)` pairs the reference client would send for the given validators.
///
/// `positions` are zero-based offsets into the recorded share list, so indices are `position + 1`,
/// matching the 1-based committee indices both clients use for Lagrange interpolation.
fn shares(round: &Round, positions: &[usize]) -> Vec<(u32, DecryptionShare)> {
    positions
        .iter()
        .map(|position| {
            let bytes: [u8; DECRYPTION_SHARE_LEN] = unhex(round.shares[*position].2);
            let share = DecryptionShare::decode(&bytes).expect("share decodes");
            (*position as u32 + 1, share)
        })
        .collect()
}

/// The whole 5-of-7 quorum in committee order.
fn full_quorum(round: &Round) -> Vec<(u32, DecryptionShare)> {
    shares(round, &(0..NEOX_DKG_PARTICIPANTS).collect::<Vec<_>>())
}

/// Recovers the AES key and decrypts the round's message, asserting both succeed.
fn open(round: &Round, contributions: &[(u32, DecryptionShare)]) -> Vec<u8> {
    let global_public_key: [u8; 48] = unhex(round.global_public_key);
    let key = aggregate_and_decrypt(&ciphertext(round), &global_public_key, contributions, SCALER)
        .expect("envelope opens");
    let encrypted = hex::decode(round.encrypted_message).expect("message hex decodes");
    key.decrypt_message(&encrypted).expect("AES decryption succeeds").to_vec()
}

/// The reference client's committee scaler must match the constant this crate hard-codes.
#[test]
fn scaler_matches_reference_client() {
    assert_eq!(SCALER, NEOX_DKG_SCALER);
}

/// A rotation must change the global key, otherwise the two groups would be interchangeable and
/// every separation assertion below would be vacuous.
#[test]
fn rotated_global_keys_differ() {
    assert_ne!(
        PREVIOUS_ROUND.global_public_key, CURRENT_ROUND.global_public_key,
        "the two rounds must not share a global public key"
    );
}

/// The two rounds must also be sealed under different aggregate commitments.
#[test]
fn rotated_commitments_differ() {
    assert_ne!(PREVIOUS_ROUND.commitment, CURRENT_ROUND.commitment);
}

/// Each round's global key must be exactly what this crate derives from that round's commitment.
#[test]
fn global_keys_match_reference_commitments() {
    for round in [&PREVIOUS_ROUND, &CURRENT_ROUND] {
        let commitment = hex::decode(round.commitment).expect("commitment hex decodes");
        let derived =
            global_public_key_from_commitment(&commitment, SCALER).expect("commitment is valid");
        let expected: [u8; 48] = unhex(round.global_public_key);
        assert_eq!(derived, expected, "{}: global public key mismatch", round.name);
    }
}

/// Both Envelopes must decode and satisfy the pairing commitment check independently of any share.
#[test]
fn both_round_ciphertexts_verify() {
    for round in [&PREVIOUS_ROUND, &CURRENT_ROUND] {
        let _ = ciphertext(round);
    }
}

/// Every validator's private share must reproduce the public share Geth recorded, in both rounds.
#[test]
fn per_round_public_shares_match_reference_client() {
    for round in [&PREVIOUS_ROUND, &CURRENT_ROUND] {
        for (position, (private, public, _)) in round.shares.iter().enumerate() {
            let private: [u8; TPKE_PRIVATE_KEY_LEN] = unhex(private);
            let derived = public_key_from_private_key(&private).expect("private share is canonical");
            let expected: [u8; 48] = unhex(public);
            assert_eq!(
                derived, expected,
                "{}: public share mismatch for validator {}",
                round.name,
                position + 1
            );
        }
    }
}

/// This crate must derive byte-identical decryption shares from both rounds' private shares.
#[test]
fn per_round_decryption_shares_match_byte_for_byte() {
    for round in [&PREVIOUS_ROUND, &CURRENT_ROUND] {
        let decoded = ciphertext(round);
        for (position, (private, _, share)) in round.shares.iter().enumerate() {
            let private: [u8; TPKE_PRIVATE_KEY_LEN] = unhex(private);
            let derived = decoded.decryption_share(&private).expect("private share is usable");
            let expected: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            assert_eq!(
                derived.as_bytes(),
                &expected,
                "{}: decryption share mismatch for validator {}",
                round.name,
                position + 1
            );
        }
    }
}

/// A Envelope sealed before the rotation must still open with the previous-round group.
///
/// This is the fallback path: the `reshared` group exists precisely so that Envelopes stranded by
/// an epoch change can still be decrypted once the committee has moved on.
#[test]
fn previous_round_envelope_opens_with_previous_round_group() {
    let contributions = full_quorum(&PREVIOUS_ROUND);
    let decrypted = open(&PREVIOUS_ROUND, &contributions);
    let expected = hex::decode(PREVIOUS_ROUND.plaintext).expect("plaintext hex decodes");
    assert_eq!(decrypted.as_slice(), expected.as_slice(), "previous-round plaintext mismatch");
}

/// A Envelope sealed after the rotation must open with the current-round group.
#[test]
fn current_round_envelope_opens_with_current_round_group() {
    let contributions = full_quorum(&CURRENT_ROUND);
    let decrypted = open(&CURRENT_ROUND, &contributions);
    let expected = hex::decode(CURRENT_ROUND.plaintext).expect("plaintext hex decodes");
    assert_eq!(decrypted.as_slice(), expected.as_slice(), "current-round plaintext mismatch");
}

/// Any 5-of-7 subset must open the previous-round Envelope, not just the first five.
#[test]
fn alternate_previous_round_quorum_recovers_the_same_plaintext() {
    let quorum = shares(&PREVIOUS_ROUND, &[2, 3, 4, 5, 6]);
    let decrypted = open(&PREVIOUS_ROUND, &quorum);
    let expected = hex::decode(PREVIOUS_ROUND.plaintext).expect("plaintext hex decodes");
    assert_eq!(decrypted.as_slice(), expected.as_slice());
}

/// The previous-round Envelope must not open with the rotated-in shares.
///
/// This is the core anti-mixing property: a validator that joined in the new epoch must not be
/// able to contribute to decrypting an Envelope sealed under the previous epoch's key.
#[test]
fn previous_round_ciphertext_rejects_current_round_shares() {
    let global_public_key: [u8; 48] = unhex(PREVIOUS_ROUND.global_public_key);
    let contributions = full_quorum(&CURRENT_ROUND);
    let error = aggregate_and_decrypt(
        &ciphertext(&PREVIOUS_ROUND),
        &global_public_key,
        &contributions,
        SCALER,
    )
    .expect_err("cross-round shares must not open a previous-round Envelope");
    assert_eq!(error, TpkeError::InvalidDecryptionShares);
}

/// The current-round Envelope must not open with the rotated-out shares.
#[test]
fn current_round_ciphertext_rejects_previous_round_shares() {
    let global_public_key: [u8; 48] = unhex(CURRENT_ROUND.global_public_key);
    let contributions = full_quorum(&PREVIOUS_ROUND);
    let error = aggregate_and_decrypt(
        &ciphertext(&CURRENT_ROUND),
        &global_public_key,
        &contributions,
        SCALER,
    )
    .expect_err("cross-round shares must not open a current-round Envelope");
    assert_eq!(error, TpkeError::InvalidDecryptionShares);
}

/// Even with the correct shares, the wrong round's global key must be rejected: the pairing check
/// binds the Envelope to the key it was sealed under, not merely to a quorum of validators.
#[test]
fn previous_round_ciphertext_rejects_current_round_global_key() {
    let global_public_key: [u8; 48] = unhex(CURRENT_ROUND.global_public_key);
    let contributions = full_quorum(&PREVIOUS_ROUND);
    let error = aggregate_and_decrypt(
        &ciphertext(&PREVIOUS_ROUND),
        &global_public_key,
        &contributions,
        SCALER,
    )
    .expect_err("a mismatched global key must not open the Envelope");
    assert_eq!(error, TpkeError::InvalidDecryptionShares);
}

/// A quorum partially drawn from each round must be rejected, so a mixed committee cannot cobble
/// together a key from shares that never belonged to the same polynomial.
#[test]
fn mixed_round_quorum_is_rejected() {
    let global_public_key: [u8; 48] = unhex(PREVIOUS_ROUND.global_public_key);
    let mut contributions = shares(&PREVIOUS_ROUND, &[0, 1, 2]);
    contributions.extend(shares(&CURRENT_ROUND, &[3, 4]));
    assert_eq!(contributions.len(), NEOX_DKG_THRESHOLD, "mixed quorum is threshold-sized");
    let error = aggregate_and_decrypt(
        &ciphertext(&PREVIOUS_ROUND),
        &global_public_key,
        &contributions,
        SCALER,
    )
    .expect_err("a quorum mixing both rounds must not open the Envelope");
    assert_eq!(error, TpkeError::InvalidDecryptionShares);
}

/// Falling below the threshold must fail on the fallback path exactly as it does on the normal
/// path -- resharing must not relax the decryption quorum.
#[test]
fn below_threshold_previous_round_is_rejected() {
    let global_public_key: [u8; 48] = unhex(PREVIOUS_ROUND.global_public_key);
    let contributions = shares(&PREVIOUS_ROUND, &[0, 1, 2, 3]);
    assert!(contributions.len() < NEOX_DKG_THRESHOLD);
    let error = aggregate_and_decrypt(
        &ciphertext(&PREVIOUS_ROUND),
        &global_public_key,
        &contributions,
        SCALER,
    )
    .expect_err("four shares cannot reconstruct a degree-4 secret");
    assert_eq!(error, TpkeError::InvalidDecryptionShares);
}

/// The two rounds' private shares must be distinct: a rotation that reused the old share material
/// would make the previous/current separation cosmetic rather than cryptographic.
#[test]
fn rotated_private_shares_differ() {
    for position in 0..NEOX_DKG_PARTICIPANTS {
        assert_ne!(
            PREVIOUS_ROUND.shares[position].0, CURRENT_ROUND.shares[position].0,
            "validator {} must receive new share material after a reshare",
            position + 1
        );
    }
}
'''

content = (
    HEADER
    + round_literal("previous_round", "PREVIOUS_ROUND")
    + "\n\n"
    + round_literal("current_round", "CURRENT_ROUND")
    + "\n"
    + BODY
)

OUT.write_text(content, encoding="utf-8", newline="\n")
print("wrote", OUT, len(content), "bytes")
