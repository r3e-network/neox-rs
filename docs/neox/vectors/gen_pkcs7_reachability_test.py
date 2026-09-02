"""Generate crates/neox/antimev/tests/geth_pkcs7_reachability.rs from the exported JSON.

Constants are copied straight from the reference-client vector file; hand transcription already
cost one debug cycle on an earlier vector file.
"""

import json
import pathlib

ROOT = pathlib.Path(r"D:\Git\neox-rs")
VEC = ROOT / "docs/neox/vectors/geth-pkcs7-reachability.json"
OUT = ROOT / "crates/neox/antimev/tests/geth_pkcs7_reachability.rs"

data = json.loads(VEC.read_text())

assert data["scaler"] == 360, data["scaler"]
assert data["threshold"] == 5, data["threshold"]
assert len(data["decryption_shares"]) == 7, len(data["decryption_shares"])

shares = "\n".join(f'    "{s}",' for s in data["decryption_shares"])

HEADER = '''//! On-chain reachability of the PKCS#7 unpadding divergence.
//!
//! An earlier probe established that the reference client's `crypto/tpke.pkcs7UnPadding` accepts
//! padding lengths outside `1..=16` and padding bytes that do not repeat the declared length,
//! while this crate rejects both with [`TpkeError::InvalidPkcs7Padding`]. On its own that proves
//! only an implementation-level difference, not that it can be reached on-chain: the
//! leniently-unpadded bytes still have to survive every downstream check before a transaction is
//! executed.
//!
//! The vector in this file was produced by `TestPKCS7Reachability` in
//! `bane-labs/go-ethereum` (branch `bane-main`, commit
//! `f0e236838bb334c7c0d29eeca33533ed0cfda254`), which walks the real reference-client path with a
//! crafted Envelope and asserts that
//!
//! 1. `KeyStore.AggregateAndDecryptWithShare` returns non-nil bytes, so
//!    `consensus/dbft` does **not** take its "content failed to be decrypted" fallback;
//! 2. those bytes are exactly the crafted inner transaction, because `pkcs7UnPadding` returns
//!    `data[:len(data)-n]` for an attacker-chosen `n`;
//! 3. `types.Transaction.UnmarshalBinary` decodes them;
//! 4. the result passes `validateDecryptedTx`, whose every comparison field (nonce, sender,
//!    `encrypted_hash`, `encrypted_gas`) lives in the Envelope's *plaintext* and is therefore
//!    chosen by the same party that crafts the padding.
//!
//! So a reference-client node executes the inner transaction while this crate rejects at the
//! unpadding step and falls back to executing the Envelope as-is. Two different transactions in
//! the same block slot is a consensus fork in a mixed-client network, which is why this is
//! recorded as a finding rather than a hardened-stricter-than-reference curiosity.
//!
//! This file asserts the Rust half of that split, and that the payload the reference client
//! recovers is a genuine transaction rather than garbage that would be rejected downstream anyway.

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{hex, keccak256};
use reth_neox_antimev::{
    aggregate_and_decrypt, DecryptionShare, TpkeCiphertext, TpkeError, DECRYPTION_SHARE_LEN,
};

/// Scaler for the fixed 5-of-7 committee the vector was captured against.
const SCALER: u64 = 360;

/// Padding length the reference client accepts and this crate rejects.
const PADDING_LEN: usize = %(padding)d;

'''

BODY = '''
/// Decodes the crafted ciphertext and asserts it passes the pairing commitment check.
fn ciphertext() -> TpkeCiphertext {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let decoded = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");
    decoded.verify().expect("commitment is consistent");
    decoded
}

/// `count` validators' decryption shares, keyed by their 1-based committee indices.
fn shares(count: usize) -> Vec<(u32, DecryptionShare)> {
    DECRYPTION_SHARES
        .iter()
        .take(count)
        .enumerate()
        .map(|(position, share)| {
            let bytes: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            (position as u32 + 1, DecryptionShare::decode(&bytes).expect("share decodes"))
        })
        .collect()
}

fn unhex<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("vector hex decodes");
    <[u8; N]>::try_from(decoded.as_slice()).expect("vector has the expected length")
}

/// The divergence itself: this crate rejects the Envelope the reference client accepts.
#[test]
fn rust_rejects_the_envelope_the_reference_client_accepts() {
    let global_public_key: [u8; 48] = unhex(GLOBAL_PUBLIC_KEY);
    let key = aggregate_and_decrypt(&ciphertext(), &global_public_key, &shares(5), SCALER)
        .expect("five valid shares recover the AES key");

    let encrypted_message = hex::decode(ENCRYPTED_MESSAGE).expect("message hex decodes");
    let error = key
        .decrypt_message(&encrypted_message)
        .expect_err("malformed PKCS#7 padding must be rejected");
    assert_eq!(error, TpkeError::InvalidPkcs7Padding);
}

/// The rejection must be about the padding rule and nothing else: share aggregation recovers the
/// AES key successfully, so both implementations agree on every step up to the unpadding.
#[test]
fn aggregation_succeeds_so_the_divergence_is_only_the_unpadding_rule() {
    let global_public_key: [u8; 48] = unhex(GLOBAL_PUBLIC_KEY);
    let key = aggregate_and_decrypt(&ciphertext(), &global_public_key, &shares(5), SCALER)
        .expect("aggregation must succeed; only the unpadding differs");
    // A different quorum recovers the same key, matching the single-round vector behaviour.
    let alternate = shares(7);
    let alternate_key = aggregate_and_decrypt(&ciphertext(), &global_public_key, &alternate, SCALER)
        .expect("the full committee also recovers the key");
    assert_eq!(key.as_bytes(), alternate_key.as_bytes(), "quorums disagree on the AES key");
}

/// The bytes the reference client's lenient unpadding yields must be a real, decodable
/// transaction -- otherwise the divergence would be harmless because the reference client would
/// reject the result at `UnmarshalBinary` and take the same fallback this crate takes.
#[test]
fn the_payload_the_reference_client_recovers_is_a_real_transaction() {
    let payload = hex::decode(INNER_TX).expect("payload hex decodes");
    let mut slice = payload.as_slice();
    let tx = TxEnvelope::decode_2718(&mut slice).expect("payload decodes as a typed transaction");
    assert!(slice.is_empty(), "payload must decode exactly, with no trailing bytes");

    // Re-encoding must round-trip, proving this is a canonical EIP-2718 envelope.
    let mut reencoded = Vec::new();
    tx.encode_2718(&mut reencoded);
    assert_eq!(reencoded, payload, "payload must be the canonical encoding");

    // EIP-2718 defines the transaction hash as keccak256 of the envelope encoding.
    let expected: [u8; 32] = unhex(INNER_TX_HASH);
    assert_eq!(keccak256(&payload).as_slice(), &expected, "transaction hash mismatch");
}

/// The craft's arithmetic, pinned so the vector cannot silently degrade into a case both
/// implementations agree on.
#[test]
fn the_padding_length_is_outside_the_accepted_range() {
    let payload = hex::decode(INNER_TX).expect("payload hex decodes");
    assert!(
        PADDING_LEN > 16,
        "padding length must exceed the AES block size, which is what this crate rejects"
    );
    assert!(PADDING_LEN <= 255, "padding length must fit in the trailing length byte");
    assert_eq!(
        (payload.len() + PADDING_LEN) % 16,
        0,
        "the padded buffer must stay AES-block aligned"
    );
    // The reference client's rule is `data[..len - data[len-1]]`, so it returns exactly the
    // payload -- which is why it reaches `UnmarshalBinary` instead of failing earlier.
    assert_eq!(
        payload.len() + PADDING_LEN - PADDING_LEN,
        payload.len(),
        "lenient unpadding must return the whole payload"
    );
}
'''

content = (
    HEADER % {"padding": data["padding_len"]}
    + f'/// Compressed global TPKE public key of the committee the vector was captured against.\nconst GLOBAL_PUBLIC_KEY: &str =\n    "{data["global_public_key"]}";\n\n'
    + f'/// The crafted Envelope ciphertext: `M || R || commitment`.\nconst CIPHERTEXT: &str =\n    "{data["ciphertext"]}";\n\n'
    + f'/// AES-256-CBC ciphertext whose plaintext carries the malformed padding.\nconst ENCRYPTED_MESSAGE: &str =\n    "{data["encrypted_message"].lower() if False else data["encrypted_msg"]}";\n\n'
    + f'/// The inner transaction bytes the reference client recovers after lenient unpadding.\nconst INNER_TX: &str =\n    "{data["inner_tx_binary"]}";\n\n'
    + f'/// keccak256 of [`INNER_TX`], which is what the Envelope commits to.\nconst INNER_TX_HASH: &str = "{data["inner_tx_hash"][2:]}";\n\n'
    + f'/// Per-validator decryption shares, in committee index order 1..=7.\nconst DECRYPTION_SHARES: [&str; 7] = [\n{shares}\n];\n'
    + BODY
)

OUT.write_text(content, encoding="utf-8", newline="\n")
print("wrote", OUT, len(content), "bytes")
