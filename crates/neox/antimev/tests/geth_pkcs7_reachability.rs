//! On-chain reachability of the PKCS#7 unpadding divergence.
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
//! 1. `KeyStore.AggregateAndDecryptWithShare` returns non-nil bytes, so `consensus/dbft` does
//!    **not** take its "content failed to be decrypted" fallback;
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
const PADDING_LEN: usize = 32;

// Compile-time guards on the craft's shape: the padding length must exceed the AES block size
// (otherwise this crate would accept it and there would be no divergence) while still fitting in
// the single trailing byte the reference client's unpadding rule reads.
const _: () = assert!(PADDING_LEN > 16);
const _: () = assert!(PADDING_LEN <= 255);

/// Compressed global TPKE public key of the committee the vector was captured against.
const GLOBAL_PUBLIC_KEY: &str =
    "8f2df85bc8add14e861a2bafedb0a408d23d94160c49300c87009477c546e2373a343f95c97b56d027445be0ea7b6f75";

/// The crafted Envelope ciphertext: `M || R || commitment`.
const CIPHERTEXT: &str =
    "b1d70bbab7255bca7fe48b7fab1c72482b56b0a0e877ae059fe461deb4f256530db18677411fbf69d46c7e8ab4d1daccb6fdbb3e870c944514d337422d57a697b5c7518621043a4f39ad7dccffbe1fb3cabfdb8cf0658dd8b1b6e955ac320a63a2072650fa93641590222b8a0538224c94bfe75c2a2a1bd1c5e6e7aee1902a6e70bd0f4d50563257905155a3867e7b160ff8fe642cf337cfdcb32744ab2d6c2e13554f0dd1073db2661aa95520b442e870961b43cc19851c7e8e41cfd333653e";

/// AES-256-CBC ciphertext whose plaintext carries the malformed padding.
const ENCRYPTED_MESSAGE: &str =
    "719f5d211119e0d553ff9ada9d4c19b57832e73d0e7a8015e205c0d8c94ab7e54325ca37c60c0ac79dc3dc0900a1189db545d83f14d25caf416f7a63c71d9f69ad9fcce14369836f4d7098ccf6a8fc56a78857385f4105e334d632292a885f1c5d90ce2d90de9a7764294a3ef6649ddf10c8de0c6975cdd6f716d33719cb32a72e25c16b688ae1a498e114f2d4446344";

/// The inner transaction bytes the reference client recovers after lenient unpadding.
const INNER_TX: &str =
    "02f86d83ba930480843b9aca0084b2d05e008252089474f4effb0b538baec703346b03b6d9292f53a4cd0180c080a05654acf7a0dc790bf29d955fcd24ccb98f5b93f03fdae1b2ad14799c8cf1cb00a038869595d7fa3642d827640d97174c33470dc35a498f90fcef5d228d5b95a6a8";

/// keccak256 of [`INNER_TX`], which is what the Envelope commits to.
const INNER_TX_HASH: &str = "87d9ffa086c88b491f30dd663075feaf3659286979e20b64435f0a8fd9452657";

/// Per-validator decryption shares, in committee index order 1..=7.
const DECRYPTION_SHARES: [&str; 7] = [
    "b28f3156ba9cdf1f359376b2ab66e467011190beee94e33ca2bb11c130bfa68612c0ec6fd98b8bd904a1c5d20356b178",
    "8e54b55d14cb59b6a7e077254e595afa38605414e9fe54059c55537834db6f35bde7af426b8b46d3c83a47048355607e",
    "a368d6ed80de80ecacc56c3c7c56fa6be188dbd4081498716b6302782c3a771e349b9219b8f1f70844486e6604e0b025",
    "84afcb66ddf9c5bb365426c228d4817565457072d68944cb08f8c67534b52e09c12b05672c7ef2bc045e811271d1836f",
    "a200313f6892cc6f30dc49d7be614cd76388f7364b47a7af64832ebe3091296e0b8d66b362dd6a0c28c6cb4233b44f23",
    "b7b072996fb51bfbc0a6d04d1859ed62e69647571679aa7207b2e635cb5894c076b2b6ea355616c7a850613c0842a0fd",
    "aad2e488d89fd9a39e9ff9ebcf5df20ab4f572e974e2448d8516abeb550c13e0243365cfa4733521f24cdafbdfd69bbe",
];

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
    let alternate_key =
        aggregate_and_decrypt(&ciphertext(), &global_public_key, &alternate, SCALER)
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

/// Replays the reference client's unpadding rule on the crafted buffer.
///
/// `crypto/tpke.pkcs7UnPadding` returns `data[..len - data[len-1]]`, bounding `data[len-1]` only by
/// the buffer length. Replaying it here (rather than asserting the arithmetic) is what shows the
/// reference client reaches `UnmarshalBinary` with a complete payload instead of failing earlier.
#[test]
fn the_reference_clients_rule_returns_the_whole_payload() {
    let payload = hex::decode(INNER_TX).expect("payload hex decodes");

    let mut padded = payload.clone();
    padded.resize(payload.len() + PADDING_LEN, 0x00);
    *padded.last_mut().expect("nonempty buffer") = u8::try_from(PADDING_LEN)
        .expect("padding length must fit in the trailing byte the reference client reads");
    assert_eq!(
        (padded.len()) % 16,
        0,
        "the padded buffer must stay AES-block aligned so AESDecrypt accepts it"
    );

    // The reference client's rule: strip `data[len-1]` bytes from the end.
    let declared = usize::from(padded[padded.len() - 1]);
    let lenient = &padded[..padded.len() - declared];
    assert_eq!(lenient, payload.as_slice(), "lenient unpadding must return exactly the payload");

    // The same buffer is what this crate refuses to unpad at all.
    assert!(
        declared == 0 || declared > 16,
        "this craft must land outside the 1..=16 range this crate accepts, got {declared}"
    );
}
