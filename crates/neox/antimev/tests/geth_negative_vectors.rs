//! Negative and boundary vectors derived from the Neo X Geth reference client.
//!
//! This companion to `geth_cross_vectors.rs` pins down the *rejection* paths: a malformed or
//! hostile Envelope must be refused, not silently tolerated. Every ciphertext here was produced by
//! the reference client's own AES-CBC routine (`crypto/tpke.AESEncrypt`'s key derivation applied to
//! hand-built padded blocks), so these are the exact bytes the reference client would see.
//!
//! The PKCS#7 cases document a **confirmed implementation divergence**, not a bug in this crate:
//! Geth's `pkcs7UnPadding` accepts a padding length outside `1..=16` and never checks that the
//! padding bytes repeat the declared length, while this crate rejects all of those. See
//! `docs/neox/reports/2026-09-01-FULL-AUDIT.md` for the risk assessment.

use alloy_primitives::hex;
use reth_neox_antimev::{
    aggregate_and_decrypt, global_public_key_from_commitment, DecryptedKey, DecryptionShare,
    TpkeCiphertext, TpkeError, DECRYPTION_SHARE_LEN, ENCRYPTED_DATA_PREFIX, NEOX_DKG_SCALER,
    TPKE_PRIVATE_KEY_LEN,
};

const GETH_SCALER: u64 = 360;

const AGGREGATED_COMMITMENT: &str = "0000000000000000000000000000000018dd4618491d74d7f2f28d3abbc75da47c5e7f8dbe6be755f088ee6a33303182f692a11374e097320284ef6741ada855000000000000000000000000000000000d891e0baaebc62690986dfda50d19cea62cdd56bc4855c156f00d3125b67164fc1c5e99aa42348aa2c7470b26bf66bc";

const GLOBAL_PUBLIC_KEY: &str = "8f2df85bc8add14e861a2bafedb0a408d23d94160c49300c87009477c546e2373a343f95c97b56d027445be0ea7b6f75";

const CIPHERTEXT: &str = "87646d6c9ad515aa13110fd840e3061b9bf7aac0c6916acac7d1ce9dd95b188bfd24a9dbac1a3142bd061236eae5a607b673683c8b635aeb6bf2916e383a049608909d227273021a8198ef2fc34fd38d876585ff92bb7d8deaa84d41760da1d7b895ff7eccc2e1081fcc36f49239101efdea44853c6a552cf9a42d04378239a2c40b4e375b64aaa82160f4a77d69e7400514dd3d483f92ccca7b5fc627c5289a829e6fce849259788352ef1aea8c68a714674ce824f1ee453bcfea5dfb2ecf5b";

/// AES-256-CBC payload that only the honestly recovered key can open.
const ENCRYPTED_MESSAGE: &str = "46128109e9d2c1aaed6b416c0fe7c23825910d7a1324ff87885759b2210e9471eaaa39c8250ce13447ce3a39b78edb401db7a3ead31e91586daa554924350d0e5d19c641c1adacc53d26f6d8234ecbbfc25b7f6cf25cf3f9629fb5653cc32097b030f020d37b098f6020365a944085d01c5cc6d85bb5bd50a53483ab1571207c";

/// The plaintext behind [`ENCRYPTED_MESSAGE`].
const PLAINTEXT: &str = "736f6d6520646174612074686174206973206d6f7265207468616e2031303520627974657320696e206c656e6774683a2070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a612070697a7a61";

/// Per-validator DKG material, in committee index order 1..=7.
const PARTICIPANTS: [(&str, &str, &str); 7] = [
    (
        "618286e75dda640cba97df5a97be17b25936c8fa8040abea9baa4c8d10e68bfa",
        "8429ac052ced7fe0412d3a2965b1879820ec0547e8ff627194723b5ff536791d4fa02dfdfd8e8cba1f5b9ba7d0ea33d3",
        "973618eae2f0ec417bde10b8805c2c60a2a4680775d479e9dd38a52c5a61683e02bb5b005a37c22a6f1d57a2f840c95b",
    ),
    (
        "12ab1fcaabc4ebfd3f9f722bb97f251cf79ec842d5cd0f95c47606353de27ee5",
        "a75e0ee6b72c2c93744f1515fd04ebed2f9b45d63d20432f8291420845e4a18c57155f8908fd45953457f661d014f48b",
        "a056f0b730d431fb0d755e8c4a10ebd89bb79d0f2ddef99ad47b51bed59d823b8dd7071f8e73d9968a7e496770a6f9f3",
    ),
    (
        "1e707f4b2ee144cea1470e7f0ea26b89c21002af8784e073f2771c6e858a8de2",
        "a456454442931117506b3cc9e5216ecf656629ffe7d0edf31c62548b9642b58f559e202c2a3493f275d608e645f677cb",
        "af12a908d841532ea6416a98ecf10a0f8da73130ae2cb42b44bc30c9aaf6b0ea6394d96b69724aeca7605b30e85524a2",
    ),
    (
        "2c5ce96f8986bd196854cf0fb7921eeaee875f11579915b55345049466215c4d",
        "b54e4f0b71b9a2ea9a3f53b3fb9271a3d2196ca3f47860c217eaff993938b3dc1ab9e8039f52eae8f5dfdadade32c8fd",
        "b26caa41a740f48c32c4b40cb0e7af6978d0e92e547fe2fb717c4106c9c42ce7a7c79411511d2a0ef62fbe9bdfb0cc97",
    ),
    (
        "2b7b80ce44123d37b2e9df36224c80bc12e5e04649dcd508ddabb8ca10d08b4d",
        "a810811bbcc319257e1a0ceda547eea4b35c815f1854d43d0c0d816c49335d1f96af3c3874b6eff510fc5ce9795a070b",
        "a26b0029708c6ceab92f2e3a6bf8e144a1f689a2bab6da7d78b4bc026d2ac8cb1915d44a1e53a33808bce6c3a3705088",
    ),
    (
        "5258468dcce6474534827ae80a63e00224f0a539a3c5729c51abb7fa69a8b9d4",
        "b4ad04143898d2cd91af519fc37b9d1aed4471ae28724b2a1581ff6e05ebe7aceac8d3f702120c61bdcc3f73a8814f9f",
        "a9cc7d36167f32c1a5fa699aa4a7ba6320a6331e007eb94abe0e71a7240890f381ce2687a05ea74bff3beb4d3d53bd65",
    ),
    (
        "3724cbbe252ffc8ecf823ea865bae940d2d5a0ddec6db91e387a05da07a1849d",
        "b09aba5f471a642a05b610156176aeb2a140c8f06bc5390de5dfdd3b90362b9d15c679fbee09083eea6617c11cbd70e7",
        "a37c845a880a1202a7d2d1871688b5d22d22bb1781154f81841f241e601249b5c20e617cdf122effe7d7e0615b006e0f",
    ),
];

/// Control: a canonically padded block the reference client also accepts.
const PKCS7_VALID: &str = "f5e052c58a2e84ac0f05f53c621995bfa7f1b12b266f89a2a46b254ab5b333f58447bcd53a2a49319342c85d2a74189bca81f33702a3db6db513a56b71c30e500bf3ce9d7a18c57f44d4236931424c9b137e6c005e0be1cdcf352c8882fe1325b8ecf643473a7508de3243c381e61046b20ef8ff5848f4a872a14565e60bf869";

/// Last padding byte is `0x00`, which is outside the legal `1..=16` range.
const PKCS7_ZERO_PADDING: &str = "f5e052c58a2e84ac0f05f53c621995bfa7f1b12b266f89a2a46b254ab5b333f58447bcd53a2a49319342c85d2a74189bca81f33702a3db6db513a56b71c30e500bf3ce9d7a18c57f44d4236931424c9b137e6c005e0be1cdcf352c8882fe1325b8ecf643473a7508de3243c381e610465cd29d88e97c0e11dc9c25b780acaccb";

/// Last padding byte is `0x14` (20), larger than the 16-byte AES block.
const PKCS7_OVERSIZED_PADDING: &str = "f5e052c58a2e84ac0f05f53c621995bfa7f1b12b266f89a2a46b254ab5b333f58447bcd53a2a49319342c85d2a74189bca81f33702a3db6db513a56b71c30e500bf3ce9d7a18c57f44d4236931424c9b137e6c005e0be1cdcf352c8882fe1325b8ecf643473a7508de3243c381e6104698fd7dfe1f885554c63a2a83696d7b16";

/// Declares eight padding bytes but the preceding seven do not repeat `0x08`.
const PKCS7_INCONSISTENT_PADDING: &str = "f5e052c58a2e84ac0f05f53c621995bfa7f1b12b266f89a2a46b254ab5b333f58447bcd53a2a49319342c85d2a74189bca81f33702a3db6db513a56b71c30e500bf3ce9d7a18c57f44d4236931424c9b137e6c005e0be1cdcf352c8882fe1325b8ecf643473a7508de3243c381e6104603c2823a0ccc5d7ad76fcd6361c225e0";

fn unhex<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("vector hex decodes");
    <[u8; N]>::try_from(decoded.as_slice()).expect("vector has the expected length")
}

fn ciphertext() -> TpkeCiphertext {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    TpkeCiphertext::decode(&encoded).expect("ciphertext decodes")
}

fn global_key() -> [u8; 48] {
    let commitment = hex::decode(AGGREGATED_COMMITMENT).expect("commitment hex decodes");
    let derived =
        global_public_key_from_commitment(&commitment, GETH_SCALER).expect("commitment is valid");
    assert_eq!(derived, unhex::<48>(GLOBAL_PUBLIC_KEY), "derived key must match the recorded one");
    derived
}

/// Recovers the AES key from the first `count` validators, in committee index order.
fn recover(count: usize) -> Result<DecryptedKey, TpkeError> {
    let shares = PARTICIPANTS
        .iter()
        .take(count)
        .enumerate()
        .map(|(position, (_, _, share))| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            (position as u32 + 1, DecryptionShare::decode(&share).expect("share decodes"))
        })
        .collect::<Vec<_>>();
    aggregate_and_decrypt(&ciphertext(), &global_key(), &shares, GETH_SCALER)
}

/// The control case must succeed, otherwise every rejection below would be meaningless.
#[test]
fn canonical_padding_is_accepted() {
    let key = recover(5).expect("five valid shares recover the key");
    let ciphertext = hex::decode(PKCS7_VALID).expect("hex decodes");
    let plaintext = key.decrypt_message(&ciphertext).expect("canonical padding decrypts");
    assert_eq!(plaintext.len(), 112);
    assert!(plaintext.iter().all(|byte| *byte == b'a'));
}

/// Padding length zero is outside `1..=16`; the reference client accepts it and returns the whole
/// block, this crate must refuse.
#[test]
fn zero_padding_byte_is_rejected() {
    let key = recover(5).expect("five valid shares recover the key");
    let ciphertext = hex::decode(PKCS7_ZERO_PADDING).expect("hex decodes");
    let error = key.decrypt_message(&ciphertext).expect_err("padding length 0 is invalid");
    assert!(matches!(error, TpkeError::InvalidPkcs7Padding), "unexpected error: {error:?}");
}

/// A declared padding length of 20 exceeds the 16-byte block; the reference client silently strips
/// 20 bytes and returns truncated data, this crate must refuse.
#[test]
fn oversized_padding_byte_is_rejected() {
    let key = recover(5).expect("five valid shares recover the key");
    let ciphertext = hex::decode(PKCS7_OVERSIZED_PADDING).expect("hex decodes");
    let error = key.decrypt_message(&ciphertext).expect_err("padding length 20 is invalid");
    assert!(matches!(error, TpkeError::InvalidPkcs7Padding), "unexpected error: {error:?}");
}

/// Declared padding length is legal but the padding bytes do not repeat it; the reference client
/// accepts this, this crate must refuse.
#[test]
fn inconsistent_padding_bytes_are_rejected() {
    let key = recover(5).expect("five valid shares recover the key");
    let ciphertext = hex::decode(PKCS7_INCONSISTENT_PADDING).expect("hex decodes");
    let error = key.decrypt_message(&ciphertext).expect_err("non-repeating padding is invalid");
    assert!(matches!(error, TpkeError::InvalidPkcs7Padding), "unexpected error: {error:?}");
}

/// A non-multiple of the AES block size must be refused before any padding is inspected.
#[test]
fn ragged_aes_ciphertext_is_rejected() {
    let key = recover(5).expect("five valid shares recover the key");
    let mut ciphertext = hex::decode(PKCS7_VALID).expect("hex decodes");
    ciphertext.pop();
    let error = key.decrypt_message(&ciphertext).expect_err("ragged ciphertext is invalid");
    assert!(
        matches!(error, TpkeError::InvalidAesCiphertextLength { .. }),
        "unexpected error: {error:?}"
    );
}

/// An empty payload must be refused as well.
#[test]
fn empty_aes_ciphertext_is_rejected() {
    let key = recover(5).expect("five valid shares recover the key");
    let error = key.decrypt_message(&[]).expect_err("empty ciphertext is invalid");
    assert!(
        matches!(error, TpkeError::InvalidAesCiphertextLength { .. }),
        "unexpected error: {error:?}"
    );
}

/// Flipping a byte in the pairing commitment must break the ciphertext's own proof.
///
/// The commitment is the last 96 bytes of the serialized ciphertext.
#[test]
fn tampered_pairing_commitment_is_rejected() {
    let mut encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    match TpkeCiphertext::decode(&encoded) {
        // Either the point fails to decode / is outside the subgroup, or it decodes but no longer
        // matches the random commitment. Both are acceptable rejections.
        Err(_) => {}
        Ok(tampered) => {
            let _ = tampered.verify().expect_err("tampered commitment must not verify");
        }
    }
}

/// Substituting a different valid G1 point for the encrypted message is **not** caught by the
/// pairing check, and the reference client behaves identically.
///
/// Both clients verify only that the recovered `r * PK` matches the ciphertext's declared random
/// commitment; neither binds the encrypted message `M` to that proof. Geth says so explicitly in
/// `crypto/tpke/startWorker`: *"If a user (the encryptor) use a different r to generate cMsg, no
/// error will be detected here, but the following aes decryption will fail."* A substituted `M`
/// therefore yields a syntactically valid but wrong AES key, and the tampering only surfaces at the
/// AES layer. This test pins that boundary so the two implementations cannot silently drift apart:
/// the substitution must produce a *different* key, and that key must not recover the plaintext.
#[test]
fn substituted_encrypted_message_yields_a_key_that_cannot_decrypt() {
    let mut tampered = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    // Replace the encrypted message with another validator's valid compressed G1 share.
    let replacement: [u8; DECRYPTION_SHARE_LEN] = unhex(PARTICIPANTS[3].2);
    tampered[..DECRYPTION_SHARE_LEN].copy_from_slice(&replacement);

    let tampered = TpkeCiphertext::decode(&tampered).expect("substituted point still decodes");
    tampered.verify().expect("random commitment is untouched, so the proof still holds");

    let shares = PARTICIPANTS
        .iter()
        .take(5)
        .enumerate()
        .map(|(position, (_, _, share))| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            (position as u32 + 1, DecryptionShare::decode(&share).expect("share decodes"))
        })
        .collect::<Vec<_>>();

    // Aggregation still succeeds: the pairing check protects `r`, not `M`.
    let tampered_key = aggregate_and_decrypt(&tampered, &global_key(), &shares, GETH_SCALER)
        .expect("the pairing check does not bind the encrypted message");
    let honest_key = aggregate_and_decrypt(&ciphertext(), &global_key(), &shares, GETH_SCALER)
        .expect("honest ciphertext aggregates");
    assert_ne!(
        tampered_key.as_bytes(),
        honest_key.as_bytes(),
        "substitution must change the recovered key"
    );

    // The tampering surfaces at the AES layer instead: the substituted key cannot recover the
    // plaintext (almost certainly an invalid PKCS#7 pad, but a wrong plaintext would also qualify).
    let encrypted_message = hex::decode(ENCRYPTED_MESSAGE).expect("message hex decodes");
    match tampered_key.decrypt_message(&encrypted_message) {
        Err(_) => {}
        Ok(recovered) => assert_ne!(
            recovered.as_slice(),
            hex::decode(PLAINTEXT).expect("plaintext hex decodes").as_slice(),
            "substituted key must not recover the honest plaintext"
        ),
    }
}

/// Four shares are below the 5-of-7 threshold; interpolation yields a wrong key and the pairing
/// check must reject it rather than returning attacker-influenced plaintext.
#[test]
fn insufficient_shares_are_rejected() {
    let error = recover(4).expect_err("four shares cannot reconstruct a 5-of-7 secret");
    assert!(matches!(error, TpkeError::InvalidDecryptionShares), "unexpected error: {error:?}");
}

/// Duplicating one validator's share under two different indices must not pass, otherwise a single
/// committee member could forge a quorum.
#[test]
fn duplicated_share_cannot_forge_a_quorum() {
    let shares = [(1_usize, 0_usize), (2, 0), (3, 2), (4, 3), (5, 4)]
        .into_iter()
        .map(|(index, source)| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(PARTICIPANTS[source].2);
            (index as u32, DecryptionShare::decode(&share).expect("share decodes"))
        })
        .collect::<Vec<_>>();

    let error = aggregate_and_decrypt(&ciphertext(), &global_key(), &shares, GETH_SCALER)
        .expect_err("a duplicated share cannot form a quorum");
    assert!(matches!(error, TpkeError::InvalidDecryptionShares), "unexpected error: {error:?}");
}

/// A zero index is not a DKG participant and must be refused before any curve work happens.
#[test]
fn zero_valued_share_index_is_rejected() {
    let share: [u8; DECRYPTION_SHARE_LEN] = unhex(PARTICIPANTS[0].2);
    let share = DecryptionShare::decode(&share).expect("share decodes");
    let shares = vec![(0_u32, share)];
    let error = aggregate_and_decrypt(&ciphertext(), &global_key(), &shares, GETH_SCALER)
        .expect_err("index 0 is not a DKG participant");
    assert!(
        matches!(error, TpkeError::InvalidShareIndex { .. } | TpkeError::InvalidDecryptionShares),
        "unexpected error: {error:?}"
    );
}

/// A commitment whose EIP-2537 padding bytes are non-zero must be refused.
#[test]
fn malformed_commitment_padding_is_rejected() {
    let mut commitment = hex::decode(AGGREGATED_COMMITMENT).expect("commitment hex decodes");
    commitment[0] = 0x01;
    let error = global_public_key_from_commitment(&commitment, GETH_SCALER)
        .expect_err("non-zero padding is invalid");
    assert!(matches!(error, TpkeError::InvalidCommitmentPadding), "unexpected error: {error:?}");
}

/// A zero scaler would make the global key undefined and must be refused.
#[test]
fn zero_scaler_is_rejected() {
    let commitment = hex::decode(AGGREGATED_COMMITMENT).expect("commitment hex decodes");
    let error = global_public_key_from_commitment(&commitment, 0)
        .expect_err("a zero scaler cannot scale a key");
    assert!(matches!(error, TpkeError::InvalidScaler), "unexpected error: {error:?}");
}

/// Guards the constants the negative cases build on.
#[test]
fn negative_vectors_use_the_mainnet_scaler() {
    assert_eq!(GETH_SCALER, NEOX_DKG_SCALER);
    assert_eq!(ENCRYPTED_DATA_PREFIX, [0xff; 4]);
    assert_eq!(TPKE_PRIVATE_KEY_LEN, 32);
}
