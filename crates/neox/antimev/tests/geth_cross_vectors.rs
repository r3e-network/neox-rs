//! Cross-implementation vectors captured from the Neo X Geth reference client.
//!
//! These values were produced by an exporter added to `bane-labs/go-ethereum` (branch `bane-main`,
//! commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`) which replays the deterministic 7-node /
//! 5-threshold DKG privnet setup and dumps every intermediate TPKE value. The exporter file is
//! `antimev/neox_cross_vectors_test.go` and it does not alter any Geth protocol logic.
//!
//! The AES message key and the encryption nonce are randomised on every reference-client run, so
//! these are *observed* values from one run, not stable golden bytes. What they prove is
//! **interoperability**: given exactly what Geth produced, this crate must decode the same
//! ciphertext, derive the same per-validator decryption shares, recover the same AES key and
//! decrypt to the same plaintext. Layout constants are deterministic and are asserted directly.

use alloy_primitives::hex;
use reth_neox_antimev::{
    aggregate_and_decrypt, global_public_key_from_commitment, public_key_from_private_key,
    DecryptionShare, EnvelopeData, TpkeCiphertext, DECRYPTION_SHARE_LEN, ENCRYPTED_DATA_GAS_LEN,
    ENCRYPTED_DATA_HASH_LEN, ENCRYPTED_DATA_PREFIX, ENCRYPTED_DATA_ROUND_LEN, ENVELOPE_TARGET,
    MIN_ENCRYPTED_GAS_LIMIT, MIN_ENVELOPE_DATA_LEN, NEOX_DKG_SCALER, TPKE_CIPHERTEXT_LEN,
    TPKE_PRIVATE_KEY_LEN, TPKE_SERIALIZED_LEN,
};

/// Scaler the reference client computed for its fixed 5-of-7 committee.
const GETH_SCALER: u64 = 360;

/// EIP-2537 padded aggregated DKG commitment (`KeyManagement` wire format).
const AGGREGATED_COMMITMENT: &str = "0000000000000000000000000000000018dd4618491d74d7f2f28d3abbc75da47c5e7f8dbe6be755f088ee6a33303182f692a11374e097320284ef6741ada855000000000000000000000000000000000d891e0baaebc62690986dfda50d19cea62cdd56bc4855c156f00d3125b67164fc1c5e99aa42348aa2c7470b26bf66bc";

/// Compressed global TPKE public key the reference client derived from that commitment.
const GLOBAL_PUBLIC_KEY: &str =
    "8f2df85bc8add14e861a2bafedb0a408d23d94160c49300c87009477c546e2373a343f95c97b56d027445be0ea7b6f75";

/// One Envelope ciphertext as serialized by Geth: `M || R || commitment`.
const CIPHERTEXT: &str = "87646d6c9ad515aa13110fd840e3061b9bf7aac0c6916acac7d1ce9dd95b188bfd24a9dbac1a3142bd061236eae5a607b673683c8b635aeb6bf2916e383a049608909d227273021a8198ef2fc34fd38d876585ff92bb7d8deaa84d41760da1d7b895ff7eccc2e1081fcc36f49239101efdea44853c6a552cf9a42d04378239a2c40b4e375b64aaa82160f4a77d69e7400514dd3d483f92ccca7b5fc627c5289a829e6fce849259788352ef1aea8c68a714674ce824f1ee453bcfea5dfb2ecf5b";

/// AES-256-CBC ciphertext of [`PLAINTEXT`] under the recovered key.
const ENCRYPTED_MESSAGE: &str = "46128109e9d2c1aaed6b416c0fe7c23825910d7a1324ff87885759b2210e9471eaaa39c8250ce13447ce3a39b78edb401db7a3ead31e91586daa554924350d0e5d19c641c1adacc53d26f6d8234ecbbfc25b7f6cf25cf3f9629fb5653cc32097b030f020d37b098f6020365a944085d01c5cc6d85bb5bd50a53483ab1571207c";

/// The plaintext that must come back out.
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

fn unhex<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("vector hex decodes");
    <[u8; N]>::try_from(decoded.as_slice()).expect("vector has the expected length")
}

/// The reference client's own committee scaler must match the constant this crate hard-codes.
#[test]
fn scaler_matches_reference_client() {
    assert_eq!(GETH_SCALER, NEOX_DKG_SCALER);
}

/// Envelope recognition constants must match the reference client byte for byte.
#[test]
fn envelope_layout_matches_reference_client() {
    assert_eq!(ENCRYPTED_DATA_PREFIX, [0xff; 4]);
    assert_eq!(ENCRYPTED_DATA_ROUND_LEN, 4);
    assert_eq!(ENCRYPTED_DATA_GAS_LEN, 4);
    assert_eq!(ENCRYPTED_DATA_HASH_LEN, 32);
    assert_eq!(TPKE_CIPHERTEXT_LEN, 192);
    assert_eq!(MIN_ENVELOPE_DATA_LEN, 348);
    assert_eq!(MIN_ENCRYPTED_GAS_LIMIT, 21_000);
    assert_eq!(DECRYPTION_SHARE_LEN, 48);
    assert_eq!(
        ENVELOPE_TARGET.to_string().to_lowercase(),
        "0x1212000000000000000000000000000000000003"
    );
}

/// The global key derived from the on-chain commitment must equal the reference client's key.
#[test]
fn global_public_key_matches_reference_client() {
    let commitment = hex::decode(AGGREGATED_COMMITMENT).expect("commitment hex decodes");
    let derived =
        global_public_key_from_commitment(&commitment, GETH_SCALER).expect("commitment is valid");
    let expected = unhex::<48>(GLOBAL_PUBLIC_KEY);
    assert_eq!(derived, expected, "global public key mismatch");
}

/// Every validator's private share must reproduce the public share Geth recorded.
#[test]
fn per_validator_public_shares_match_reference_client() {
    for (index, (private, public, _)) in PARTICIPANTS.iter().enumerate() {
        let private: [u8; TPKE_PRIVATE_KEY_LEN] = unhex(private);
        let derived = public_key_from_private_key(&private).expect("private share is canonical");
        let expected: [u8; 48] = unhex(public);
        assert_eq!(derived, expected, "public share mismatch for validator {}", index + 1);
    }
}

/// The reference client's ciphertext must decode and pass this crate's commitment proof.
#[test]
fn reference_ciphertext_decodes_and_verifies() {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    assert_eq!(encoded.len(), TPKE_SERIALIZED_LEN);
    let ciphertext = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");
    ciphertext.verify().expect("ciphertext commitment is consistent");
    assert_eq!(ciphertext.to_bytes().as_slice(), encoded.as_slice());
}

/// This crate must derive byte-identical decryption shares from the same private shares.
///
/// This is the strictest cross-implementation check in the file: it is not enough for both clients
/// to decrypt successfully, they must produce the same wire bytes for the `PreCommit` path.
#[test]
fn decryption_shares_match_reference_client_byte_for_byte() {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let ciphertext = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");

    for (index, (private, _, share)) in PARTICIPANTS.iter().enumerate() {
        let private: [u8; TPKE_PRIVATE_KEY_LEN] = unhex(private);
        let derived = ciphertext.decryption_share(&private).expect("private share is usable");
        let expected: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
        assert_eq!(
            derived.as_bytes(),
            &expected,
            "decryption share mismatch for validator {}",
            index + 1
        );
    }
}

/// Recovering the AES key from five Geth-generated shares must reproduce Geth's plaintext.
///
/// The reference client decrypts with the first five validators, so this exercises the exact
/// 5-of-7 quorum Neo X uses on mainnet rather than a wider quorum that could mask a scaler bug.
#[test]
fn threshold_decryption_matches_reference_client() {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let ciphertext = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");
    let global_public_key: [u8; 48] = unhex(GLOBAL_PUBLIC_KEY);

    let shares = PARTICIPANTS
        .iter()
        .take(5)
        .enumerate()
        .map(|(position, (_, _, share))| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            let share = DecryptionShare::decode(&share).expect("share decodes");
            (position as u32 + 1, share)
        })
        .collect::<Vec<_>>();

    let key = aggregate_and_decrypt(&ciphertext, &global_public_key, &shares, GETH_SCALER)
        .expect("five valid shares recover the key");

    let encrypted_message = hex::decode(ENCRYPTED_MESSAGE).expect("message hex decodes");
    let decrypted = key.decrypt_message(&encrypted_message).expect("AES decryption succeeds");
    let expected = hex::decode(PLAINTEXT).expect("plaintext hex decodes");
    assert_eq!(decrypted.as_slice(), expected.as_slice(), "decrypted plaintext mismatch");
}

/// The same quorum must recover an identical key when a different 5-of-7 subset is used, proving
/// the Lagrange interpolation is independent of which validators participate.
#[test]
fn alternate_quorum_recovers_the_same_key() {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let ciphertext = TpkeCiphertext::decode(&encoded).expect("ciphertext decodes");
    let global_public_key: [u8; 48] = unhex(GLOBAL_PUBLIC_KEY);

    let first = PARTICIPANTS
        .iter()
        .take(5)
        .enumerate()
        .map(|(position, (_, _, share))| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            (position as u32 + 1, DecryptionShare::decode(&share).expect("share decodes"))
        })
        .collect::<Vec<_>>();
    let last = PARTICIPANTS
        .iter()
        .skip(2)
        .enumerate()
        .map(|(position, (_, _, share))| {
            let share: [u8; DECRYPTION_SHARE_LEN] = unhex(share);
            (position as u32 + 3, DecryptionShare::decode(&share).expect("share decodes"))
        })
        .collect::<Vec<_>>();

    let first_key = aggregate_and_decrypt(&ciphertext, &global_public_key, &first, GETH_SCALER)
        .expect("first quorum recovers");
    let last_key = aggregate_and_decrypt(&ciphertext, &global_public_key, &last, GETH_SCALER)
        .expect("second quorum recovers");
    assert_eq!(first_key.as_bytes(), last_key.as_bytes(), "quorums disagree on the AES key");

    let encrypted_message = hex::decode(ENCRYPTED_MESSAGE).expect("message hex decodes");
    let decrypted = last_key.decrypt_message(&encrypted_message).expect("AES decryption succeeds");
    let expected = hex::decode(PLAINTEXT).expect("plaintext hex decodes");
    assert_eq!(decrypted.as_slice(), expected.as_slice());
}

/// An Envelope assembled from the reference ciphertext must parse to the values Geth wrote.
#[test]
fn envelope_fields_parse_from_reference_layout() {
    let encoded = hex::decode(CIPHERTEXT).expect("ciphertext hex decodes");
    let encrypted_message = hex::decode(ENCRYPTED_MESSAGE).expect("message hex decodes");

    let mut data = Vec::new();
    data.extend_from_slice(&ENCRYPTED_DATA_PREFIX);
    data.extend_from_slice(&7_u32.to_be_bytes());
    data.extend_from_slice(&21_000_u32.to_be_bytes());
    data.extend_from_slice(&[0xab; 32]);
    data.extend_from_slice(&encoded);
    data.extend_from_slice(&encrypted_message);

    assert!(reth_neox_antimev::is_envelope_data(&data));
    let parsed = EnvelopeData::decode(&data).expect("envelope parses");
    assert_eq!(parsed.dkg_round, 7);
    assert_eq!(parsed.encrypted_gas, 21_000);
    assert_eq!(parsed.encrypted_hash, alloy_primitives::B256::repeat_byte(0xab));
}
