//! Cross-implementation vectors for the previous/current round separation (DKG resharing).
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

const PREVIOUS_ROUND: Round = Round {
    name: "previous",
    commitment: "0000000000000000000000000000000018dd4618491d74d7f2f28d3abbc75da47c5e7f8dbe6be755f088ee6a33303182f692a11374e097320284ef6741ada855000000000000000000000000000000000d891e0baaebc62690986dfda50d19cea62cdd56bc4855c156f00d3125b67164fc1c5e99aa42348aa2c7470b26bf66bc",
    global_public_key: "8f2df85bc8add14e861a2bafedb0a408d23d94160c49300c87009477c546e2373a343f95c97b56d027445be0ea7b6f75",
    ciphertext: "8ffb3ccfb0bd5e4ee4f3240cc1af31ce9e79513e485bf55f0c6b6ed81a98da0a6408d832c5854f14c8f0d1a12464c41cb66e81a7306a940ff3db9228df173e953f0cb90d1f3bf1728bdbc562cc5fe26407d927dd938430c61f1abf74a81693609895cc4476acb17e3965d7939a504f0fc51e0899ab0b948a7c0e51511e6360c83e54af8a9854f4f7bee6421e809eca6d106c5be160f671fc274e7b9c688035c51910c40a736dd4ab4d457199df8ab3aa1ccc449470b773ff609f60a92bf2a291",
    encrypted_message: "e81b47a408011a76c6b55c2f4fc2f292b29e3725897b3fc5853171e8b5e7fa31c80c37e0187160d4cfac50df555e5055b5cab71bc429bfca6230c523221d9be64109dec0704ec9ae13bcc714162cbd49633db1355d212b23e9a1fad89ef087409ade2a2bc5c2d509af1778fd99c5d4e98ec60cbdd0818fb80bd2dbd669ee6b0f901664cae4b63243c68e8d9f1156dc7d",
    plaintext: "70726576696f75732d726f756e64207061796c6f61643a20616e20456e76656c6f7065207365616c6564206265666f72652074686520636f6d6d697474656520726f746174696f6e2c206c6f6e6720656e6f75676820746f206e656564206d6f7265207468616e206f6e652041455320626c6f636b20746f20626520696e746572657374696e67",
    shares: [
        (
            "47c66c197be13af484372fe5d6cf656a99427ca686bf774dc16f878c32883381",
            "a286a0112b71499eb9f919a0fdf401414328d671c2012685199139def8ad4b4f9d2f1cd33c1aa098fed48fb0be1f3692",
            "b39dbf179e3c145747f8719b4a9148b59c5b0d5338add75af2ca92f61b0a4e9b5c59371eb47740112c58c6632313e784",
        ),
        (
            "6a9ab809f656138408994c47ac6397ad9184f4896f0025e7e98d0c686942c49e",
            "b66fe9518845242e33eeea999579a7149372e0162d6cbea23a1c4618cfca4569c2257f0fec0d8a69f39417f07f689b02",
            "8bd1da5d74f72e1a6033185760410bdf08ff99c492b798d7318a37e975dde9478000532ef042cbd6caf208de5eaee557",
        ),
        (
            "2f42b55ec0b2bd6f684dcefbb98954efe54c2752441b10a394393d2ba01e3e41",
            "98b967fdb67c809b422863438d7fb4e557d0761674f67197240a86c9e62b3cda6fef6da2b4b7d3ca5b33b0ed957dc4b2",
            "8cf5c2659d5782078bd4f3e956752ec81e3d30c46b29b483054d23b63273a20473f31f0cb2f968019e63f6794a90792c",
        ),
        (
            "4d50be9ac7e42c01230ca271baf65e76c06b22ecc095123af1b26978949696ca",
            "86d0e24dfe6f07f1b8e6eb7b242e84c84f0aea9eedaf3c4b14bb869fcd140408b702c385cf1d120b4035680ff30f3f9e",
            "8b1fb218e5099ee9afc34a101d73b71e8d5749c4e0b07bd7970f147fa29eb99b19303d12df7beac441ee92e25a6d2e07",
        ),
        (
            "04b62474a6b6a2a9aedad5587121fd569d17b97ed47e8c175a4580e8f8f03f96",
            "b3591376432003030b259ccf12bc1627536d33de6ae1aeecae24f09de5f6887e397fb85ccd8a0ced617be37a8a2c79ef",
            "8a854a7b1221f1fd939844ebead65231f604ac7a8de16a186c368d816bf491879cb8820f8dcfcf27e836f2ad6b17ebdf",
        ),
        (
            "4942c11cc92421f8de9f82d5e3b1ea988e19fd7da567ea4a4e4e130674382506",
            "84192a8b2e79f37703e82b0daf52951f662dd2960c0867c0b310ac5c7194b7700742298f63e2c60fb5f1c1b598690de1",
            "969f133e6db7591a4f4a7478f6ebbfdca5b0def3115ea0784d1d0ff45adc0051144bebee1ea612ee724081241a836182",
        ),
        (
            "2337bda41f687d5c48551247146b8f0fa0df21958e6ec39576364f52a243ae77",
            "83cd718058b888360ea228f4a652e4d5f3862cdec5594d50cbb2f6cf1e057e09f85b3dbb91bcffc4cfd0c2814b09a6b3",
            "abe4dd24af2e5915327b8e603e02a3f4da0edde8734d4a3318d5731227f4794b24fc0bb346386f6ec4868fcedb5f8bb0",
        ),
    ],
};

const CURRENT_ROUND: Round = Round {
    name: "current",
    commitment: "000000000000000000000000000000000244303fc0a8dfa9cb691be80347a1a94afd236c4412f41204300da56c304dd7ed0e5e21d59460bdebcdd8f0028b739d000000000000000000000000000000000f871d9c81b4bf2a7adfe9fa570150c2f25d8ae0fab92a79c7084b5f6eaf3787d54adda967c7201a585756d338e251b3",
    global_public_key: "90d2a7ea34b67eb3c3584b8e19bef3f3fb4be203a94cb558243a73515920202166d5a84ff6bb6c6788304c5d0e366b86",
    ciphertext: "982e1a27978404f041ee8ac4aed3ad0d39eeef7b1572dc201bbe377d95d5cf2932642a2e225eff847e96a596ab97cb31acfea9c07b4985f5f719d7eec663928e2ef08a1f5b705b74c3b16a79933e204189c02f01c26c7d72a43c08945b9f538da839d474339082d2d8a1f1633b1839f1bda3328ae34590af5e6c04ea16bfdd1045a0eae4c9ed8f531dfa7c1d7b8099b40299486ae5400e181ad406986f2af18faecc69786b907898b52bed48aff36d9008240c9e76b7347d7f7b5ce5695772a0",
    encrypted_message: "da5ca5f7f35b30169d84dd80d057fd5579a20ff348e1c7e5c479d1bcf2dea620b060c517ff4f68008e8ab8eb1b9a3d4f8485493f788e3471e5c4a6b6f1b8ea4fd6fcb01169d85b9b9f4a47ae54f0aae998489f69f4cf5f270ce86bd75a44740161e0762bfd5553dd10e744200bae0e4c207c24ea14ed41e8f477e2fc244c930a",
    plaintext: "63757272656e742d726f756e64207061796c6f61643a20616e20456e76656c6f7065207365616c65642061667465722074686520636f6d6d697474656520726f746174696f6e2c20616c736f206c6f6e6720656e6f75676820746f207370616e207365766572616c2041455320626c6f636b73",
    shares: [
        (
            "13d8b1287c013385ff19801d9ec913b07fcc540e089498cd93df8760c21a6b3b",
            "8bd970d9e1afb5e763cb58b0f8468cb939fad7370d3b9f5595e587deb3515585abc23c21125b1fb898dd3d149315f872",
            "99c745c05446188333946c43b4b49e25ce3a749ffdd77da65bdcdee6da9c0241bb0b489908de2a1956c4a055b882ef27",
        ),
        (
            "66c7e78cc0d747a1c0fc327db722f4e0cba5ec3cb4a17313264448542586cc9d",
            "85250fb47f67b741768f5153b6d4b720b71e1049eafb334e41b3f5b6391e45afd9b031fb98df6c4cf99578792d3b7062",
            "8c29fd7e7b0ffb79a029041024c65a740992ea4dd023b0feeeab2a7522e43e5a8450cecf495e276c873df61cd65ecb42",
        ),
        (
            "1a6e02cdcceaff83c9f2fc0cefaf5daba253fe2f69e096ca4c898f3eb02b11a9",
            "850c4fd16dafd6a956f938ccf202b37e06e2a6f12b959e58752b7c2c45357abab0ee1a418374ca8ccd67635e78ece559",
            "b260f685a0cf0e4e9a560fd7c9eee804b846dc071bd9148edccdfde0af8a643c464849bf820573b8bf5b0ed2832857df",
        ),
        (
            "0c339ad2d5b10c547942bffd98dca34abd1bb1bfbdb2021a5c9291d07d433d03",
            "b4f48deeb2426be11249abbb0767df428bc95740f8f62a1730ecd21999aab3e5619cb41f46e873d55312b1a41039376f",
            "a7d639310d3d68ee8965afe1719adaac5214c168880c5457b53900c5f6da28be65994e2225406f55d611fff793f6f21f",
        ),
        (
            "2a67832b441c977d3550647a191936ce4cc53029ce724e125e84e82f561cd3ae",
            "a882cf9ccefe6a8110e01963a8654616b5bb2590f87ea6af310597aab3a0d417eaf6d69953e7b4ab793fcb574e12602f",
            "80cdbc6cf4d5063d0b4c4b08f0109dacfeff5a073633334e866bf2ff56258c77aef0830e4233adbd6cbffa713585efa0",
        ),
        (
            "5c1a19b507da3d38d21482b500175527a116ec12437766a70cc88cf4b216dd0e",
            "85e4a54671523c47f797e03645e7d86e0c9b5c8d63f7dc34f2bd7f289656249e40f28d95e55cd5a5ba6bce42f05b8d55",
            "a58bb3bf986e223c125d9a4e9870f1f0b55fa8b0cd4677f704ba61b03d81ce724299000ab71e84eadf04b98b4c53919d",
        ),
        (
            "0d2f9f496db28f4b5de18ee0fd2b2f23d517fd834d122eb3d407dd2eb6a1e2e7",
            "a561185d80f1c97946d4e371064ae3ffa91ad84c5e802144587b072cd8f814584966907225d779a584dcc214ec2698d3",
            "b003b2520ab11199472149d69ddb307c8d56afe0c52e6708e2ae6ea80be29cb7ae6974b63e618661ec6646f027deb0c2",
        ),
    ],
};

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
            let derived =
                public_key_from_private_key(&private).expect("private share is canonical");
            let expected: [u8; 48] = unhex(public);
            assert_eq!(
                derived,
                expected,
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
            PREVIOUS_ROUND.shares[position].0,
            CURRENT_ROUND.shares[position].0,
            "validator {} must receive new share material after a reshare",
            position + 1
        );
    }
}
