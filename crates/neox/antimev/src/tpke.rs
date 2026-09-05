//! Neo X TPKE ciphertext verification, share aggregation, and AES decryption.

use crate::field::{from_u64 as fr_from_u64, multiply as fr_mul, subtract as fr_sub};
use aes::{cipher::BlockDecrypt, Aes256, Block};
use alloc::vec::Vec;
use blst::{
    blst_fp12, blst_fr, blst_fr_cneg, blst_fr_inverse, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_generator, blst_p1_affine_in_g1,
    blst_p1_cneg, blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult, blst_p1_serialize,
    blst_p1_to_affine, blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine,
    blst_p2_affine_compress, blst_p2_affine_generator, blst_p2_affine_in_g2, blst_p2_from_affine,
    blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress, blst_scalar, blst_scalar_from_bendian,
    blst_scalar_from_fr, blst_sk_check, min_pk, BLST_ERROR,
};
use cipher::KeyInit;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Compressed BLS12-381 G1 point length.
pub const G1_COMPRESSED_LEN: usize = 48;
/// Uncompressed BLS12-381 G1 point length used as the AES key seed.
pub const G1_UNCOMPRESSED_LEN: usize = 96;
/// EIP-2537's padded uncompressed G1 encoding used by the `KeyManagement` contract.
pub const G1_EIP2537_LEN: usize = 128;
/// Compressed BLS12-381 G2 point length.
pub const G2_COMPRESSED_LEN: usize = 96;
/// Serialized TPKE ciphertext length.
pub const TPKE_SERIALIZED_LEN: usize = G1_COMPRESSED_LEN * 2 + G2_COMPRESSED_LEN;
/// Serialized local decryption-share length.
pub const DECRYPTION_SHARE_LEN: usize = G1_COMPRESSED_LEN;
/// Serialized BLS12-381 G2 threshold-signature share length.
pub const SIGNATURE_SHARE_LEN: usize = G2_COMPRESSED_LEN;
/// Serialized TPKE private scalar length.
pub const TPKE_PRIVATE_KEY_LEN: usize = 32;
/// Neo X TPKE BLS signature domain separation tag.
pub const TPKE_SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Least common interpolation denominator for Neo X's fixed 5-of-7 DKG group.
pub const NEOX_DKG_SCALER: u64 = 360;

/// Neo X currently fixes the dBFT/DKG committee at seven participants.
pub const MAX_TPKE_SIGNATURE_SHARES: usize = 7;
/// Defensive ceiling for Neo X's fixed-size decryption committee.
pub const MAX_TPKE_DECRYPTION_CONTRIBUTIONS: usize = 7;

/// A validated Neo X TPKE ciphertext: `C = M + rPK`, `R = rG1`, commitment `-rG2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpkeCiphertext {
    encrypted_message: [u8; G1_COMPRESSED_LEN],
    random_commitment: [u8; G1_COMPRESSED_LEN],
    pairing_commitment: [u8; G2_COMPRESSED_LEN],
}

impl TpkeCiphertext {
    /// Parses all three compressed curve points and enforces subgroup membership.
    pub fn decode(encoded: &[u8]) -> Result<Self, TpkeError> {
        if encoded.len() != TPKE_SERIALIZED_LEN {
            return Err(TpkeError::WrongCiphertextLength { actual: encoded.len() });
        }
        let ciphertext = Self {
            encrypted_message: encoded[..G1_COMPRESSED_LEN]
                .try_into()
                .expect("fixed G1 ciphertext slice"),
            random_commitment: encoded[G1_COMPRESSED_LEN..G1_COMPRESSED_LEN * 2]
                .try_into()
                .expect("fixed G1 commitment slice"),
            pairing_commitment: encoded[G1_COMPRESSED_LEN * 2..]
                .try_into()
                .expect("fixed G2 commitment slice"),
        };
        decode_g1(&ciphertext.encrypted_message, "encrypted message")?;
        decode_g1(&ciphertext.random_commitment, "random commitment")?;
        decode_g2(&ciphertext.pairing_commitment, "pairing commitment")?;
        Ok(ciphertext)
    }

    /// Serializes the canonical compressed representation used inside an Envelope.
    pub fn to_bytes(self) -> [u8; TPKE_SERIALIZED_LEN] {
        let mut encoded = [0_u8; TPKE_SERIALIZED_LEN];
        encoded[..G1_COMPRESSED_LEN].copy_from_slice(&self.encrypted_message);
        encoded[G1_COMPRESSED_LEN..G1_COMPRESSED_LEN * 2].copy_from_slice(&self.random_commitment);
        encoded[G1_COMPRESSED_LEN * 2..].copy_from_slice(&self.pairing_commitment);
        encoded
    }

    /// Proves that the G1 and negated G2 commitments contain the same encryption scalar.
    pub fn verify(&self) -> Result<(), TpkeError> {
        let random_commitment = decode_g1(&self.random_commitment, "random commitment")?;
        let pairing_commitment = decode_g2(&self.pairing_commitment, "pairing commitment")?;
        // SAFETY: BLST returns process-lifetime pointers to immutable group generators.
        let (g1, g2) = unsafe { (*blst_p1_affine_generator(), *blst_p2_affine_generator()) };
        let product = blst_fp12::miller_loop_n(&[g2, pairing_commitment], &[random_commitment, g1])
            .final_exp();
        if product == blst_fp12::default() {
            Ok(())
        } else {
            Err(TpkeError::InvalidCiphertextCommitment)
        }
    }

    /// Produces this validator's compressed `R * private_share` decryption share.
    pub fn decryption_share(
        &self,
        private_key: &[u8; TPKE_PRIVATE_KEY_LEN],
    ) -> Result<DecryptionShare, TpkeError> {
        let mut scalar = blst_scalar::default();
        // SAFETY: both buffers have BLST's required fixed sizes and remain alive for the call.
        unsafe { blst_scalar_from_bendian(&raw mut scalar, private_key.as_ptr()) };
        // SAFETY: `scalar` was initialized immediately above.
        if !unsafe { blst_sk_check(&raw const scalar) } {
            return Err(TpkeError::InvalidPrivateKey);
        }
        let point = projective(&decode_g1(&self.random_commitment, "random commitment")?);
        let result = multiply(&point, &scalar);
        Ok(DecryptionShare(compress(&result)))
    }
}

/// A subgroup-checked compressed G1 decryption share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionShare([u8; DECRYPTION_SHARE_LEN]);

impl DecryptionShare {
    /// Decodes a compressed decryption share.
    pub fn decode(encoded: &[u8]) -> Result<Self, TpkeError> {
        if encoded.len() != DECRYPTION_SHARE_LEN {
            return Err(TpkeError::WrongShareLength { actual: encoded.len() });
        }
        let encoded: [u8; DECRYPTION_SHARE_LEN] =
            encoded.try_into().expect("fixed decryption-share slice");
        decode_g1(&encoded, "decryption share")?;
        Ok(Self(encoded))
    }

    /// Returns the compressed wire representation.
    pub const fn as_bytes(&self) -> &[u8; DECRYPTION_SHARE_LEN] {
        &self.0
    }
}

/// A subgroup-checked compressed G2 threshold-signature contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureShare([u8; SIGNATURE_SHARE_LEN]);

impl SignatureShare {
    /// Decodes a compressed signature share and enforces prime-order subgroup membership.
    pub fn decode(encoded: &[u8]) -> Result<Self, TpkeError> {
        if encoded.len() != SIGNATURE_SHARE_LEN {
            return Err(TpkeError::WrongSignatureShareLength { actual: encoded.len() });
        }
        let encoded: [u8; SIGNATURE_SHARE_LEN] =
            encoded.try_into().expect("fixed signature-share slice");
        decode_g2(&encoded, "signature share")?;
        Ok(Self(encoded))
    }

    /// Returns the compressed Neo X wire representation.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SHARE_LEN] {
        &self.0
    }
}

/// An aggregated subgroup-checked G2 threshold signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdSignature([u8; SIGNATURE_SHARE_LEN]);

impl ThresholdSignature {
    /// Returns the compressed signature bytes stored in dBFT header extra data.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_SHARE_LEN] {
        &self.0
    }
}

/// Signs the Neo X threshold-seal message with one local DKG private share.
pub fn sign_share(
    message: &[u8],
    private_key: &[u8; TPKE_PRIVATE_KEY_LEN],
    negate_result: bool,
) -> Result<SignatureShare, TpkeError> {
    let key =
        min_pk::SecretKey::from_bytes(private_key).map_err(|_| TpkeError::InvalidPrivateKey)?;
    let signature = key.sign(message, TPKE_SIGNATURE_DST, &[]);
    let mut encoded = signature.to_bytes();
    if negate_result {
        // Compressed BLS points use this bit to choose between the two possible Y coordinates.
        encoded[0] ^= 0x20;
    }
    SignatureShare::decode(&encoded)
}

/// Derives a compressed G1 public key from one canonical TPKE private scalar.
pub fn public_key_from_private_key(
    private_key: &[u8; TPKE_PRIVATE_KEY_LEN],
) -> Result<[u8; G1_COMPRESSED_LEN], TpkeError> {
    let key =
        min_pk::SecretKey::from_bytes(private_key).map_err(|_| TpkeError::InvalidPrivateKey)?;
    Ok(key.sk_to_pk().to_bytes())
}

/// Interpolates indexed Neo X signature shares at zero using the on-chain DKG scaler.
pub fn aggregate_signature_shares(
    shares: &[(u32, SignatureShare)],
    scaler: u64,
) -> Result<ThresholdSignature, TpkeError> {
    validate_indexed_shares(shares, scaler)?;
    let points = shares
        .iter()
        .map(|(index, share)| Ok((*index, decode_g2(share.as_bytes(), "signature share")?)))
        .collect::<Result<Vec<_>, TpkeError>>()?;
    Ok(interpolate_signature_shares(&points, scaler))
}

/// Lagrange-interpolates already-decoded G2 signature shares at the origin.
///
/// The caller has validated share indices (unique, nonzero). Splitting the decode out lets the
/// combination search decode each G2 share once instead of on every subset it appears in.
fn interpolate_signature_shares(
    points: &[(u32, blst_p2_affine)],
    scaler: u64,
) -> ThresholdSignature {
    let indices = points.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let mut aggregated: Option<blst_p2> = None;
    for (position, (_, point)) in points.iter().enumerate() {
        let lambda = lagrange_coefficient(position, &indices, scaler);
        let weighted = multiply_g2(&projective_g2(point), &lambda);
        if let Some(sum) = &mut aggregated {
            let prior = *sum;
            // SAFETY: inputs are initialized subgroup points and output aliases neither input.
            unsafe { blst_p2_add_or_double(sum, &raw const prior, &raw const weighted) };
        } else {
            aggregated = Some(weighted);
        }
    }
    ThresholdSignature(compress_g2(&aggregated.expect("nonempty shares checked above")))
}

/// Tries threshold-sized share combinations and returns the first aggregate matching the global
/// DKG public key.
pub fn aggregate_and_verify_signature_shares(
    message: &[u8],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    shares: &[(u32, SignatureShare)],
    threshold: usize,
    scaler: u64,
    negated_result: bool,
) -> Result<ThresholdSignature, TpkeError> {
    aggregate_and_verify_signature_shares_with_limit(
        message,
        global_public_key,
        shares,
        threshold,
        scaler,
        negated_result,
        MAX_TPKE_SIGNATURE_SHARES,
    )
}

/// Parameterized counterpart used by Geth committees whose size is not seven.
pub fn aggregate_and_verify_signature_shares_with_parameters(
    message: &[u8],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    shares: &[(u32, SignatureShare)],
    threshold: usize,
    scaler: u64,
    negated_result: bool,
    participants: usize,
) -> Result<ThresholdSignature, TpkeError> {
    aggregate_and_verify_signature_shares_with_limit(
        message,
        global_public_key,
        shares,
        threshold,
        scaler,
        negated_result,
        participants,
    )
}

fn aggregate_and_verify_signature_shares_with_limit(
    message: &[u8],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    shares: &[(u32, SignatureShare)],
    threshold: usize,
    scaler: u64,
    negated_result: bool,
    max_shares: usize,
) -> Result<ThresholdSignature, TpkeError> {
    if threshold == 0 || shares.len() < threshold {
        return Err(TpkeError::NotEnoughSignatureShares { threshold, actual: shares.len() });
    }
    if shares.len() > max_shares {
        return Err(TpkeError::TooManySignatureShares(shares.len()));
    }
    validate_indexed_shares(shares, scaler)?;
    let public_key = min_pk::PublicKey::key_validate(global_public_key)
        .map_err(|_| TpkeError::InvalidGlobalPublicKey)?;
    let mut ordered = shares.to_vec();
    ordered.sort_unstable_by_key(|(index, _)| *index);
    // Decode each candidate G2 share once; every subgroup check already passed at SignatureShare
    // construction, so a share appears in many combinations but need only be uncompressed once.
    let decoded = ordered
        .iter()
        .map(|(index, share)| Ok((*index, decode_g2(share.as_bytes(), "signature share")?)))
        .collect::<Result<Vec<_>, TpkeError>>()?;
    let mut positions = Vec::with_capacity(threshold);
    let mut combinations = Vec::new();
    collect_combinations(ordered.len(), threshold, 0, &mut positions, &mut combinations);
    for positions in combinations {
        let selected = positions.iter().map(|position| decoded[*position]).collect::<Vec<_>>();
        let signature = interpolate_signature_shares(&selected, scaler);
        let mut verification_bytes = *signature.as_bytes();
        if negated_result {
            verification_bytes[0] ^= 0x20;
        }
        let Ok(candidate) = min_pk::Signature::sig_validate(&verification_bytes, true) else {
            continue;
        };
        if candidate.verify(true, message, TPKE_SIGNATURE_DST, &[], &public_key, true) ==
            BLST_ERROR::BLST_SUCCESS
        {
            return Ok(signature);
        }
    }
    Err(TpkeError::SignatureAggregationFailed)
}

fn collect_combinations(
    item_count: usize,
    choose: usize,
    start: usize,
    current: &mut Vec<usize>,
    output: &mut Vec<Vec<usize>>,
) {
    if current.len() == choose {
        output.push(current.clone());
        return;
    }
    let remaining = choose - current.len();
    for position in start..=item_count - remaining {
        current.push(position);
        collect_combinations(item_count, choose, position + 1, current, output);
        current.pop();
    }
}

/// Converts `KeyManagement`'s unscaled EIP-2537 commitment into the compressed global DKG key.
pub fn global_public_key_from_commitment(
    commitment: &[u8],
    scaler: u64,
) -> Result<[u8; G1_COMPRESSED_LEN], TpkeError> {
    if commitment.len() != G1_EIP2537_LEN {
        return Err(TpkeError::WrongCommitmentLength { actual: commitment.len() });
    }
    if scaler == 0 {
        return Err(TpkeError::InvalidScaler);
    }
    if commitment[..16].iter().any(|byte| *byte != 0) ||
        commitment[64..80].iter().any(|byte| *byte != 0)
    {
        return Err(TpkeError::InvalidCommitmentPadding);
    }
    let mut unpadded = [0_u8; G1_UNCOMPRESSED_LEN];
    unpadded[..G1_COMPRESSED_LEN].copy_from_slice(&commitment[16..64]);
    unpadded[G1_COMPRESSED_LEN..].copy_from_slice(&commitment[80..]);
    let mut affine = blst_p1_affine::default();
    // SAFETY: `unpadded` has BLST's exact uncompressed G1 length and the output is valid storage.
    let status = unsafe { blst_p1_deserialize(&raw mut affine, unpadded.as_ptr()) };
    // SAFETY: `affine` was initialized by BLST when deserialization succeeded.
    if status != BLST_ERROR::BLST_SUCCESS || !unsafe { blst_p1_affine_in_g1(&raw const affine) } {
        return Err(TpkeError::InvalidG1Point("aggregated commitment"));
    }
    let scalar = fr_from_u64(scaler);
    let mut scalar_bytes = blst_scalar::default();
    // SAFETY: `scalar` is an initialized scalar-field element.
    unsafe { blst_scalar_from_fr(&raw mut scalar_bytes, &raw const scalar) };
    Ok(compress(&multiply(&projective(&affine), &scalar_bytes)))
}

/// A recovered TPKE message point used as the AES-256 key seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptedKey([u8; G1_COMPRESSED_LEN]);

impl DecryptedKey {
    /// Returns the canonical compressed G1 point.
    pub const fn as_bytes(&self) -> &[u8; G1_COMPRESSED_LEN] {
        &self.0
    }

    /// Decrypts AES-256-CBC content using Neo X's point-derived key and IV with strict PKCS#7
    /// unpadding.
    pub fn decrypt_message(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, TpkeError> {
        self.decrypt_message_with_mode(ciphertext, true)
    }

    /// Decrypts AES-256-CBC content using Neo X's point-derived key and IV.
    ///
    /// When `strict` is `true`, PKCS#7 unpadding strictly requires padding bytes in `1..=16`
    /// and all padding bytes to equal the declared padding length.
    /// When `strict` is `false` (legacy reference-client mode), unpadding only verifies that
    /// the declared padding length does not exceed the plaintext buffer length.
    pub fn decrypt_message_with_mode(
        &self,
        ciphertext: &[u8],
        strict: bool,
    ) -> Result<Zeroizing<Vec<u8>>, TpkeError> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(TpkeError::InvalidAesCiphertextLength { actual: ciphertext.len() });
        }
        let affine = decode_g1(&self.0, "decrypted key")?;
        let point = projective(&affine);
        let mut seed = Zeroizing::new([0_u8; G1_UNCOMPRESSED_LEN]);
        // SAFETY: `seed` is exactly the 96 bytes required by BLST and `point` is initialized.
        unsafe { blst_p1_serialize(seed.as_mut_ptr(), &raw const point) };
        let digest = Sha256::digest(seed);
        let cipher = Aes256::new_from_slice(&digest).map_err(|_| TpkeError::InvalidAesKey)?;
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        let mut previous =
            Zeroizing::new(<[u8; 16]>::try_from(&digest[..16]).expect("SHA-256 IV slice"));
        for chunk in plaintext.as_chunks_mut::<16>().0 {
            let encrypted = Zeroizing::new(*chunk);
            let mut block = Block::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for ((output, decrypted), chaining) in
                chunk.iter_mut().zip(block.iter()).zip(previous.iter())
            {
                *output = *decrypted ^ *chaining;
            }
            previous.copy_from_slice(&*encrypted);
            block.zeroize();
        }
        let padding = usize::from(*plaintext.last().expect("nonempty AES plaintext"));
        if strict {
            if padding == 0 || padding > 16 || plaintext.len() < padding {
                return Err(TpkeError::InvalidPkcs7Padding);
            }
            if !plaintext[plaintext.len() - padding..]
                .iter()
                .all(|byte| usize::from(*byte) == padding)
            {
                return Err(TpkeError::InvalidPkcs7Padding);
            }
        } else if plaintext.len() < padding {
            return Err(TpkeError::InvalidPkcs7Padding);
        }
        let message_len = plaintext.len() - padding;
        plaintext.truncate(message_len);
        Ok(plaintext)
    }
}

/// Aggregates indexed threshold shares and recovers the encrypted G1 AES key.
///
/// `scaler` must match the DKG group scaler used to derive the on-chain global public key.
pub fn aggregate_and_decrypt(
    ciphertext: &TpkeCiphertext,
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    shares: &[(u32, DecryptionShare)],
    scaler: u64,
) -> Result<DecryptedKey, TpkeError> {
    validate_indexed_shares(shares, scaler)?;
    let public_key = decode_g1(global_public_key, "global public key")?;
    aggregate_and_decrypt_with_key(ciphertext, &public_key, shares, scaler)
}

/// Aggregates decryption shares against an already-decoded global public key.
///
/// Callers must pass validated shares (unique, nonzero indices); the batch path decodes the shared
/// public key once and skips the per-combination re-validation because each combination is a subset
/// of an already-validated eligible set.
fn aggregate_and_decrypt_with_key(
    ciphertext: &TpkeCiphertext,
    public_key: &blst_p1_affine,
    shares: &[(u32, DecryptionShare)],
    scaler: u64,
) -> Result<DecryptedKey, TpkeError> {
    let indices = shares.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let mut aggregated: Option<blst_p1> = None;
    for (position, (_, share)) in shares.iter().enumerate() {
        let lambda = lagrange_coefficient(position, &indices, scaler);
        let point = projective(&decode_g1(share.as_bytes(), "decryption share")?);
        let weighted = multiply(&point, &lambda);
        if let Some(sum) = &mut aggregated {
            let prior = *sum;
            // SAFETY: all points are initialized subgroup points; output may alias neither input.
            unsafe { blst_p1_add_or_double(sum, &raw const prior, &raw const weighted) };
        } else {
            aggregated = Some(weighted);
        }
    }
    let recovered_random = aggregated.expect("nonempty shares checked above");

    let commitment = decode_g2(&ciphertext.pairing_commitment, "pairing commitment")?;
    let recovered_affine = affine(&recovered_random);
    // SAFETY: BLST returns a process-lifetime pointer to the immutable G2 generator.
    let g2 = unsafe { *blst_p2_affine_generator() };
    let proof =
        blst_fp12::miller_loop_n(&[commitment, g2], &[*public_key, recovered_affine]).final_exp();
    if proof != blst_fp12::default() {
        return Err(TpkeError::InvalidDecryptionShares);
    }

    let encrypted_message =
        projective(&decode_g1(&ciphertext.encrypted_message, "encrypted message")?);
    let mut negative_random = recovered_random;
    // SAFETY: `negative_random` is an initialized subgroup point.
    unsafe { blst_p1_cneg(&raw mut negative_random, true) };
    let mut decrypted = blst_p1::default();
    // SAFETY: inputs are initialized subgroup points and output is a distinct buffer.
    unsafe {
        blst_p1_add_or_double(
            &raw mut decrypted,
            &raw const encrypted_message,
            &raw const negative_random,
        )
    };
    Ok(DecryptedKey(compress(&decrypted)))
}

/// Tries threshold-sized validator combinations and decrypts every AES key with one valid subset.
///
/// Contributions whose share count does not match the ciphertext count are ignored, matching the
/// reference client's handling of partial `PreCommit` packets. A single subset must verify for all
/// keys so a Byzantine validator cannot influence different Envelopes with different quorums.
pub fn aggregate_and_decrypt_keys(
    ciphertexts: &[TpkeCiphertext],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    contributions: &[(u32, Vec<DecryptionShare>)],
    threshold: usize,
    scaler: u64,
) -> Result<Vec<DecryptedKey>, TpkeError> {
    aggregate_and_decrypt_keys_with_limit(
        ciphertexts,
        global_public_key,
        contributions,
        threshold,
        scaler,
        MAX_TPKE_DECRYPTION_CONTRIBUTIONS,
    )
}

/// Parameterized counterpart used by Geth committees whose size is not seven.
pub fn aggregate_and_decrypt_keys_with_parameters(
    ciphertexts: &[TpkeCiphertext],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    contributions: &[(u32, Vec<DecryptionShare>)],
    threshold: usize,
    scaler: u64,
    participants: usize,
) -> Result<Vec<DecryptedKey>, TpkeError> {
    aggregate_and_decrypt_keys_with_limit(
        ciphertexts,
        global_public_key,
        contributions,
        threshold,
        scaler,
        participants,
    )
}

fn aggregate_and_decrypt_keys_with_limit(
    ciphertexts: &[TpkeCiphertext],
    global_public_key: &[u8; G1_COMPRESSED_LEN],
    contributions: &[(u32, Vec<DecryptionShare>)],
    threshold: usize,
    scaler: u64,
    max_contributions: usize,
) -> Result<Vec<DecryptedKey>, TpkeError> {
    if ciphertexts.is_empty() {
        return Ok(Vec::new());
    }
    let mut eligible = contributions
        .iter()
        .filter(|(_, shares)| shares.len() == ciphertexts.len())
        .cloned()
        .collect::<Vec<_>>();
    if threshold == 0 || eligible.len() < threshold {
        return Err(TpkeError::NotEnoughDecryptionContributions {
            threshold,
            actual: eligible.len(),
        });
    }
    if eligible.len() > max_contributions {
        return Err(TpkeError::TooManyDecryptionContributions(eligible.len()));
    }
    validate_indexed_shares(&eligible, scaler)?;
    eligible.sort_unstable_by_key(|(index, _)| *index);

    // The global DKG public key is identical for the whole block; decode and subgroup-check it once
    // rather than on every (combination x ciphertext) inner call. A malformed key must still
    // surface as DecryptionAggregationFailed to match the per-combination error-swallowing
    // below (which the non-empty `combinations` set guarantees is reached).
    let Ok(public_key) = decode_g1(global_public_key, "global public key") else {
        return Err(TpkeError::DecryptionAggregationFailed);
    };

    let mut positions = Vec::with_capacity(threshold);
    let mut combinations = Vec::new();
    collect_combinations(eligible.len(), threshold, 0, &mut positions, &mut combinations);
    for positions in combinations {
        let mut keys = Vec::with_capacity(ciphertexts.len());
        let mut valid = true;
        for (ciphertext_index, ciphertext) in ciphertexts.iter().enumerate() {
            let shares = positions
                .iter()
                .map(|position| {
                    let (index, contribution) = &eligible[*position];
                    (*index, contribution[ciphertext_index])
                })
                .collect::<Vec<_>>();
            match aggregate_and_decrypt_with_key(ciphertext, &public_key, &shares, scaler) {
                Ok(key) => keys.push(key),
                Err(_) => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Ok(keys);
        }
    }
    Err(TpkeError::DecryptionAggregationFailed)
}

fn validate_indexed_shares<T>(shares: &[(u32, T)], scaler: u64) -> Result<(), TpkeError> {
    if shares.is_empty() {
        return Err(TpkeError::NotEnoughShares);
    }
    if scaler == 0 {
        return Err(TpkeError::InvalidScaler);
    }
    for (position, (index, _)) in shares.iter().enumerate() {
        if *index == 0 {
            return Err(TpkeError::InvalidShareIndex(0));
        }
        if shares[..position].iter().any(|(prior, _)| prior == index) {
            return Err(TpkeError::DuplicateShareIndex(*index));
        }
    }
    Ok(())
}

fn lagrange_coefficient(position: usize, indices: &[u32], scaler: u64) -> blst_scalar {
    let x_i = fr_from_u64(u64::from(indices[position]));
    let mut numerator = fr_from_u64(scaler);
    let mut denominator = fr_from_u64(1);
    for (other_position, index) in indices.iter().enumerate() {
        if other_position == position {
            continue;
        }
        let x_j = fr_from_u64(u64::from(*index));
        let mut negative_x_j = blst_fr::default();
        // SAFETY: both values are initialized field elements and the output is distinct.
        unsafe { blst_fr_cneg(&raw mut negative_x_j, &raw const x_j, true) };
        numerator = fr_mul(&numerator, &negative_x_j);
        denominator = fr_mul(&denominator, &fr_sub(&x_i, &x_j));
    }
    let mut denominator_inverse = blst_fr::default();
    // SAFETY: unique nonzero indexes make `denominator` nonzero.
    unsafe { blst_fr_inverse(&raw mut denominator_inverse, &raw const denominator) };
    let coefficient = fr_mul(&numerator, &denominator_inverse);
    let mut scalar = blst_scalar::default();
    // SAFETY: `coefficient` is an initialized scalar-field element.
    unsafe { blst_scalar_from_fr(&raw mut scalar, &raw const coefficient) };
    scalar
}

fn decode_g1(
    encoded: &[u8; G1_COMPRESSED_LEN],
    field: &'static str,
) -> Result<blst_p1_affine, TpkeError> {
    let mut point = blst_p1_affine::default();
    // SAFETY: `encoded` has BLST's required compressed G1 length and both buffers are valid.
    let status = unsafe { blst_p1_uncompress(&raw mut point, encoded.as_ptr()) };
    // SAFETY: `point` was initialized by BLST when decompression succeeded.
    if status != BLST_ERROR::BLST_SUCCESS || !unsafe { blst_p1_affine_in_g1(&raw const point) } {
        return Err(TpkeError::InvalidG1Point(field));
    }
    Ok(point)
}

fn decode_g2(
    encoded: &[u8; G2_COMPRESSED_LEN],
    field: &'static str,
) -> Result<blst_p2_affine, TpkeError> {
    let mut point = blst_p2_affine::default();
    // SAFETY: `encoded` has BLST's required compressed G2 length and both buffers are valid.
    let status = unsafe { blst_p2_uncompress(&raw mut point, encoded.as_ptr()) };
    // SAFETY: `point` was initialized by BLST when decompression succeeded.
    if status != BLST_ERROR::BLST_SUCCESS || !unsafe { blst_p2_affine_in_g2(&raw const point) } {
        return Err(TpkeError::InvalidG2Point(field));
    }
    Ok(point)
}

fn projective(point: &blst_p1_affine) -> blst_p1 {
    let mut result = blst_p1::default();
    // SAFETY: input is an initialized affine point and output has sufficient storage.
    unsafe { blst_p1_from_affine(&raw mut result, point) };
    result
}

fn affine(point: &blst_p1) -> blst_p1_affine {
    let mut result = blst_p1_affine::default();
    // SAFETY: input is an initialized projective point and output has sufficient storage.
    unsafe { blst_p1_to_affine(&raw mut result, point) };
    result
}

fn multiply(point: &blst_p1, scalar: &blst_scalar) -> blst_p1 {
    let mut result = blst_p1::default();
    // SAFETY: point/scalar are initialized and the scalar buffer is the 255-bit BLST format.
    unsafe { blst_p1_mult(&raw mut result, point, scalar.b.as_ptr(), 255) };
    result
}

fn compress(point: &blst_p1) -> [u8; G1_COMPRESSED_LEN] {
    let affine = affine(point);
    let mut result = [0_u8; G1_COMPRESSED_LEN];
    // SAFETY: output is exactly 48 bytes and input is an initialized affine point.
    unsafe { blst_p1_affine_compress(result.as_mut_ptr(), &raw const affine) };
    result
}

fn projective_g2(point: &blst_p2_affine) -> blst_p2 {
    let mut result = blst_p2::default();
    // SAFETY: input is an initialized affine point and output has sufficient storage.
    unsafe { blst_p2_from_affine(&raw mut result, point) };
    result
}

fn affine_g2(point: &blst_p2) -> blst_p2_affine {
    let mut result = blst_p2_affine::default();
    // SAFETY: input is an initialized projective point and output has sufficient storage.
    unsafe { blst_p2_to_affine(&raw mut result, point) };
    result
}

fn multiply_g2(point: &blst_p2, scalar: &blst_scalar) -> blst_p2 {
    let mut result = blst_p2::default();
    // SAFETY: point/scalar are initialized and the scalar buffer is the 255-bit BLST format.
    unsafe { blst_p2_mult(&raw mut result, point, scalar.b.as_ptr(), 255) };
    result
}

fn compress_g2(point: &blst_p2) -> [u8; G2_COMPRESSED_LEN] {
    let affine = affine_g2(point);
    let mut result = [0_u8; G2_COMPRESSED_LEN];
    // SAFETY: output is exactly 96 bytes and input is an initialized affine point.
    unsafe { blst_p2_affine_compress(result.as_mut_ptr(), &raw const affine) };
    result
}

/// Neo X TPKE and AES compatibility failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TpkeError {
    /// TPKE ciphertext is not exactly 192 bytes.
    #[error("invalid TPKE ciphertext length: expected 192, got {actual}")]
    WrongCiphertextLength {
        /// Actual byte length.
        actual: usize,
    },
    /// A decryption share is not exactly 48 bytes.
    #[error("invalid TPKE decryption-share length: expected 48, got {actual}")]
    WrongShareLength {
        /// Actual byte length.
        actual: usize,
    },
    /// A signature share is not exactly one compressed G2 point.
    #[error("invalid TPKE signature-share length: expected 96, got {actual}")]
    WrongSignatureShareLength {
        /// Actual byte length.
        actual: usize,
    },
    /// `KeyManagement` commitments use four 32-byte EIP-2537 limbs.
    #[error("invalid KeyManagement commitment length: expected 128, got {actual}")]
    WrongCommitmentLength {
        /// Actual byte length.
        actual: usize,
    },
    /// EIP-2537 pads each 48-byte base-field coordinate to 64 bytes with zeroes.
    #[error("invalid nonzero KeyManagement commitment padding")]
    InvalidCommitmentPadding,
    /// The global DKG public key is not a subgroup-valid compressed G1 point.
    #[error("invalid Neo X DKG global public key")]
    InvalidGlobalPublicKey,
    /// Fewer signature contributions were supplied than the configured threshold.
    #[error("not enough TPKE signature shares: need {threshold}, got {actual}")]
    NotEnoughSignatureShares {
        /// Required number of shares.
        threshold: usize,
        /// Supplied number of shares.
        actual: usize,
    },
    /// Defensive bound for share-combination search.
    #[error("too many TPKE signature shares: {0}")]
    TooManySignatureShares(usize),
    /// No threshold-sized subset produced a signature matching the global key.
    #[error("TPKE signature shares could not be aggregated into a valid signature")]
    SignatureAggregationFailed,
    /// Fewer structurally complete decryption contributions were supplied than the threshold.
    #[error("not enough TPKE decryption contributions: need {threshold}, got {actual}")]
    NotEnoughDecryptionContributions {
        /// Required number of validator contributions.
        threshold: usize,
        /// Structurally complete contributions supplied.
        actual: usize,
    },
    /// Defensive bound for decryption-share combination search.
    #[error("too many TPKE decryption contributions: {0}")]
    TooManyDecryptionContributions(usize),
    /// No threshold-sized contribution subset decrypted every encrypted key.
    #[error("TPKE decryption contributions could not recover the encrypted keys")]
    DecryptionAggregationFailed,
    /// A compressed G1 point is malformed or outside the prime-order subgroup.
    #[error("invalid TPKE G1 point in {0}")]
    InvalidG1Point(&'static str),
    /// A compressed G2 point is malformed or outside the prime-order subgroup.
    #[error("invalid TPKE G2 point in {0}")]
    InvalidG2Point(&'static str),
    /// `R` and the negated G2 commitment do not contain the same random scalar.
    #[error("invalid TPKE ciphertext pairing commitment")]
    InvalidCiphertextCommitment,
    /// The local private share is zero or not a canonical BLS12-381 scalar.
    #[error("invalid TPKE private key")]
    InvalidPrivateKey,
    /// No validator shares were supplied.
    #[error("no TPKE decryption shares supplied")]
    NotEnoughShares,
    /// DKG share indexes start from one.
    #[error("invalid TPKE share index {0}")]
    InvalidShareIndex(u32),
    /// Share interpolation cannot use the same DKG index twice.
    #[error("duplicate TPKE share index {0}")]
    DuplicateShareIndex(u32),
    /// A DKG scaler must be nonzero.
    #[error("invalid zero TPKE DKG scaler")]
    InvalidScaler,
    /// Aggregated shares do not match the global public key and ciphertext commitment.
    #[error("TPKE decryption shares failed pairing verification")]
    InvalidDecryptionShares,
    /// AES-CBC input must be a nonempty sequence of complete blocks.
    #[error("invalid AES-CBC ciphertext length {actual}")]
    InvalidAesCiphertextLength {
        /// Actual byte length.
        actual: usize,
    },
    /// AES-256 rejected the derived 32-byte key.
    #[error("invalid derived AES-256 key")]
    InvalidAesKey,
    /// AES plaintext does not contain strict PKCS#7 padding.
    #[error("invalid AES-CBC PKCS#7 padding")]
    InvalidPkcs7Padding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn scalar_bytes(value: u64) -> [u8; TPKE_PRIVATE_KEY_LEN] {
        let mut encoded = [0_u8; TPKE_PRIVATE_KEY_LEN];
        encoded[TPKE_PRIVATE_KEY_LEN - 8..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    fn polynomial(index: u64) -> u64 {
        3 + 5 * index + 7 * index.pow(2) + 11 * index.pow(3) + 13 * index.pow(4)
    }

    const SECRET: [u8; 32] =
        alloy_primitives::hex!("4642141848782b7edebdf6c4bbd0c0262efb3ffda85469b5b6af3c5ac471f3cd");
    const PUBLIC: [u8; 48] = alloy_primitives::hex!(
        "b212a84213ff85bdb998f20acf6e3841d8e58e78716e27b776eb7b39d8a09009\
         26dc0e7e9ef550a22cf2421a347c4bdf"
    );
    const MESSAGE: [u8; 48] = alloy_primitives::hex!(
        "af95b8218cbee2f4fa48e6b6f1df4e8ee46fee73c270dba395dad523d10c9b35\
         295ccfc92cf0a9db8a065e16dafbfaad"
    );
    const CIPHERTEXT: [u8; 192] = alloy_primitives::hex!(
        "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
         966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
         8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
         8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
         cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
         17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
    );
    const SHARE: [u8; 48] = alloy_primitives::hex!(
        "8dcd83e7fd7ea998b6b170354e9b87bebd4844d0dfe45d8d45650f84859adb04\
         6c8fe43ac96567e67f944915268b4d31"
    );
    const AES_CIPHERTEXT: [u8; 48] = alloy_primitives::hex!(
        "11c33a6047ffc7c6ad7924bfec11cc01407fc48876528175ecceacdb385b0802e\
         64dc8156dc3d74545e9686bec0745ba"
    );
    const PLAINTEXT: &[u8] = b"Neo X Reth TPKE compatibility vector";

    const THRESHOLD_PUBLIC: [u8; 48] = alloy_primitives::hex!(
        "a9aff13809f72c4c35e2196675fd26a0d0d077ca35c6d4f05bd471deba419f66\
         a303935358a8abf7a8ef3b76e67072c2"
    );
    const THRESHOLD_MESSAGE: [u8; 48] = alloy_primitives::hex!(
        "8e561be3daa71004f1079f6e5de35a852cc5a167305fb1004a44764298130611\
         8df2244de29566320a8fb4b727021f89"
    );
    const THRESHOLD_CIPHERTEXT: [u8; 192] = alloy_primitives::hex!(
        "8418bd4bd31c6edc5b4c62e92d5f4823ec68866e7b8b41726c0dfd30ca6132c5\
         c117c02251bc725c44348741141a4d0da19380790417c8ee14a30e3ff44f06f6\
         df21976cd24894cf784da5708fde08d0e02b51be1e375dee205f4a98198c5e3e\
         8b947bc9dfb76541a6c5e3672d97119eb86699d2eae60459c39593ffb48fe9ce\
         34f29959376387ab4e7054bcaba5110418508378f8d1e20a606287ab36d9a167\
         9b7a16747fd14ba12909fab4bbc9fc5ba39a04ef61dbdb29097a2d5403826897"
    );
    const THRESHOLD_SHARES: [(u32, [u8; 48]); 5] = [
        (
            1,
            alloy_primitives::hex!(
                "83539765592bf2bde85abfed46ca18c9fd18eba94b8d180aa608aac4d15db124\
                 d665b79ac3c01ed2d06216197b34f08b"
            ),
        ),
        (
            2,
            alloy_primitives::hex!(
                "8cb3077295c815d275c08515a1aad8f9f1f66c1f9d0326f89cee56344de23bf9\
                 6cd955315a460f0c6b83c2560a0f8d49"
            ),
        ),
        (
            4,
            alloy_primitives::hex!(
                "94a618b9b24c336a530362cec808f81699a5bb6c8f994d2b9393a9df82bd4c16\
                 b3b8987337c97fa9d1058320784aabe5"
            ),
        ),
        (
            6,
            alloy_primitives::hex!(
                "807fb76b7fb43d0c49ea7eebcf3ac01c5a6e88d2d9ab872b65845b15ae6c379\
                 b5c753f4213f4f22db50ed1e65ac2e44f"
            ),
        ),
        (
            7,
            alloy_primitives::hex!(
                "85651e6c1ed980dcbe3745e699c5c6d265c3332c83922680e5d9834ccd9fc96a\
                 e83fac254c7ac514adc35cdab1a98793"
            ),
        ),
    ];

    #[test]
    fn matches_geth_tpke_and_aes_vector() {
        let ciphertext = TpkeCiphertext::decode(&CIPHERTEXT).unwrap();
        assert_eq!(ciphertext.to_bytes(), CIPHERTEXT);
        ciphertext.verify().unwrap();

        let share = ciphertext.decryption_share(&SECRET).unwrap();
        assert_eq!(share.as_bytes(), &SHARE);
        let decrypted = aggregate_and_decrypt(&ciphertext, &PUBLIC, &[(1, share)], 1).unwrap();
        assert_eq!(decrypted.as_bytes(), &MESSAGE);
        assert_eq!(&**decrypted.decrypt_message(&AES_CIPHERTEXT).unwrap(), PLAINTEXT);
    }

    #[test]
    fn rejects_mismatched_ciphertext_commitment_and_share_indexes() {
        let mut invalid = CIPHERTEXT;
        invalid[96] ^= 0x20;
        let ciphertext = TpkeCiphertext::decode(&invalid).unwrap();
        assert_eq!(ciphertext.verify(), Err(TpkeError::InvalidCiphertextCommitment));

        let ciphertext = TpkeCiphertext::decode(&CIPHERTEXT).unwrap();
        let share = DecryptionShare::decode(&SHARE).unwrap();
        assert_eq!(
            aggregate_and_decrypt(&ciphertext, &PUBLIC, &[(0, share)], 1),
            Err(TpkeError::InvalidShareIndex(0))
        );
        assert_eq!(
            aggregate_and_decrypt(&ciphertext, &PUBLIC, &[(1, share), (1, share)], 1),
            Err(TpkeError::DuplicateShareIndex(1))
        );
    }

    #[test]
    fn matches_geth_five_of_seven_interpolation_vector() {
        let ciphertext = TpkeCiphertext::decode(&THRESHOLD_CIPHERTEXT).unwrap();
        ciphertext.verify().unwrap();
        let shares: Vec<_> = THRESHOLD_SHARES
            .iter()
            .map(|(index, share)| (*index, DecryptionShare::decode(share).unwrap()))
            .collect();
        let decrypted =
            aggregate_and_decrypt(&ciphertext, &THRESHOLD_PUBLIC, &shares, 360).unwrap();
        assert_eq!(decrypted.as_bytes(), &THRESHOLD_MESSAGE);

        let mut invalid = shares;
        invalid[2].1 .0[0] ^= 0x20;
        assert_eq!(
            aggregate_and_decrypt(&ciphertext, &THRESHOLD_PUBLIC, &invalid, 360),
            Err(TpkeError::InvalidDecryptionShares)
        );
    }

    #[test]
    fn batch_decryption_ignores_partial_and_byzantine_contributions() {
        let ciphertext = TpkeCiphertext::decode(&THRESHOLD_CIPHERTEXT).unwrap();
        let mut contributions = THRESHOLD_SHARES
            .iter()
            .map(|(index, share)| (*index, vec![DecryptionShare::decode(share).unwrap()]))
            .collect::<Vec<_>>();
        contributions.push((3, vec![DecryptionShare::decode(&SHARE).unwrap()]));
        contributions.push((5, Vec::new()));

        let keys = aggregate_and_decrypt_keys(
            &[ciphertext],
            &THRESHOLD_PUBLIC,
            &contributions,
            5,
            NEOX_DKG_SCALER,
        )
        .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].as_bytes(), &THRESHOLD_MESSAGE);

        assert_eq!(
            aggregate_and_decrypt_keys(
                &[ciphertext],
                &THRESHOLD_PUBLIC,
                &contributions[..4],
                5,
                NEOX_DKG_SCALER,
            ),
            Err(TpkeError::NotEnoughDecryptionContributions { threshold: 5, actual: 4 })
        );
    }

    #[test]
    fn rejects_invalid_aes_lengths_and_padding() {
        let key = DecryptedKey(MESSAGE);
        assert_eq!(
            key.decrypt_message(&[]),
            Err(TpkeError::InvalidAesCiphertextLength { actual: 0 })
        );
        assert_eq!(
            key.decrypt_message(&AES_CIPHERTEXT[..AES_CIPHERTEXT.len() - 1]),
            Err(TpkeError::InvalidAesCiphertextLength { actual: AES_CIPHERTEXT.len() - 1 })
        );

        for mask in [1, 2, 0x10, 0x80] {
            let mut corrupted = AES_CIPHERTEXT;
            *corrupted.last_mut().unwrap() ^= mask;
            assert_eq!(
                key.decrypt_message(&corrupted),
                Err(TpkeError::InvalidPkcs7Padding),
                "ciphertext mutation {mask:#x} must not produce a partial plaintext"
            );
        }
    }

    /// Derives the AES key and IV the way [`DecryptedKey::decrypt_message`] does, so tests can
    /// build ciphertexts whose plaintexts carry a chosen PKCS#7 padding.
    fn aes_material(key: &DecryptedKey) -> (Aes256, [u8; 16]) {
        let affine = decode_g1(key.as_bytes(), "test key").unwrap();
        let point = projective(&affine);
        let mut seed = Zeroizing::new([0_u8; G1_UNCOMPRESSED_LEN]);
        // SAFETY: `seed` is exactly the 96 bytes required by BLST and `point` is initialized.
        unsafe { blst_p1_serialize(seed.as_mut_ptr(), &raw const point) };
        let digest = Sha256::digest(seed.as_ref());
        let cipher = Aes256::new_from_slice(&digest).unwrap();
        (cipher, digest[..16].try_into().expect("SHA-256 IV slice"))
    }

    fn aes_cbc_encrypt(cipher: &Aes256, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut previous = *iv;
        for chunk in plaintext.as_chunks::<16>().0 {
            let mut block = Block::clone_from_slice(chunk);
            for (byte, chaining) in block.iter_mut().zip(previous.iter()) {
                *byte ^= chaining;
            }
            cipher.encrypt_block(&mut block);
            let encrypted: [u8; 16] = block.into();
            ciphertext.extend_from_slice(&encrypted);
            previous = encrypted;
        }
        ciphertext
    }

    #[test]
    fn accepts_every_valid_pkcs7_padding_length() {
        let key = DecryptedKey(MESSAGE);
        let (cipher, iv) = aes_material(&key);

        for padding in 1..=16_usize {
            let mut plaintext = [0xa5_u8; 32][..32 - padding].to_vec();
            plaintext.resize(32, padding as u8);
            let ciphertext = aes_cbc_encrypt(&cipher, &iv, &plaintext);

            let decrypted = key.decrypt_message(&ciphertext).unwrap();
            assert_eq!(*decrypted, plaintext[..32 - padding], "padding length {padding}");
        }
    }

    #[test]
    fn rejects_padding_violations_the_reference_client_rejects() {
        let key = DecryptedKey(MESSAGE);
        let (cipher, iv) = aes_material(&key);

        // Padding bytes outside 1..=16 must refuse instead of truncating to a partial plaintext.
        for padding in [0_u8, 17, 255] {
            let plaintext = vec![padding; 32];
            let ciphertext = aes_cbc_encrypt(&cipher, &iv, &plaintext);
            assert_eq!(
                key.decrypt_message(&ciphertext),
                Err(TpkeError::InvalidPkcs7Padding),
                "padding byte {padding}"
            );
        }

        // A tail whose bytes do not all repeat the padding length must also refuse.
        let mut inconsistent = vec![0xa5_u8; 29];
        inconsistent.extend_from_slice(&[3, 3, 2]);
        let ciphertext = aes_cbc_encrypt(&cipher, &iv, &inconsistent);
        assert_eq!(key.decrypt_message(&ciphertext), Err(TpkeError::InvalidPkcs7Padding));
    }

    #[test]
    fn aggregates_five_of_seven_signature_shares() {
        const MESSAGE: &[u8] = b"Neo X Reth threshold signature vector";
        let mut shares = [1_u32, 2, 4, 6, 7]
            .into_iter()
            .map(|index| {
                (
                    index,
                    sign_share(MESSAGE, &scalar_bytes(polynomial(u64::from(index))), false)
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            shares[0].1.as_bytes(),
            &alloy_primitives::hex!(
                "888c8840ce22c3d241cac8402addac66992cc4eafd48b23483822f3ddb866686744c43a39e7ca8b16e9cf4ec6db30e160f087b846776dfc1952ba904f162f85f90658c9b0e53fbc1bbe756018e5f368f717dd382cda2a3b9aa9fb8e2e7c935c5"
            )
        );
        let aggregated = aggregate_signature_shares(&shares, 360).unwrap();

        // Interpolation at zero recovers `f(0)`, while the Neo X DKG public key and signature are
        // both multiplied by the group scaler.
        let global_key = min_pk::SecretKey::from_bytes(&scalar_bytes(3 * 360)).unwrap();
        let expected = global_key.sign(MESSAGE, TPKE_SIGNATURE_DST, &[]).to_bytes();
        let global_public_key = global_key.sk_to_pk().to_bytes();
        assert_eq!(aggregated.as_bytes(), &expected);
        assert_eq!(
            aggregated.as_bytes(),
            &alloy_primitives::hex!(
                "89bea6da3b4306794620e843e52721cea119bef812790a02e3d93f4714b2c24c3043766295b23aa7741caea35eca7fe80d6358fd0b3787f37984ca60742a400442b68eb64efeaafb45b33c844b8ce4522de0ed26ef823e9da80c7d6c98ec0373"
            )
        );
        shares.push((
            3,
            sign_share(MESSAGE, &scalar_bytes(999), false).expect("valid but incorrect share"),
        ));
        assert_eq!(
            aggregate_and_verify_signature_shares(
                MESSAGE,
                &global_public_key,
                &shares,
                5,
                NEOX_DKG_SCALER,
                false,
            )
            .unwrap()
            .as_bytes(),
            &expected
        );

        let negated = [1_u32, 2, 4, 6, 7]
            .into_iter()
            .map(|index| {
                (
                    index,
                    sign_share(MESSAGE, &scalar_bytes(polynomial(u64::from(index))), true).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut expected_negated = expected;
        expected_negated[0] ^= 0x20;
        assert_eq!(
            aggregate_signature_shares(&negated, 360).unwrap().as_bytes(),
            &expected_negated
        );
        assert_eq!(
            aggregate_and_verify_signature_shares(
                MESSAGE,
                &global_public_key,
                &negated,
                5,
                NEOX_DKG_SCALER,
                true,
            )
            .unwrap()
            .as_bytes(),
            &expected_negated
        );
    }

    #[test]
    fn converts_live_testnet_key_management_commitment() {
        let commitment = alloy_primitives::hex!(
            "0000000000000000000000000000000014c3bd13c1d7fcf70d288e1be25e5fed75ecd9de009614311862bf53a630de41b688d3dc2dd8ab6418b7ff74d16e1d310000000000000000000000000000000011172e2b1d5f21c54ba685ff04703657f74630886044a3b8884c5a2077fa0776da2cc1a4dbdfa64dd1092bcb0c3fe192"
        );
        assert_eq!(
            global_public_key_from_commitment(&commitment, 360).unwrap(),
            alloy_primitives::hex!(
                "94d0b75f3e08312e972fc319b25d2d58ca20f077704a7b351cb264716b8e75409e8c463c1da64f288cce8d961e592019"
            )
        );
    }

    /// Pins the Anti-MEV half of the infinity divergence registered in `docs/neox/README.md`.
    ///
    /// The same gnark `MillerLoop` filtering that lets the reference client accept an all-infinity
    /// dBFT header seal also applies to `PublicKey.Verify`, whose pairs are `(pk, hash)` and
    /// `(-g1, sig)`. An infinity global key and an infinity aggregate drop both pairs, leaving the
    /// accumulator at one, so `VerifySig` reports success. Threshold aggregation here rejects both
    /// instead, so the divergence is a client-wide validation policy rather than a header-path
    /// special case.
    #[test]
    fn rejects_infinity_signature_inputs_accepted_by_the_geth_oracle() {
        const MESSAGE: &[u8] = b"Neo X Reth threshold signature vector";
        let mut infinity_public_key = [0_u8; G1_COMPRESSED_LEN];
        infinity_public_key[0] = 0xc0;

        let shares = [1_u32, 2, 4, 6, 7]
            .into_iter()
            .map(|index| {
                (
                    index,
                    sign_share(MESSAGE, &scalar_bytes(polynomial(u64::from(index))), false)
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        // An infinity global public key must fail key validation before any pairing is attempted.
        assert_eq!(
            aggregate_and_verify_signature_shares(
                MESSAGE,
                &infinity_public_key,
                &shares,
                5,
                360,
                false
            ),
            Err(TpkeError::InvalidGlobalPublicKey)
        );

        // A real key with infinity shares must fail aggregation rather than verify against the
        // filtered pairing. Infinity is a valid compressed G2 encoding, so `SignatureShare::decode`
        // accepts it and the rejection has to come from the aggregate check.
        let global_public_key =
            min_pk::SecretKey::from_bytes(&scalar_bytes(3 * 360)).unwrap().sk_to_pk().to_bytes();
        let mut infinity_share = [0_u8; SIGNATURE_SHARE_LEN];
        infinity_share[0] = 0xc0;
        let infinity_shares = [1_u32, 2, 4, 6, 7]
            .into_iter()
            .map(|index| (index, SignatureShare::decode(&infinity_share).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            aggregate_and_verify_signature_shares(
                MESSAGE,
                &global_public_key,
                &infinity_shares,
                5,
                360,
                false
            ),
            Err(TpkeError::SignatureAggregationFailed)
        );

        // The ciphertext commitment pairing is deliberately *not* strict: infinity is accepted
        // there to keep Envelope recognition byte-compatible, since a zero encryption scalar only
        // exposes the sender's own payload and cannot forge consensus.
        let mut degenerate = [0_u8; TPKE_SERIALIZED_LEN];
        degenerate[0] = 0xc0;
        degenerate[G1_COMPRESSED_LEN] = 0xc0;
        degenerate[G1_COMPRESSED_LEN * 2] = 0xc0;
        assert!(TpkeCiphertext::decode(&degenerate).is_ok());
    }
}
