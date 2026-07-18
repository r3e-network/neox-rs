//! Neo X 5-of-7 DKG polynomial and PVSS generation.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use alloc::vec::Vec;
use alloy_primitives::{hex, U256};
use blst::{
    blst_bendian_from_scalar, blst_fp12, blst_fr, blst_fr_add, blst_fr_cneg, blst_fr_from_scalar,
    blst_fr_from_uint64, blst_fr_inverse, blst_fr_mul, blst_fr_sub, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_affine_generator, blst_p1_affine_in_g1, blst_p1_affine_is_equal,
    blst_p1_affine_is_inf, blst_p1_deserialize, blst_p1_from_affine, blst_p1_generator,
    blst_p1_mult, blst_p1_serialize, blst_p1_to_affine, blst_p2, blst_p2_affine,
    blst_p2_affine_generator, blst_p2_affine_in_g2, blst_p2_affine_is_inf, blst_p2_cneg,
    blst_p2_deserialize, blst_p2_generator, blst_p2_mult, blst_p2_serialize, blst_scalar,
    blst_scalar_from_bendian, blst_scalar_from_fr, BLST_ERROR,
};
use core::fmt;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, SecretKey};
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed validator count deployed by Neo X DKG.
pub const NEOX_DKG_PARTICIPANTS: usize = 7;
/// Fixed Byzantine threshold deployed by Neo X DKG.
pub const NEOX_DKG_THRESHOLD: usize = 5;
/// EIP-2537 encoded G1 point length.
pub const NEOX_DKG_G1_LEN: usize = 128;
/// EIP-2537 encoded G2 point length.
pub const NEOX_DKG_G2_LEN: usize = 256;
/// Exact ECIES share-message length accepted by Neo X Geth.
pub const NEOX_DKG_ECIES_MESSAGE_LEN: usize = 124;
/// Exact polynomial-commitment length inside a Neo X PVSS.
pub const NEOX_DKG_COMMITMENT_LEN: usize = NEOX_DKG_THRESHOLD * NEOX_DKG_G1_LEN;
/// Exact PVSS length accepted by `KeyManagement`.
pub const NEOX_DKG_GENERATED_PVSS_LEN: usize =
    (NEOX_DKG_THRESHOLD + NEOX_DKG_PARTICIPANTS + 1) * NEOX_DKG_G1_LEN + NEOX_DKG_G2_LEN;

const NEOX_DKG_ECIES_POINT_LEN: usize = 64;
const NEOX_DKG_ECIES_NONCE_LEN: usize = 12;

const BLS12_381_SCALAR_MODULUS: [u8; 32] =
    hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// One canonical nonzero BLS12-381 scalar containing private DKG material.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DkgSecretScalar([u8; 32]);

impl DkgSecretScalar {
    /// Validates a big-endian scalar without silently reducing it modulo the field.
    pub fn new(encoded: [u8; 32]) -> Result<Self, DkgMaterialError> {
        if encoded.iter().all(|byte| *byte == 0) || encoded >= BLS12_381_SCALAR_MODULUS {
            return Err(DkgMaterialError::InvalidScalar)
        }
        Ok(Self(encoded))
    }

    /// Returns the canonical big-endian encoding.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Adds canonical shares in the BLS12-381 scalar field.
    pub fn aggregate(shares: &[&Self]) -> Result<Self, DkgMaterialError> {
        if shares.is_empty() {
            return Err(DkgMaterialError::EmptyScalarAggregation)
        }
        let mut result = fr_from_u64(0);
        for share in shares {
            result = fr_add(&result, &fr_from_secret(share));
        }
        try_secret_from_fr(&result)
    }

    fn random() -> Result<Self, DkgMaterialError> {
        loop {
            let mut encoded = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut encoded)
                .map_err(|error| DkgMaterialError::Entropy(error.to_string()))?;
            if let Ok(scalar) = Self::new(encoded) {
                return Ok(scalar)
            }
        }
    }

    #[cfg(test)]
    fn from_u64(value: u64) -> Self {
        let mut encoded = [0_u8; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        Self::new(encoded).expect("test scalar is canonical")
    }
}

impl fmt::Debug for DkgSecretScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgSecretScalar([REDACTED])")
    }
}

/// Secret degree-four polynomial used by Neo X's fixed 5-of-7 sharing scheme.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DkgPolynomial {
    coefficients: [DkgSecretScalar; NEOX_DKG_THRESHOLD],
}

impl DkgPolynomial {
    /// Derives the same replay-protected sharing polynomial as Neo X Geth.
    ///
    /// Geth intentionally truncates both the round and coefficient position to one byte.
    pub fn deterministic(
        message_private_key: &[u8; 32],
        chain_id: U256,
        round: u64,
    ) -> Result<Self, DkgMaterialError> {
        if message_private_key.iter().all(|byte| *byte == 0) {
            return Err(DkgMaterialError::EmptyPrivateSource)
        }
        if chain_id.is_zero() {
            return Err(DkgMaterialError::EmptyReplayProtection)
        }
        let private_first = message_private_key
            .iter()
            .position(|byte| *byte != 0)
            .expect("nonzero private source checked");
        // Go's `big.Int.Bytes()` omits leading zeroes from the ECIES private scalar.
        let private_source = &message_private_key[private_first..];
        let chain_id = chain_id.to_be_bytes::<32>();
        let first = chain_id.iter().position(|byte| *byte != 0).expect("nonzero chain ID checked");
        let public_source = &chain_id[first..];
        let mut coefficients = Vec::with_capacity(NEOX_DKG_THRESHOLD);
        for index in 0..NEOX_DKG_THRESHOLD {
            coefficients.push(predictable_scalar(
                private_source,
                public_source,
                round as u8,
                index as u8,
            ));
        }
        Ok(Self {
            coefficients: coefficients
                .try_into()
                .expect("fixed DKG threshold determines coefficient count"),
        })
    }

    /// Re-randomizes all nonconstant terms while retaining the current global secret.
    pub fn renovate(&self) -> Result<Self, DkgMaterialError> {
        let mut coefficients = Vec::with_capacity(NEOX_DKG_THRESHOLD);
        coefficients.push(self.coefficients[0].clone());
        for _ in 1..NEOX_DKG_THRESHOLD {
            coefficients.push(DkgSecretScalar::random()?);
        }
        Ok(Self {
            coefficients: coefficients
                .try_into()
                .expect("fixed DKG threshold determines coefficient count"),
        })
    }

    /// Generates fresh PVSS randomness, seven private evaluations, and the exact contract bytes.
    pub fn generate_pvss(&self) -> Result<DkgPvssMaterial, DkgMaterialError> {
        let randomizer = DkgSecretScalar::random()?;
        Ok(self.generate_pvss_with_randomizer(&randomizer))
    }

    /// Returns one canonical evaluation at a one-based validator index.
    pub fn evaluate(&self, index: u64) -> Result<DkgSecretScalar, DkgMaterialError> {
        if !(1..=NEOX_DKG_PARTICIPANTS as u64).contains(&index) {
            return Err(DkgMaterialError::InvalidParticipantIndex(index))
        }
        Ok(secret_from_fr(&evaluate_polynomial(&self.coefficients, index)))
    }

    /// Returns the exact EIP-2537 commitment for all five coefficients.
    pub fn commitment(&self) -> [u8; NEOX_DKG_COMMITMENT_LEN] {
        let mut encoded = [0_u8; NEOX_DKG_COMMITMENT_LEN];
        for (index, coefficient) in self.coefficients.iter().enumerate() {
            let start = index * NEOX_DKG_G1_LEN;
            encoded[start..start + NEOX_DKG_G1_LEN]
                .copy_from_slice(&encode_g1(&multiply_g1_generator(coefficient)));
        }
        encoded
    }

    /// Interpolates a missing validator's constant term from five indexed shares and renovates it.
    pub fn recover_and_renovate(
        shares: &[(u64, DkgSecretScalar)],
    ) -> Result<Self, DkgMaterialError> {
        if shares.len() < NEOX_DKG_THRESHOLD {
            return Err(DkgMaterialError::InsufficientRecoveryShares { actual: shares.len() })
        }
        let selected = &shares[..NEOX_DKG_THRESHOLD];
        for (position, (index, _)) in selected.iter().enumerate() {
            if !(1..=NEOX_DKG_PARTICIPANTS as u64).contains(index) {
                return Err(DkgMaterialError::InvalidParticipantIndex(*index))
            }
            if selected[..position].iter().any(|(previous, _)| previous == index) {
                return Err(DkgMaterialError::DuplicateRecoveryShareIndex(*index))
            }
        }

        let mut constant = fr_from_u64(0);
        for (position, (index, share)) in selected.iter().enumerate() {
            let x_i = fr_from_u64(*index);
            let mut numerator = fr_from_u64(1);
            let mut denominator = fr_from_u64(1);
            for (other_position, (other_index, _)) in selected.iter().enumerate() {
                if position == other_position {
                    continue
                }
                let x = fr_from_u64(*other_index);
                let mut negative_x = blst_fr::default();
                // SAFETY: `x` is initialized and the output is distinct from the input.
                unsafe { blst_fr_cneg(&raw mut negative_x, &raw const x, true) };
                numerator = fr_mul(&numerator, &negative_x);
                denominator = fr_mul(&denominator, &fr_sub(&x_i, &fr_from_u64(*other_index)));
            }
            let mut denominator_inverse = blst_fr::default();
            // SAFETY: unique indices make the initialized denominator nonzero.
            unsafe { blst_fr_inverse(&raw mut denominator_inverse, &raw const denominator) };
            let coefficient = fr_mul(&numerator, &denominator_inverse);
            constant = fr_add(&constant, &fr_mul(&fr_from_secret(share), &coefficient));
        }

        let mut polynomial = Self::random()?;
        polynomial.coefficients[0] = try_secret_from_fr(&constant)?;
        Ok(polynomial)
    }

    fn random() -> Result<Self, DkgMaterialError> {
        let mut coefficients = Vec::with_capacity(NEOX_DKG_THRESHOLD);
        for _ in 0..NEOX_DKG_THRESHOLD {
            coefficients.push(DkgSecretScalar::random()?);
        }
        Ok(Self {
            coefficients: coefficients
                .try_into()
                .expect("fixed DKG threshold determines coefficient count"),
        })
    }

    fn generate_pvss_with_randomizer(&self, randomizer: &DkgSecretScalar) -> DkgPvssMaterial {
        let mut encoded = Vec::with_capacity(NEOX_DKG_GENERATED_PVSS_LEN);
        for coefficient in &self.coefficients {
            encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(coefficient)));
        }

        encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(randomizer)));
        let mut r2 = multiply_g2_generator(randomizer);
        // Geth encodes `-rG2`, making `e(rG1,G2) * e(G1,-rG2) == 1`.
        // SAFETY: `r2` is an initialized projective point and is mutated in place.
        unsafe { blst_p2_cneg(&raw mut r2, true) };
        encoded.extend_from_slice(&encode_g2(&r2));

        let shares = core::array::from_fn(|position| {
            self.evaluate((position + 1) as u64).expect("fixed one-based PVSS index is valid")
        });
        for share in &shares {
            encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(share)));
        }
        debug_assert_eq!(encoded.len(), NEOX_DKG_GENERATED_PVSS_LEN);
        DkgPvssMaterial { encoded, shares }
    }

    #[cfg(test)]
    fn from_u64_coefficients(coefficients: [u64; NEOX_DKG_THRESHOLD]) -> Self {
        Self { coefficients: coefficients.map(DkgSecretScalar::from_u64) }
    }
}

impl fmt::Debug for DkgPolynomial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgPolynomial([REDACTED])")
    }
}

/// Public PVSS bytes paired with the seven secret polynomial evaluations used by the prover.
pub struct DkgPvssMaterial {
    encoded: Vec<u8>,
    shares: [DkgSecretScalar; NEOX_DKG_PARTICIPANTS],
}

impl DkgPvssMaterial {
    /// Returns the exact 1,920-byte EIP-2537 contract encoding.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns secret evaluations in one-based pending-validator order.
    pub const fn shares(&self) -> &[DkgSecretScalar; NEOX_DKG_PARTICIPANTS] {
        &self.shares
    }

    /// Separates the public contract bytes from the zeroizing secret evaluations.
    pub fn into_parts(self) -> (Vec<u8>, [DkgSecretScalar; NEOX_DKG_PARTICIPANTS]) {
        (self.encoded, self.shares)
    }
}

impl fmt::Debug for DkgPvssMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DkgPvssMaterial")
            .field("encoded_len", &self.encoded.len())
            .field("shares", &"[REDACTED]")
            .finish()
    }
}

/// A fully decoded and verified Neo X PVSS announcement.
pub struct DkgPvss {
    commitments: [blst_p1_affine; NEOX_DKG_THRESHOLD],
    random_commitment_g1: blst_p1_affine,
    random_commitment_g2: blst_p2_affine,
    public_shares: [blst_p1_affine; NEOX_DKG_PARTICIPANTS],
}

impl DkgPvss {
    /// Decodes every EIP-2537 point and verifies the randomizer pairing and all polynomial shares.
    pub fn decode(encoded: &[u8]) -> Result<Self, DkgMaterialError> {
        if encoded.len() != NEOX_DKG_GENERATED_PVSS_LEN {
            return Err(DkgMaterialError::WrongPvssLength { actual: encoded.len() })
        }

        let mut offset = 0;
        let mut commitments = Vec::with_capacity(NEOX_DKG_THRESHOLD);
        for index in 0..NEOX_DKG_THRESHOLD {
            commitments.push(decode_g1_eip2537(
                &encoded[offset..offset + NEOX_DKG_G1_LEN],
                "polynomial commitment",
            )?);
            offset += NEOX_DKG_G1_LEN;
            debug_assert_eq!(offset, (index + 1) * NEOX_DKG_G1_LEN);
        }
        let random_commitment_g1 =
            decode_g1_eip2537(&encoded[offset..offset + NEOX_DKG_G1_LEN], "PVSS G1 randomizer")?;
        offset += NEOX_DKG_G1_LEN;
        let random_commitment_g2 =
            decode_g2_eip2537(&encoded[offset..offset + NEOX_DKG_G2_LEN], "PVSS G2 randomizer")?;
        offset += NEOX_DKG_G2_LEN;
        let mut public_shares = Vec::with_capacity(NEOX_DKG_PARTICIPANTS);
        for _ in 0..NEOX_DKG_PARTICIPANTS {
            public_shares.push(decode_g1_eip2537(
                &encoded[offset..offset + NEOX_DKG_G1_LEN],
                "public secret share",
            )?);
            offset += NEOX_DKG_G1_LEN;
        }
        debug_assert_eq!(offset, encoded.len());

        let pvss = Self {
            commitments: commitments
                .try_into()
                .expect("fixed DKG threshold determines commitment count"),
            random_commitment_g1,
            random_commitment_g2,
            public_shares: public_shares
                .try_into()
                .expect("fixed DKG committee determines public-share count"),
        };
        pvss.verify()?;
        Ok(pvss)
    }

    /// Returns the canonical EIP-2537 polynomial commitment.
    pub fn commitment(&self) -> [u8; NEOX_DKG_COMMITMENT_LEN] {
        let mut encoded = [0_u8; NEOX_DKG_COMMITMENT_LEN];
        for (index, commitment) in self.commitments.iter().enumerate() {
            let start = index * NEOX_DKG_G1_LEN;
            encoded[start..start + NEOX_DKG_G1_LEN]
                .copy_from_slice(&encode_g1(&projective_g1(commitment)));
        }
        encoded
    }

    /// Checks whether two PVSS values share the same constant polynomial coefficient.
    pub fn renovates(&self, previous: &Self) -> bool {
        // SAFETY: both points were subgroup-checked during decoding.
        unsafe {
            blst_p1_affine_is_equal(
                &raw const self.commitments[0],
                &raw const previous.commitments[0],
            )
        }
    }

    /// Verifies one decrypted scalar against the PVSS entry for a one-based validator index.
    pub fn verify_share(
        &self,
        index: u64,
        share: &DkgSecretScalar,
    ) -> Result<(), DkgMaterialError> {
        if !(1..=NEOX_DKG_PARTICIPANTS as u64).contains(&index) {
            return Err(DkgMaterialError::InvalidParticipantIndex(index))
        }
        let expected = affine_g1(&multiply_g1_generator(share));
        // SAFETY: both operands are initialized subgroup points.
        if unsafe {
            blst_p1_affine_is_equal(
                &raw const expected,
                &raw const self.public_shares[index as usize - 1],
            )
        } {
            Ok(())
        } else {
            Err(DkgMaterialError::InvalidDecryptedShare { index })
        }
    }

    fn verify(&self) -> Result<(), DkgMaterialError> {
        // Geth encodes the second randomizer with a negative sign, so the pairing product is one.
        // SAFETY: BLST returns process-lifetime pointers to immutable group generators.
        let (g1, g2) = unsafe { (*blst_p1_affine_generator(), *blst_p2_affine_generator()) };
        let product = blst_fp12::miller_loop_n(
            &[g2, self.random_commitment_g2],
            &[self.random_commitment_g1, g1],
        )
        .final_exp();
        if product != blst_fp12::default() {
            return Err(DkgMaterialError::InvalidPvssRandomizer)
        }

        for (position, actual) in self.public_shares.iter().enumerate() {
            let expected =
                affine_g1(&evaluate_public_polynomial(&self.commitments, (position + 1) as u64));
            // SAFETY: all points were decoded and subgroup-checked above.
            if !unsafe { blst_p1_affine_is_equal(&raw const expected, actual) } {
                return Err(DkgMaterialError::InvalidPvssPublicShare {
                    index: (position + 1) as u64,
                })
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DkgPvss {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgPvss { verified: true }")
    }
}

/// Decrypts one exact Neo X DKG ECIES message into a canonical BLS12-381 share scalar.
pub fn decrypt_dkg_share_message(
    message_private_key: &[u8; 32],
    message: &[u8],
) -> Result<DkgSecretScalar, DkgMaterialError> {
    if message.len() != NEOX_DKG_ECIES_MESSAGE_LEN {
        return Err(DkgMaterialError::WrongEciesMessageLength { actual: message.len() })
    }
    let private_key = SecretKey::from_slice(message_private_key)
        .map_err(|_| DkgMaterialError::InvalidMessagePrivateKey)?;

    // gnark-crypto's `RawBytes` omits SEC1's uncompressed-point tag.
    let mut encoded_point = [0_u8; NEOX_DKG_ECIES_POINT_LEN + 1];
    encoded_point[0] = 4;
    encoded_point[1..].copy_from_slice(&message[..NEOX_DKG_ECIES_POINT_LEN]);
    let ephemeral = PublicKey::from_sec1_bytes(&encoded_point)
        .map_err(|_| DkgMaterialError::InvalidEciesEphemeralPoint)?;
    let shared =
        ProjectivePoint::from(*ephemeral.as_affine()) * private_key.to_nonzero_scalar().as_ref();
    let shared = shared.to_affine().to_encoded_point(false);
    let shared_x = shared.x().ok_or(DkgMaterialError::InvalidEciesEphemeralPoint)?;

    let mut hasher = Sha3_256::new();
    hasher.update(shared_x);
    hasher.update(&message[..NEOX_DKG_ECIES_POINT_LEN]);
    let mut key = hasher.finalize();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("SHA3-256 is an AES-256 key");
    key.zeroize();
    let nonce = Nonce::from_slice(
        &message[NEOX_DKG_ECIES_POINT_LEN..NEOX_DKG_ECIES_POINT_LEN + NEOX_DKG_ECIES_NONCE_LEN],
    );
    let mut plaintext = cipher
        .decrypt(nonce, &message[NEOX_DKG_ECIES_POINT_LEN + NEOX_DKG_ECIES_NONCE_LEN..])
        .map_err(|_| DkgMaterialError::EciesAuthentication)?;
    if plaintext.len() != 32 {
        let actual = plaintext.len();
        plaintext.zeroize();
        return Err(DkgMaterialError::InvalidEciesPlaintextLength { actual })
    }
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(&plaintext);
    plaintext.zeroize();
    DkgSecretScalar::new(scalar)
}

fn predictable_scalar(
    private_source: &[u8],
    public_source: &[u8],
    round: u8,
    index: u8,
) -> DkgSecretScalar {
    let modulus = U256::from_be_bytes(BLS12_381_SCALAR_MODULUS);
    let mut zero_suffix = 0_usize;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(private_source);
        hasher.update(public_source);
        hasher.update([round, index]);
        for _ in 0..zero_suffix {
            hasher.update([0]);
        }
        let candidate = U256::from_be_bytes(hasher.finalize().into());
        // This matches Geth's `Cmp(max) > 0`; equality is rejected below instead of producing an
        // invalid scalar, an event with probability approximately 2^-256.
        let candidate = if candidate > modulus { candidate % modulus } else { candidate };
        if let Ok(candidate) = DkgSecretScalar::new(candidate.to_be_bytes()) {
            return candidate
        }
        zero_suffix += 1;
    }
}

fn evaluate_polynomial(
    coefficients: &[DkgSecretScalar; NEOX_DKG_THRESHOLD],
    index: u64,
) -> blst_fr {
    let x = fr_from_u64(index);
    let mut result =
        fr_from_secret(coefficients.last().expect("fixed nonempty DKG coefficient array"));
    for coefficient in coefficients[..coefficients.len() - 1].iter().rev() {
        result = fr_add(&fr_mul(&result, &x), &fr_from_secret(coefficient));
    }
    result
}

fn fr_from_secret(secret: &DkgSecretScalar) -> blst_fr {
    let mut scalar = blst_scalar::default();
    let mut result = blst_fr::default();
    // SAFETY: the source is exactly 32 big-endian bytes, and both outputs have the storage
    // required by BLST.
    unsafe {
        blst_scalar_from_bendian(&raw mut scalar, secret.0.as_ptr());
        blst_fr_from_scalar(&raw mut result, &raw const scalar);
    }
    result
}

fn secret_from_fr(value: &blst_fr) -> DkgSecretScalar {
    try_secret_from_fr(value).expect("nonzero DKG evaluation remains a canonical scalar")
}

fn try_secret_from_fr(value: &blst_fr) -> Result<DkgSecretScalar, DkgMaterialError> {
    let mut scalar = blst_scalar::default();
    let mut encoded = [0_u8; 32];
    // SAFETY: `value` is initialized, `scalar` has sufficient storage, and the output buffer is
    // exactly BLST's scalar encoding length.
    unsafe {
        blst_scalar_from_fr(&raw mut scalar, value);
        blst_bendian_from_scalar(encoded.as_mut_ptr(), &raw const scalar);
    }
    DkgSecretScalar::new(encoded)
}

fn fr_from_u64(value: u64) -> blst_fr {
    let limbs = [value, 0, 0, 0];
    let mut result = blst_fr::default();
    // SAFETY: BLST expects four little-endian u64 limbs and `limbs` has exactly that shape.
    unsafe { blst_fr_from_uint64(&raw mut result, limbs.as_ptr()) };
    result
}

fn fr_add(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_add(&raw mut result, left, right) };
    result
}

fn fr_mul(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_mul(&raw mut result, left, right) };
    result
}

fn fr_sub(left: &blst_fr, right: &blst_fr) -> blst_fr {
    let mut result = blst_fr::default();
    // SAFETY: both inputs and the distinct output are initialized field elements.
    unsafe { blst_fr_sub(&raw mut result, left, right) };
    result
}

fn evaluate_public_polynomial(
    commitments: &[blst_p1_affine; NEOX_DKG_THRESHOLD],
    index: u64,
) -> blst_p1 {
    let x = fr_from_u64(index);
    let mut result =
        projective_g1(commitments.last().expect("fixed nonempty DKG public commitment array"));
    for commitment in commitments[..commitments.len() - 1].iter().rev() {
        result = multiply_g1_by_fr(&result, &x);
        result = add_g1(&result, &projective_g1(commitment));
    }
    result
}

fn scalar_from_secret(secret: &DkgSecretScalar) -> blst_scalar {
    let mut scalar = blst_scalar::default();
    // SAFETY: the source is exactly BLST's 32-byte big-endian scalar representation.
    unsafe { blst_scalar_from_bendian(&raw mut scalar, secret.0.as_ptr()) };
    scalar
}

fn multiply_g1_generator(secret: &DkgSecretScalar) -> blst_p1 {
    let scalar = scalar_from_secret(secret);
    let mut result = blst_p1::default();
    // SAFETY: the generator and scalar pointers are valid, the scalar is at most 255 bits, and
    // `result` has the required projective-point storage.
    unsafe { blst_p1_mult(&raw mut result, blst_p1_generator(), scalar.b.as_ptr(), 255) };
    result
}

fn multiply_g2_generator(secret: &DkgSecretScalar) -> blst_p2 {
    let scalar = scalar_from_secret(secret);
    let mut result = blst_p2::default();
    // SAFETY: the generator and scalar pointers are valid, the scalar is at most 255 bits, and
    // `result` has the required projective-point storage.
    unsafe { blst_p2_mult(&raw mut result, blst_p2_generator(), scalar.b.as_ptr(), 255) };
    result
}

fn projective_g1(point: &blst_p1_affine) -> blst_p1 {
    let mut result = blst_p1::default();
    // SAFETY: the input is initialized and the output has sufficient projective-point storage.
    unsafe { blst_p1_from_affine(&raw mut result, point) };
    result
}

fn affine_g1(point: &blst_p1) -> blst_p1_affine {
    let mut result = blst_p1_affine::default();
    // SAFETY: the input is initialized and the output has sufficient affine-point storage.
    unsafe { blst_p1_to_affine(&raw mut result, point) };
    result
}

fn multiply_g1_by_fr(point: &blst_p1, scalar: &blst_fr) -> blst_p1 {
    let mut scalar_bytes = blst_scalar::default();
    let mut result = blst_p1::default();
    // SAFETY: the field element is initialized and the scalar output has the required storage.
    unsafe { blst_scalar_from_fr(&raw mut scalar_bytes, scalar) };
    // SAFETY: the point and scalar are initialized, and the output is distinct from the input.
    unsafe { blst_p1_mult(&raw mut result, point, scalar_bytes.b.as_ptr(), 255) };
    result
}

fn add_g1(left: &blst_p1, right: &blst_p1) -> blst_p1 {
    let mut result = blst_p1::default();
    // SAFETY: both inputs are initialized and the output is distinct from them.
    unsafe { blst_p1_add_or_double(&raw mut result, left, right) };
    result
}

fn encode_g1(point: &blst_p1) -> [u8; NEOX_DKG_G1_LEN] {
    let mut raw = [0_u8; 96];
    // SAFETY: BLST writes exactly 96 bytes for an initialized G1 point.
    unsafe { blst_p1_serialize(raw.as_mut_ptr(), point) };
    let mut encoded = [0_u8; NEOX_DKG_G1_LEN];
    encoded[16..64].copy_from_slice(&raw[..48]);
    encoded[80..128].copy_from_slice(&raw[48..]);
    encoded
}

fn encode_g2(point: &blst_p2) -> [u8; NEOX_DKG_G2_LEN] {
    let mut raw = [0_u8; 192];
    // SAFETY: BLST writes exactly 192 bytes for an initialized G2 point.
    unsafe { blst_p2_serialize(raw.as_mut_ptr(), point) };
    let mut encoded = [0_u8; NEOX_DKG_G2_LEN];
    // BLST serializes Fp2 as A1,A0 while gnark's EIP-2537 helper writes A0,A1.
    encoded[16..64].copy_from_slice(&raw[48..96]);
    encoded[80..128].copy_from_slice(&raw[..48]);
    encoded[144..192].copy_from_slice(&raw[144..192]);
    encoded[208..256].copy_from_slice(&raw[96..144]);
    encoded
}

fn decode_g1_eip2537(
    encoded: &[u8],
    field: &'static str,
) -> Result<blst_p1_affine, DkgMaterialError> {
    if encoded.len() != NEOX_DKG_G1_LEN {
        return Err(DkgMaterialError::InvalidPvssPointLength { field, actual: encoded.len() })
    }
    if encoded[..16].iter().any(|byte| *byte != 0) || encoded[64..80].iter().any(|byte| *byte != 0)
    {
        return Err(DkgMaterialError::InvalidPvssPadding { field })
    }
    let mut raw = [0_u8; 96];
    raw[..48].copy_from_slice(&encoded[16..64]);
    raw[48..].copy_from_slice(&encoded[80..128]);
    let mut point = blst_p1_affine::default();
    // SAFETY: `raw` is BLST's exact uncompressed G1 length and output storage is valid.
    let status = unsafe { blst_p1_deserialize(&raw mut point, raw.as_ptr()) };
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    if status != BLST_ERROR::BLST_SUCCESS ||
        !unsafe { blst_p1_affine_in_g1(&raw const point) } ||
        unsafe { blst_p1_affine_is_inf(&raw const point) }
    {
        return Err(DkgMaterialError::InvalidPvssG1Point { field })
    }
    Ok(point)
}

fn decode_g2_eip2537(
    encoded: &[u8],
    field: &'static str,
) -> Result<blst_p2_affine, DkgMaterialError> {
    if encoded.len() != NEOX_DKG_G2_LEN {
        return Err(DkgMaterialError::InvalidPvssPointLength { field, actual: encoded.len() })
    }
    if [0, 64, 128, 192]
        .into_iter()
        .any(|start| encoded[start..start + 16].iter().any(|byte| *byte != 0))
    {
        return Err(DkgMaterialError::InvalidPvssPadding { field })
    }
    let mut raw = [0_u8; 192];
    // BLST uses A1,A0 for each Fp2 coordinate, while EIP-2537 uses A0,A1.
    raw[..48].copy_from_slice(&encoded[80..128]);
    raw[48..96].copy_from_slice(&encoded[16..64]);
    raw[96..144].copy_from_slice(&encoded[208..256]);
    raw[144..].copy_from_slice(&encoded[144..192]);
    let mut point = blst_p2_affine::default();
    // SAFETY: `raw` is BLST's exact uncompressed G2 length and output storage is valid.
    let status = unsafe { blst_p2_deserialize(&raw mut point, raw.as_ptr()) };
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    if status != BLST_ERROR::BLST_SUCCESS ||
        !unsafe { blst_p2_affine_in_g2(&raw const point) } ||
        unsafe { blst_p2_affine_is_inf(&raw const point) }
    {
        return Err(DkgMaterialError::InvalidPvssG2Point { field })
    }
    Ok(point)
}

/// Failure to derive or generate private DKG material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgMaterialError {
    /// Scalars are canonical nonzero elements and are never reduced implicitly at an API boundary.
    #[error("invalid canonical Neo X DKG scalar")]
    InvalidScalar,
    /// Aggregating no shares cannot produce a local threshold key.
    #[error("cannot aggregate an empty Neo X DKG share set")]
    EmptyScalarAggregation,
    /// Deterministic sharing requires a private message-encryption source.
    #[error("Neo X DKG deterministic sharing requires a private source")]
    EmptyPrivateSource,
    /// Chain ID prevents deterministic shares from being replayed across networks.
    #[error("Neo X DKG deterministic sharing requires a nonzero chain ID")]
    EmptyReplayProtection,
    /// Validator positions are one-based within the fixed seven-member group.
    #[error("invalid Neo X DKG participant index {0}")]
    InvalidParticipantIndex(u64),
    /// Five indexed shares are required to reconstruct the constant term.
    #[error(
        "insufficient Neo X DKG recovery shares: got {actual}, expected at least {NEOX_DKG_THRESHOLD}"
    )]
    InsufficientRecoveryShares {
        /// Number of usable shares supplied.
        actual: usize,
    },
    /// Lagrange interpolation requires distinct x coordinates.
    #[error("duplicate Neo X DKG recovery share index {0}")]
    DuplicateRecoveryShareIndex(u64),
    /// Contract PVSS data has one exact deployed encoding length.
    #[error("invalid Neo X DKG PVSS length {actual}, expected {NEOX_DKG_GENERATED_PVSS_LEN}")]
    WrongPvssLength {
        /// Observed byte length.
        actual: usize,
    },
    /// Internal point decoders reject slices with a shape other than the selected curve group.
    #[error("invalid Neo X DKG {field} byte length {actual}")]
    InvalidPvssPointLength {
        /// Point role inside the PVSS.
        field: &'static str,
        /// Observed byte length.
        actual: usize,
    },
    /// EIP-2537 requires the high 16 bytes of each field element to be zero.
    #[error("invalid EIP-2537 padding in Neo X DKG {field}")]
    InvalidPvssPadding {
        /// Point role inside the PVSS.
        field: &'static str,
    },
    /// A G1 point failed canonical decoding, subgroup validation, or the non-infinity check.
    #[error("invalid G1 point in Neo X DKG {field}")]
    InvalidPvssG1Point {
        /// Point role inside the PVSS.
        field: &'static str,
    },
    /// A G2 point failed canonical decoding, subgroup validation, or the non-infinity check.
    #[error("invalid G2 point in Neo X DKG {field}")]
    InvalidPvssG2Point {
        /// Point role inside the PVSS.
        field: &'static str,
    },
    /// The two PVSS randomizer commitments do not contain the same scalar.
    #[error("Neo X DKG PVSS randomizer pairing verification failed")]
    InvalidPvssRandomizer,
    /// One advertised public share does not evaluate from the polynomial commitment.
    #[error("Neo X DKG PVSS public share {index} does not match its commitment")]
    InvalidPvssPublicShare {
        /// One-based validator position.
        index: u64,
    },
    /// One decrypted share does not match its advertised public share.
    #[error("decrypted Neo X DKG share {index} does not match its PVSS")]
    InvalidDecryptedShare {
        /// One-based validator position.
        index: u64,
    },
    /// DKG ECIES messages have a fixed point, nonce, ciphertext, and tag layout.
    #[error(
        "invalid Neo X DKG ECIES message length {actual}, expected {NEOX_DKG_ECIES_MESSAGE_LEN}"
    )]
    WrongEciesMessageLength {
        /// Observed byte length.
        actual: usize,
    },
    /// The message decryption key must be a canonical nonzero secp256k1 scalar.
    #[error("invalid Neo X DKG message private key")]
    InvalidMessagePrivateKey,
    /// The ECIES ephemeral point must be a canonical secp256k1 point.
    #[error("invalid Neo X DKG ECIES ephemeral point")]
    InvalidEciesEphemeralPoint,
    /// AES-GCM rejected a modified or incorrectly addressed share message.
    #[error("Neo X DKG ECIES authentication failed")]
    EciesAuthentication,
    /// ECIES share plaintexts are exact 32-byte scalar encodings.
    #[error("invalid Neo X DKG ECIES plaintext length {actual}, expected 32")]
    InvalidEciesPlaintextLength {
        /// Observed plaintext length.
        actual: usize,
    },
    /// OS entropy failed while generating a polynomial or PVSS randomizer.
    #[error("failed to obtain Neo X DKG entropy: {0}")]
    Entropy(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_hex(value: &DkgSecretScalar) -> String {
        hex::encode(value.as_bytes())
    }

    #[test]
    fn deterministic_polynomial_matches_geth() {
        let mut private_key = [0_u8; 32];
        private_key[31] = 1;
        let polynomial =
            DkgPolynomial::deterministic(&private_key, U256::from(47_763), 18).unwrap();
        let expected = [
            "4fce72a0fb0b1cf973721db7edab84cf0421414ee72dd6de34a00b3104075fa6",
            "2d703b8352d4d1482ec909ed8d16864a7238f7cf78b27bc3d00b88409b2161e9",
            "6b4f074d98f0069d20c730a3bbbf927518726be8ac090fc59a77a110e6223bf3",
            "3989497d5bd6bb42cc2c44420ce3f92a67210dff343ab507d4c13e257a5a674e",
            "06e678b2b87f77a53eaca19788dd85411568c2bdff2024ddc081dbc0c9387a49",
        ];
        assert_eq!(polynomial.coefficients.each_ref().map(scalar_hex), expected);
    }

    #[test]
    fn pvss_and_evaluations_match_geth() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material = polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7));
        assert_eq!(material.encoded().len(), NEOX_DKG_GENERATED_PVSS_LEN);
        assert_eq!(
            hex::encode(Sha256::digest(material.encoded())),
            "18688c4b40c5fda47ff76a70f6fb16b0e6b2dc4e161e3656a82a90bebe039fcb"
        );
        let expected = [15_u64, 129, 547, 1593, 3711, 7465, 13_539];
        for (share, expected) in material.shares().iter().zip(expected) {
            assert_eq!(U256::from_be_bytes(*share.as_bytes()), U256::from(expected));
        }
    }

    #[test]
    fn decodes_and_verifies_geth_pvss() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material = polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7));
        let pvss = DkgPvss::decode(material.encoded()).unwrap();
        assert_eq!(pvss.commitment(), material.encoded()[..NEOX_DKG_COMMITMENT_LEN]);
        for (position, share) in material.shares().iter().enumerate() {
            pvss.verify_share((position + 1) as u64, share).unwrap();
        }
        assert_eq!(format!("{pvss:?}"), "DkgPvss { verified: true }");
    }

    #[test]
    fn rejects_inconsistent_pvss_randomizers_and_public_shares() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material = polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7));

        let mut bad_randomizer = material.encoded().to_vec();
        bad_randomizer[NEOX_DKG_COMMITMENT_LEN..NEOX_DKG_COMMITMENT_LEN + NEOX_DKG_G1_LEN]
            .copy_from_slice(&material.encoded()[..NEOX_DKG_G1_LEN]);
        assert_eq!(
            DkgPvss::decode(&bad_randomizer).unwrap_err(),
            DkgMaterialError::InvalidPvssRandomizer
        );

        let public_shares_start = NEOX_DKG_COMMITMENT_LEN + NEOX_DKG_G1_LEN + NEOX_DKG_G2_LEN;
        let second_share: [u8; NEOX_DKG_G1_LEN] = material.encoded()
            [public_shares_start + NEOX_DKG_G1_LEN..public_shares_start + 2 * NEOX_DKG_G1_LEN]
            .try_into()
            .unwrap();
        let mut bad_share = material.encoded().to_vec();
        bad_share[public_shares_start..public_shares_start + NEOX_DKG_G1_LEN]
            .copy_from_slice(&second_share);
        assert_eq!(
            DkgPvss::decode(&bad_share).unwrap_err(),
            DkgMaterialError::InvalidPvssPublicShare { index: 1 }
        );
    }

    #[test]
    fn decrypts_fixed_zk_dkg_ecies_vector() {
        let private_key = hex!("0000000000000000000000000000000000000000000000000000000000000003");
        // Independently generated with gnark-crypto secp256k1, r=2, nonce=000102...0b,
        // and the plaintext scalar 15 using zk-dkg v0.3.0's SHA3-256/AES-256-GCM layout.
        let message = hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a000102030405060708090a0b8c55d6075aba82953e780f6f046333958a667dd7af4fdb741abac3cb3a074bb1a8174b0be3e5438225334c07a93cfcf7");
        let share = decrypt_dkg_share_message(&private_key, &message).unwrap();
        assert_eq!(share, DkgSecretScalar::from_u64(15));

        let mut tampered = message;
        tampered[NEOX_DKG_ECIES_MESSAGE_LEN - 1] ^= 1;
        assert_eq!(
            decrypt_dkg_share_message(&private_key, &tampered),
            Err(DkgMaterialError::EciesAuthentication)
        );
    }

    #[test]
    fn rejects_invalid_sources_indices_and_scalars() {
        assert_eq!(DkgSecretScalar::new([0_u8; 32]), Err(DkgMaterialError::InvalidScalar));
        assert_eq!(
            DkgSecretScalar::new(BLS12_381_SCALAR_MODULUS),
            Err(DkgMaterialError::InvalidScalar)
        );
        assert_eq!(
            DkgPolynomial::deterministic(&[0_u8; 32], U256::from(1), 1),
            Err(DkgMaterialError::EmptyPrivateSource)
        );
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        assert_eq!(polynomial.evaluate(0), Err(DkgMaterialError::InvalidParticipantIndex(0)));
        assert_eq!(polynomial.evaluate(8), Err(DkgMaterialError::InvalidParticipantIndex(8)));
        assert_eq!(
            decrypt_dkg_share_message(&[0_u8; 32], &[0_u8; NEOX_DKG_ECIES_MESSAGE_LEN]),
            Err(DkgMaterialError::InvalidMessagePrivateKey)
        );
        assert_eq!(
            decrypt_dkg_share_message(&[1_u8; 32], &[0_u8; 1]),
            Err(DkgMaterialError::WrongEciesMessageLength { actual: 1 })
        );
    }

    #[test]
    fn renovation_preserves_only_the_global_secret() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let renovated = polynomial.renovate().unwrap();
        assert_eq!(renovated.coefficients[0], polynomial.coefficients[0]);
        assert!(renovated.coefficients[1..]
            .iter()
            .zip(&polynomial.coefficients[1..])
            .any(|(left, right)| left != right));
        assert_eq!(format!("{renovated:?}"), "DkgPolynomial([REDACTED])");
    }
}
