//! Neo X 5-of-7 DKG polynomial and PVSS generation.

use alloc::vec::Vec;
use alloy_primitives::{hex, U256};
use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_from_uint64,
    blst_fr_mul, blst_p1, blst_p1_generator, blst_p1_mult, blst_p1_serialize, blst_p2,
    blst_p2_cneg, blst_p2_generator, blst_p2_mult, blst_p2_serialize, blst_scalar,
    blst_scalar_from_bendian, blst_scalar_from_fr,
};
use core::fmt;
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};
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
/// Exact PVSS length accepted by `KeyManagement`.
pub const NEOX_DKG_GENERATED_PVSS_LEN: usize =
    (NEOX_DKG_THRESHOLD + NEOX_DKG_PARTICIPANTS + 1) * NEOX_DKG_G1_LEN + NEOX_DKG_G2_LEN;

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
#[derive(Clone, PartialEq, Eq)]
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
    let mut scalar = blst_scalar::default();
    let mut encoded = [0_u8; 32];
    // SAFETY: `value` is initialized, `scalar` has sufficient storage, and the output buffer is
    // exactly BLST's scalar encoding length.
    unsafe {
        blst_scalar_from_fr(&raw mut scalar, value);
        blst_bendian_from_scalar(encoded.as_mut_ptr(), &raw const scalar);
    }
    DkgSecretScalar::new(encoded).expect("nonzero DKG evaluation remains a canonical scalar")
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

/// Failure to derive or generate private DKG material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgMaterialError {
    /// Scalars are canonical nonzero elements and are never reduced implicitly at an API boundary.
    #[error("invalid canonical Neo X DKG scalar")]
    InvalidScalar,
    /// Deterministic sharing requires a private message-encryption source.
    #[error("Neo X DKG deterministic sharing requires a private source")]
    EmptyPrivateSource,
    /// Chain ID prevents deterministic shares from being replayed across networks.
    #[error("Neo X DKG deterministic sharing requires a nonzero chain ID")]
    EmptyReplayProtection,
    /// Validator positions are one-based within the fixed seven-member group.
    #[error("invalid Neo X DKG participant index {0}")]
    InvalidParticipantIndex(u64),
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
