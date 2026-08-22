//! Neo X DKG polynomial and PVSS generation.

use crate::{
    field::{add as fr_add, from_u64 as fr_from_u64, multiply as fr_mul, subtract as fr_sub},
    NEOX_DKG_SCALER,
};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use alloc::vec::Vec;
use alloy_primitives::{hex, U256};
use blst::{
    blst_bendian_from_scalar, blst_fp12, blst_fr, blst_fr_cneg, blst_fr_from_scalar,
    blst_fr_inverse, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_generator,
    blst_p1_affine_in_g1, blst_p1_affine_is_equal, blst_p1_affine_is_inf, blst_p1_deserialize,
    blst_p1_from_affine, blst_p1_generator, blst_p1_mult, blst_p1_serialize, blst_p1_to_affine,
    blst_p2, blst_p2_affine, blst_p2_affine_generator, blst_p2_affine_in_g2, blst_p2_affine_is_inf,
    blst_p2_cneg, blst_p2_deserialize, blst_p2_generator, blst_p2_mult, blst_p2_serialize,
    blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr, BLST_ERROR,
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

/// Runtime DKG dimensions used by Neo X Geth.
///
/// Geth does not encode `7` and `5` in the protocol.  `antimev init` accepts a committee size and
/// derives the Byzantine threshold as `n - floor((n - 1) / 3)`.  The interpolation scaler is part
/// of the persisted keystore and must be shared by every node in the group.  The canonical public
/// network happens to use the seven-member values exposed by the legacy constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgParameters {
    participants: usize,
    threshold: usize,
    scaler: u64,
}

impl DkgParameters {
    /// Constructs the Geth parameters for a committee of `participants` members.
    pub fn new(participants: usize) -> Result<Self, DkgMaterialError> {
        if participants == 0 || participants > 256 {
            return Err(DkgMaterialError::InvalidParameters { participants, threshold: 0 });
        }
        // This is the same formula used by `cmd/geth/antimevcmd.go`.
        let threshold = participants - participants.saturating_sub(1) / 3;
        let scaler = dkg_interpolation_scaler(participants, threshold)?;
        Ok(Self { participants, threshold, scaler })
    }

    /// Returns the canonical Neo X seven-member parameters.
    pub const fn canonical() -> Self {
        Self {
            participants: NEOX_DKG_PARTICIPANTS,
            threshold: NEOX_DKG_THRESHOLD,
            scaler: NEOX_DKG_SCALER,
        }
    }

    /// Number of DKG participants.
    pub const fn participants(self) -> usize {
        self.participants
    }

    /// Number of shares required to reconstruct the threshold key.
    pub const fn threshold(self) -> usize {
        self.threshold
    }

    /// Common integer scaler used by Geth's Lagrange interpolation.
    pub const fn scaler(self) -> u64 {
        self.scaler
    }

    /// Returns the EIP-2537 byte length of one Geth PVSS value.
    pub const fn pvss_len(self) -> usize {
        (self.threshold + self.participants + 1) * NEOX_DKG_G1_LEN + NEOX_DKG_G2_LEN
    }

    /// Returns the EIP-2537 byte length of the polynomial commitment prefix.
    pub const fn commitment_len(self) -> usize {
        self.threshold * NEOX_DKG_G1_LEN
    }
}

/// Computes Geth's least common interpolation denominator.
///
/// Geth currently persists the scaler as a machine-sized integer.  Rust mirrors that wire format
/// and fails closed if a committee is so large that the exact scaler cannot be represented by a
/// `u64`; realistic Neo X committees (including all published private fixtures) are well below
/// that bound.
fn dkg_interpolation_scaler(
    participants: usize,
    threshold: usize,
) -> Result<u64, DkgMaterialError> {
    if threshold == 0 || threshold > participants {
        return Err(DkgMaterialError::InvalidParameters { participants, threshold });
    }
    // Enumerating every subset is exactly what the reference implementation does.  Avoid a
    // pathological allocation/CPU spike for malformed custom genesis files before recursion.
    if participants > 16 {
        return Err(DkgMaterialError::ScalerOverflow { participants, threshold });
    }

    const fn gcd(mut left: u128, mut right: u128) -> u128 {
        while right != 0 {
            let remainder = left % right;
            left = right;
            right = remainder;
        }
        left
    }

    fn visit(
        next: usize,
        participants: usize,
        threshold: usize,
        selected: &mut Vec<usize>,
        scaler: &mut u128,
    ) -> Result<(), DkgMaterialError> {
        if selected.len() == threshold {
            for (position, index) in selected.iter().copied().enumerate() {
                let mut numerator = 1_i128;
                let mut denominator = 1_i128;
                for (other_position, other) in selected.iter().copied().enumerate() {
                    if position == other_position {
                        continue;
                    }
                    numerator = numerator
                        .checked_mul(-(other as i128))
                        .ok_or(DkgMaterialError::ScalerOverflow { participants, threshold })?;
                    denominator = denominator
                        .checked_mul(index as i128 - other as i128)
                        .ok_or(DkgMaterialError::ScalerOverflow { participants, threshold })?;
                }
                let numerator_abs = numerator.unsigned_abs();
                let denominator_abs = denominator.unsigned_abs();
                let divisor = gcd(numerator_abs, denominator_abs);
                let reduced_denominator = denominator_abs / divisor;
                let divisor = gcd(*scaler, reduced_denominator);
                *scaler = (*scaler / divisor)
                    .checked_mul(reduced_denominator)
                    .ok_or(DkgMaterialError::ScalerOverflow { participants, threshold })?;
            }
            return Ok(())
        }

        let remaining = threshold - selected.len();
        let last = participants - remaining + 1;
        for index in next..=last {
            selected.push(index);
            visit(index + 1, participants, threshold, selected, scaler)?;
            selected.pop();
        }
        Ok(())
    }

    let mut scaler = 1_u128;
    visit(1, participants, threshold, &mut Vec::with_capacity(threshold), &mut scaler)?;
    u64::try_from(scaler).map_err(|_| DkgMaterialError::ScalerOverflow { participants, threshold })
}

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
            return Err(DkgMaterialError::InvalidScalar);
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
            return Err(DkgMaterialError::EmptyScalarAggregation);
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
                return Ok(scalar);
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

/// Secret polynomial used by Neo X's parameterized sharing scheme.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DkgPolynomial {
    #[zeroize(skip)]
    parameters: DkgParameters,
    coefficients: Vec<DkgSecretScalar>,
}

impl DkgPolynomial {
    pub(crate) fn from_encoded_coefficients_with_parameters(
        coefficients: Vec<[u8; 32]>,
        parameters: DkgParameters,
    ) -> Result<Self, DkgMaterialError> {
        if coefficients.len() != parameters.threshold() {
            return Err(DkgMaterialError::InvalidParameters {
                participants: parameters.participants(),
                threshold: coefficients.len(),
            })
        }
        let coefficients =
            coefficients.into_iter().map(DkgSecretScalar::new).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { parameters, coefficients })
    }

    pub(crate) fn encoded_coefficients(&self) -> Vec<[u8; 32]> {
        self.coefficients.iter().map(|coefficient| *coefficient.as_bytes()).collect()
    }

    /// Returns the dimensions used by this polynomial.
    pub const fn parameters(&self) -> DkgParameters {
        self.parameters
    }

    /// Derives the canonical seven-member replay-protected polynomial used by Neo X Geth.
    pub fn deterministic(
        message_private_key: &[u8; 32],
        chain_id: U256,
        round: u64,
    ) -> Result<Self, DkgMaterialError> {
        Self::deterministic_with_parameters(
            message_private_key,
            chain_id,
            round,
            DkgParameters::canonical(),
        )
    }

    /// Derives a replay-protected polynomial for a Geth committee of any supported size.
    ///
    /// Geth intentionally truncates both the round and coefficient position to one byte.
    pub fn deterministic_with_parameters(
        message_private_key: &[u8; 32],
        chain_id: U256,
        round: u64,
        parameters: DkgParameters,
    ) -> Result<Self, DkgMaterialError> {
        if message_private_key.iter().all(|byte| *byte == 0) {
            return Err(DkgMaterialError::EmptyPrivateSource);
        }
        if chain_id.is_zero() {
            return Err(DkgMaterialError::EmptyReplayProtection);
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
        let coefficients = (0..parameters.threshold())
            .map(|index| {
                predictable_scalar(private_source, public_source, round as u8, index as u8)
            })
            .collect();
        Ok(Self { parameters, coefficients })
    }

    /// Re-randomizes all nonconstant terms while retaining the current global secret.
    pub fn renovate(&self) -> Result<Self, DkgMaterialError> {
        let mut coefficients = Vec::with_capacity(self.parameters.threshold());
        coefficients.push(self.coefficients[0].clone());
        for _ in 1..self.parameters.threshold() {
            coefficients.push(DkgSecretScalar::random()?);
        }
        Ok(Self { parameters: self.parameters, coefficients })
    }

    /// Generates fresh PVSS randomness and one private evaluation per participant.
    pub fn generate_pvss(&self) -> Result<DkgPvssMaterial, DkgMaterialError> {
        let randomizer = DkgSecretScalar::random()?;
        self.generate_pvss_with_randomizer(&randomizer)
    }

    /// Returns one canonical evaluation at a one-based validator index.
    pub fn evaluate(&self, index: u64) -> Result<DkgSecretScalar, DkgMaterialError> {
        if !(1..=self.parameters.participants() as u64).contains(&index) {
            return Err(DkgMaterialError::InvalidParticipantIndex(index));
        }
        try_secret_from_fr(&evaluate_polynomial(&self.coefficients, index))
    }

    /// Returns the exact EIP-2537 commitment for every polynomial coefficient.
    pub fn commitment(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.parameters.commitment_len());
        for coefficient in &self.coefficients {
            encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(coefficient)));
        }
        encoded
    }

    /// Interpolates a missing validator's constant term and renovates it.
    pub fn recover_and_renovate(
        shares: &[(u64, DkgSecretScalar)],
    ) -> Result<Self, DkgMaterialError> {
        Self::recover_and_renovate_with_parameters(shares, DkgParameters::canonical())
    }

    /// Interpolates a missing validator's constant term for the supplied committee dimensions.
    pub fn recover_and_renovate_with_parameters(
        shares: &[(u64, DkgSecretScalar)],
        parameters: DkgParameters,
    ) -> Result<Self, DkgMaterialError> {
        if shares.len() < parameters.threshold() {
            return Err(DkgMaterialError::InsufficientRecoveryShares { actual: shares.len() });
        }
        let selected = &shares[..parameters.threshold()];
        for (position, (index, _)) in selected.iter().enumerate() {
            if !(1..=parameters.participants() as u64).contains(index) {
                return Err(DkgMaterialError::InvalidParticipantIndex(*index));
            }
            if selected[..position].iter().any(|(previous, _)| previous == index) {
                return Err(DkgMaterialError::DuplicateRecoveryShareIndex(*index));
            }
        }

        let mut constant = fr_from_u64(0);
        for (position, (index, share)) in selected.iter().enumerate() {
            let x_i = fr_from_u64(*index);
            let mut numerator = fr_from_u64(1);
            let mut denominator = fr_from_u64(1);
            for (other_position, (other_index, _)) in selected.iter().enumerate() {
                if position == other_position {
                    continue;
                }
                let x = fr_from_u64(*other_index);
                let mut negative_x = blst_fr::default();
                // SAFETY: `x` is initialized and the output is distinct from the input.
                unsafe { blst_fr_cneg(&raw mut negative_x, &raw const x, true) };
                numerator = fr_mul(&numerator, &negative_x);
                denominator = fr_mul(&denominator, &fr_sub(&x_i, &x));
            }
            let mut denominator_inverse = blst_fr::default();
            // SAFETY: unique indices make the initialized denominator nonzero.
            unsafe { blst_fr_inverse(&raw mut denominator_inverse, &raw const denominator) };
            let coefficient = fr_mul(&numerator, &denominator_inverse);
            constant = fr_add(&constant, &fr_mul(&fr_from_secret(share), &coefficient));
        }

        let mut polynomial = Self::random_with_parameters(parameters)?;
        polynomial.coefficients[0] = try_secret_from_fr(&constant)?;
        Ok(polynomial)
    }

    fn random_with_parameters(parameters: DkgParameters) -> Result<Self, DkgMaterialError> {
        let mut coefficients = Vec::with_capacity(parameters.threshold());
        for _ in 0..parameters.threshold() {
            coefficients.push(DkgSecretScalar::random()?);
        }
        Ok(Self { parameters, coefficients })
    }

    fn generate_pvss_with_randomizer(
        &self,
        randomizer: &DkgSecretScalar,
    ) -> Result<DkgPvssMaterial, DkgMaterialError> {
        let mut encoded = Vec::with_capacity(self.parameters.pvss_len());
        for coefficient in &self.coefficients {
            encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(coefficient)));
        }

        encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(randomizer)));
        let mut r2 = multiply_g2_generator(randomizer);
        // Geth encodes `-rG2`, making `e(rG1,G2) * e(G1,-rG2) == 1`.
        // SAFETY: `r2` is an initialized projective point and is mutated in place.
        unsafe { blst_p2_cneg(&raw mut r2, true) };
        encoded.extend_from_slice(&encode_g2(&r2));

        let shares = (1..=self.parameters.participants() as u64)
            .map(|index| self.evaluate(index))
            .collect::<Result<Vec<_>, _>>()?;
        for share in &shares {
            encoded.extend_from_slice(&encode_g1(&multiply_g1_generator(share)));
        }
        debug_assert_eq!(encoded.len(), self.parameters.pvss_len());
        Ok(DkgPvssMaterial { parameters: self.parameters, encoded, shares })
    }

    #[cfg(test)]
    fn from_u64_coefficients(coefficients: [u64; NEOX_DKG_THRESHOLD]) -> Self {
        Self {
            parameters: DkgParameters::canonical(),
            coefficients: coefficients.map(DkgSecretScalar::from_u64).into_iter().collect(),
        }
    }
}

impl fmt::Debug for DkgPolynomial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgPolynomial([REDACTED])")
    }
}

/// Public PVSS bytes paired with the secret polynomial evaluations used by the prover.
pub struct DkgPvssMaterial {
    #[allow(dead_code)]
    parameters: DkgParameters,
    encoded: Vec<u8>,
    shares: Vec<DkgSecretScalar>,
}

impl DkgPvssMaterial {
    /// Returns the exact EIP-2537 contract encoding for this committee size.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns secret evaluations in one-based pending-validator order.
    pub fn shares(&self) -> &[DkgSecretScalar] {
        &self.shares
    }

    /// Returns the dimensions used to generate this material.
    pub const fn parameters(&self) -> DkgParameters {
        self.parameters
    }

    /// Separates the public contract bytes from the zeroizing secret evaluations.
    pub fn into_parts(self) -> (Vec<u8>, Vec<DkgSecretScalar>) {
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
    parameters: DkgParameters,
    commitments: Vec<blst_p1_affine>,
    random_commitment_g1: blst_p1_affine,
    random_commitment_g2: blst_p2_affine,
    public_shares: Vec<blst_p1_affine>,
}

impl DkgPvss {
    /// Decodes every EIP-2537 point and verifies the randomizer pairing and all polynomial shares.
    pub fn decode(encoded: &[u8]) -> Result<Self, DkgMaterialError> {
        Self::decode_with_parameters(encoded, DkgParameters::canonical())
    }

    /// Decodes a PVSS using Geth's runtime committee dimensions.
    pub fn decode_with_parameters(
        encoded: &[u8],
        parameters: DkgParameters,
    ) -> Result<Self, DkgMaterialError> {
        if encoded.len() != parameters.pvss_len() {
            return Err(DkgMaterialError::WrongPvssLength { actual: encoded.len() });
        }

        let mut offset = 0;
        let mut commitments = Vec::with_capacity(parameters.threshold());
        for index in 0..parameters.threshold() {
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
        let mut public_shares = Vec::with_capacity(parameters.participants());
        for _ in 0..parameters.participants() {
            public_shares.push(decode_g1_eip2537(
                &encoded[offset..offset + NEOX_DKG_G1_LEN],
                "public secret share",
            )?);
            offset += NEOX_DKG_G1_LEN;
        }
        debug_assert_eq!(offset, encoded.len());

        let pvss = Self {
            parameters,
            commitments,
            random_commitment_g1,
            random_commitment_g2,
            public_shares,
        };
        pvss.verify()?;
        Ok(pvss)
    }

    /// Returns the canonical EIP-2537 polynomial commitment.
    pub fn commitment(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.parameters.commitment_len());
        for (index, commitment) in self.commitments.iter().enumerate() {
            let start = index * NEOX_DKG_G1_LEN;
            debug_assert_eq!(start, encoded.len());
            encoded.extend_from_slice(&encode_g1(&projective_g1(commitment)));
        }
        encoded
    }

    /// Returns the dimensions encoded by this PVSS.
    pub const fn parameters(&self) -> DkgParameters {
        self.parameters
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
        if !(1..=self.parameters.participants() as u64).contains(&index) {
            return Err(DkgMaterialError::InvalidParticipantIndex(index));
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
            return Err(DkgMaterialError::InvalidPvssRandomizer);
        }

        for (position, actual) in self.public_shares.iter().enumerate() {
            let expected =
                affine_g1(&evaluate_public_polynomial(&self.commitments, (position + 1) as u64));
            // SAFETY: all points were decoded and subgroup-checked above.
            if !unsafe { blst_p1_affine_is_equal(&raw const expected, actual) } {
                return Err(DkgMaterialError::InvalidPvssPublicShare {
                    index: (position + 1) as u64,
                });
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

/// Verifies a settled local DKG scalar against all seven canonical PVSS contributions.
///
/// Each contribution advertises the public point for every one-based receiver position. Neo X
/// derives a receiver's final private share by adding the seven corresponding secret evaluations,
/// so its public key must equal the sum of those seven advertised points. No DKG scaler is applied
/// to this per-validator check.
pub fn verify_aggregated_dkg_share<B: AsRef<[u8]>>(
    index: u64,
    private_share: &[u8; 32],
    pvsses: &[B],
) -> Result<(), DkgMaterialError> {
    verify_aggregated_dkg_share_with_parameters(
        index,
        private_share,
        pvsses,
        DkgParameters::canonical(),
    )
}

/// Verifies a settled local DKG scalar for a parameterized committee.
pub fn verify_aggregated_dkg_share_with_parameters<B: AsRef<[u8]>>(
    index: u64,
    private_share: &[u8; 32],
    pvsses: &[B],
    parameters: DkgParameters,
) -> Result<(), DkgMaterialError> {
    if !(1..=parameters.participants() as u64).contains(&index) {
        return Err(DkgMaterialError::InvalidParticipantIndex(index));
    }
    if pvsses.len() != parameters.participants() {
        return Err(DkgMaterialError::InvalidPvssContributionCount { actual: pvsses.len() });
    }

    let private_share = DkgSecretScalar::new(*private_share)?;
    let mut aggregated = None;
    for encoded in pvsses {
        let pvss = DkgPvss::decode_with_parameters(encoded.as_ref(), parameters)?;
        let public_share = projective_g1(&pvss.public_shares[index as usize - 1]);
        aggregated = Some(match aggregated {
            Some(previous) => add_g1(&previous, &public_share),
            None => public_share,
        });
    }

    let expected = affine_g1(&aggregated.expect("fixed nonzero contribution count checked above"));
    let actual = affine_g1(&multiply_g1_generator(&private_share));
    // SAFETY: both points were constructed from subgroup-checked PVSS data or a canonical scalar.
    if unsafe { blst_p1_affine_is_equal(&raw const expected, &raw const actual) } {
        Ok(())
    } else {
        Err(DkgMaterialError::InvalidAggregatedShare { index })
    }
}

/// Verifies that a settled aggregate commitment is the sum of all seven canonical PVSS constant
/// coefficients.
///
/// `KeyManagement` retains the complete PVSS values after encrypted share-message arrays are no
/// longer available. This check binds the retained public material to the global commitment used
/// by threshold encryption without requiring those historical ciphertexts.
pub fn verify_aggregated_dkg_commitment<B: AsRef<[u8]>>(
    commitment: &[u8; NEOX_DKG_G1_LEN],
    pvsses: &[B],
) -> Result<(), DkgMaterialError> {
    verify_aggregated_dkg_commitment_with_parameters(commitment, pvsses, DkgParameters::canonical())
}

/// Verifies a settled aggregate commitment for a parameterized committee.
pub fn verify_aggregated_dkg_commitment_with_parameters<B: AsRef<[u8]>>(
    commitment: &[u8; NEOX_DKG_G1_LEN],
    pvsses: &[B],
    parameters: DkgParameters,
) -> Result<(), DkgMaterialError> {
    if pvsses.len() != parameters.participants() {
        return Err(DkgMaterialError::InvalidPvssContributionCount { actual: pvsses.len() });
    }

    let mut aggregated = None;
    for encoded in pvsses {
        let pvss = DkgPvss::decode_with_parameters(encoded.as_ref(), parameters)?;
        let constant = projective_g1(&pvss.commitments[0]);
        aggregated = Some(match aggregated {
            Some(previous) => add_g1(&previous, &constant),
            None => constant,
        });
    }
    let actual = encode_g1(&aggregated.expect("fixed nonzero contribution count checked above"));
    if &actual == commitment {
        Ok(())
    } else {
        Err(DkgMaterialError::InvalidAggregatedCommitment)
    }
}

/// Decrypts one exact Neo X DKG ECIES message into a canonical BLS12-381 share scalar.
pub fn decrypt_dkg_share_message(
    message_private_key: &[u8; 32],
    message: &[u8],
) -> Result<DkgSecretScalar, DkgMaterialError> {
    if message.len() != NEOX_DKG_ECIES_MESSAGE_LEN {
        return Err(DkgMaterialError::WrongEciesMessageLength { actual: message.len() });
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
        return Err(DkgMaterialError::InvalidEciesPlaintextLength { actual });
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
            return candidate;
        }
        zero_suffix += 1;
    }
}

fn evaluate_polynomial(coefficients: &[DkgSecretScalar], index: u64) -> blst_fr {
    let x = fr_from_u64(index);
    let mut result = fr_from_secret(coefficients.last().expect("nonempty DKG coefficient list"));
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

fn evaluate_public_polynomial(commitments: &[blst_p1_affine], index: u64) -> blst_p1 {
    let x = fr_from_u64(index);
    let mut result = projective_g1(commitments.last().expect("nonempty DKG commitment list"));
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
        return Err(DkgMaterialError::InvalidPvssPointLength { field, actual: encoded.len() });
    }
    if encoded[..16].iter().any(|byte| *byte != 0) || encoded[64..80].iter().any(|byte| *byte != 0)
    {
        return Err(DkgMaterialError::InvalidPvssPadding { field });
    }
    let mut raw = [0_u8; 96];
    raw[..48].copy_from_slice(&encoded[16..64]);
    raw[48..].copy_from_slice(&encoded[80..128]);
    let mut point = blst_p1_affine::default();
    // SAFETY: `raw` is BLST's exact uncompressed G1 length and output storage is valid.
    let status = unsafe { blst_p1_deserialize(&raw mut point, raw.as_ptr()) };
    if status != BLST_ERROR::BLST_SUCCESS {
        return Err(DkgMaterialError::InvalidPvssG1Point { field });
    }
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    let in_group = unsafe { blst_p1_affine_in_g1(&raw const point) };
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    let at_infinity = unsafe { blst_p1_affine_is_inf(&raw const point) };
    if !in_group || at_infinity {
        return Err(DkgMaterialError::InvalidPvssG1Point { field });
    }
    Ok(point)
}

fn decode_g2_eip2537(
    encoded: &[u8],
    field: &'static str,
) -> Result<blst_p2_affine, DkgMaterialError> {
    if encoded.len() != NEOX_DKG_G2_LEN {
        return Err(DkgMaterialError::InvalidPvssPointLength { field, actual: encoded.len() });
    }
    if [0, 64, 128, 192]
        .into_iter()
        .any(|start| encoded[start..start + 16].iter().any(|byte| *byte != 0))
    {
        return Err(DkgMaterialError::InvalidPvssPadding { field });
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
    if status != BLST_ERROR::BLST_SUCCESS {
        return Err(DkgMaterialError::InvalidPvssG2Point { field });
    }
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    let in_group = unsafe { blst_p2_affine_in_g2(&raw const point) };
    // SAFETY: BLST initialized `point` when deserialization succeeded.
    let at_infinity = unsafe { blst_p2_affine_is_inf(&raw const point) };
    if !in_group || at_infinity {
        return Err(DkgMaterialError::InvalidPvssG2Point { field });
    }
    Ok(point)
}

/// Failure to derive or generate private DKG material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgMaterialError {
    /// Committee dimensions do not describe a usable Geth threshold group.
    #[error("invalid Neo X DKG parameters: participants {participants}, threshold {threshold}")]
    InvalidParameters {
        /// Number of DKG participants supplied by the operator or chain.
        participants: usize,
        /// Requested reconstruction threshold.
        threshold: usize,
    },
    /// The exact interpolation scaler cannot be represented by the persisted `u64` field.
    #[error(
        "Neo X DKG interpolation scaler overflows for participants {participants}, threshold {threshold}"
    )]
    ScalerOverflow {
        /// Number of DKG participants.
        participants: usize,
        /// Reconstruction threshold.
        threshold: usize,
    },
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
    /// Successful fixed-size DKG rounds contain one accepted PVSS from every participant.
    #[error(
        "invalid Neo X DKG PVSS contribution count {actual}, expected {NEOX_DKG_PARTICIPANTS}"
    )]
    InvalidPvssContributionCount {
        /// Number of canonical contribution values supplied.
        actual: usize,
    },
    /// A local aggregate scalar must bind to the canonical public shares at its receiver position.
    #[error("Neo X DKG aggregate scalar does not match canonical public share {index}")]
    InvalidAggregatedShare {
        /// One-based validator position.
        index: u64,
    },
    /// The contract aggregate must equal the sum of every accepted PVSS constant coefficient.
    #[error("Neo X DKG aggregate commitment does not match canonical PVSS contributions")]
    InvalidAggregatedCommitment,
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
    fn derives_geth_committee_parameters() {
        let canonical = DkgParameters::new(7).unwrap();
        assert_eq!(canonical.threshold(), 5);
        assert_eq!(canonical.scaler(), 360);
        assert_eq!(canonical.pvss_len(), NEOX_DKG_GENERATED_PVSS_LEN);

        let four = DkgParameters::new(4).unwrap();
        assert_eq!(four.threshold(), 3);
        assert_eq!(four.scaler(), 3);
        assert_eq!(four.pvss_len(), (3 + 4 + 1) * NEOX_DKG_G1_LEN + NEOX_DKG_G2_LEN);

        let single = DkgParameters::new(1).unwrap();
        assert_eq!(single.threshold(), 1);
        assert_eq!(single.scaler(), 1);
    }

    #[test]
    fn deterministic_polynomial_matches_geth() {
        let mut private_key = [0_u8; 32];
        private_key[31] = 1;
        let polynomial =
            DkgPolynomial::deterministic(&private_key, U256::from(47_763), 18).unwrap();
        let expected = vec![
            "4fce72a0fb0b1cf973721db7edab84cf0421414ee72dd6de34a00b3104075fa6",
            "2d703b8352d4d1482ec909ed8d16864a7238f7cf78b27bc3d00b88409b2161e9",
            "6b4f074d98f0069d20c730a3bbbf927518726be8ac090fc59a77a110e6223bf3",
            "3989497d5bd6bb42cc2c44420ce3f92a67210dff343ab507d4c13e257a5a674e",
            "06e678b2b87f77a53eaca19788dd85411568c2bdff2024ddc081dbc0c9387a49",
        ];
        assert_eq!(polynomial.coefficients.iter().map(scalar_hex).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn pvss_and_evaluations_match_geth() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material =
            polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7)).unwrap();
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
    fn zero_polynomial_evaluation_is_a_typed_error() {
        let modulus = U256::from_be_bytes(BLS12_381_SCALAR_MODULUS);
        let cancelling = DkgSecretScalar::new((modulus - U256::from(4)).to_be_bytes()).unwrap();
        let polynomial = DkgPolynomial {
            parameters: DkgParameters::canonical(),
            coefficients: vec![
                DkgSecretScalar::from_u64(1),
                DkgSecretScalar::from_u64(1),
                DkgSecretScalar::from_u64(1),
                DkgSecretScalar::from_u64(1),
                cancelling,
            ],
        };

        assert_eq!(polynomial.evaluate(1), Err(DkgMaterialError::InvalidScalar));
        assert!(matches!(
            polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7)),
            Err(DkgMaterialError::InvalidScalar)
        ));
    }

    #[test]
    fn decodes_and_verifies_geth_pvss() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material =
            polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7)).unwrap();
        let pvss = DkgPvss::decode(material.encoded()).unwrap();
        assert_eq!(pvss.commitment(), material.encoded()[..NEOX_DKG_COMMITMENT_LEN].to_vec());
        for (position, share) in material.shares().iter().enumerate() {
            pvss.verify_share((position + 1) as u64, share).unwrap();
        }
        assert_eq!(format!("{pvss:?}"), "DkgPvss { verified: true }");
    }

    #[test]
    fn verifies_aggregate_scalar_against_all_public_shares() {
        let index = 3;
        let polynomials = (1..=NEOX_DKG_PARTICIPANTS as u64)
            .map(|constant| DkgPolynomial::from_u64_coefficients([constant, 2, 3, 4, 5]))
            .collect::<Vec<_>>();
        let materials = polynomials
            .iter()
            .enumerate()
            .map(|(position, polynomial)| {
                polynomial
                    .generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(position as u64 + 1))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let evaluations = polynomials
            .iter()
            .map(|polynomial| polynomial.evaluate(index).unwrap())
            .collect::<Vec<_>>();
        let evaluation_refs = evaluations.iter().collect::<Vec<_>>();
        let aggregate = DkgSecretScalar::aggregate(&evaluation_refs).unwrap();
        let pvsses = materials.iter().map(DkgPvssMaterial::encoded).collect::<Vec<_>>();

        verify_aggregated_dkg_share(index, aggregate.as_bytes(), &pvsses).unwrap();
        assert_eq!(
            verify_aggregated_dkg_share(index, DkgSecretScalar::from_u64(1).as_bytes(), &pvsses,),
            Err(DkgMaterialError::InvalidAggregatedShare { index })
        );
    }

    #[test]
    fn verifies_aggregate_commitment_against_all_pvss_constants() {
        let polynomials = (1..=NEOX_DKG_PARTICIPANTS as u64)
            .map(|constant| DkgPolynomial::from_u64_coefficients([constant, 2, 3, 4, 5]))
            .collect::<Vec<_>>();
        let materials = polynomials
            .iter()
            .enumerate()
            .map(|(position, polynomial)| {
                polynomial
                    .generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(position as u64 + 1))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let constants =
            (1..=NEOX_DKG_PARTICIPANTS as u64).map(DkgSecretScalar::from_u64).collect::<Vec<_>>();
        let aggregate = DkgSecretScalar::aggregate(&constants.iter().collect::<Vec<_>>()).unwrap();
        let commitment = encode_g1(&multiply_g1_generator(&aggregate));
        let pvsses = materials.iter().map(DkgPvssMaterial::encoded).collect::<Vec<_>>();

        verify_aggregated_dkg_commitment(&commitment, &pvsses).unwrap();
        let mut different = commitment;
        different[NEOX_DKG_G1_LEN - 1] ^= 1;
        assert_eq!(
            verify_aggregated_dkg_commitment(&different, &pvsses),
            Err(DkgMaterialError::InvalidAggregatedCommitment)
        );
    }

    #[test]
    fn aggregate_share_verification_requires_complete_contributions() {
        let private_share = DkgSecretScalar::from_u64(1);
        let empty: [&[u8]; 0] = [];
        assert_eq!(
            verify_aggregated_dkg_share(1, private_share.as_bytes(), &empty),
            Err(DkgMaterialError::InvalidPvssContributionCount { actual: 0 })
        );

        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material =
            polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7)).unwrap();
        let incomplete = vec![material.encoded(); NEOX_DKG_PARTICIPANTS - 1];
        assert_eq!(
            verify_aggregated_dkg_share(1, private_share.as_bytes(), &incomplete),
            Err(DkgMaterialError::InvalidPvssContributionCount {
                actual: NEOX_DKG_PARTICIPANTS - 1,
            })
        );
    }

    #[test]
    fn rejects_inconsistent_pvss_randomizers_and_public_shares() {
        let polynomial = DkgPolynomial::from_u64_coefficients([1, 2, 3, 4, 5]);
        let material =
            polynomial.generate_pvss_with_randomizer(&DkgSecretScalar::from_u64(7)).unwrap();

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
