//! Consensus-critical unencrypted Envelope layout.

use crate::TpkeCiphertext;
use alloy_consensus::TxType;
use alloy_primitives::{address, Address, B256};
use thiserror::Error;

/// Target of every Neo X Anti-MEV Envelope transaction.
pub const ENVELOPE_TARGET: Address = address!("1212000000000000000000000000000000000003");
/// Four-byte version marker at the beginning of Envelope calldata.
pub const ENCRYPTED_DATA_PREFIX: [u8; 4] = [0xff; 4];
/// Bytes used to encode the DKG round in big-endian order.
pub const ENCRYPTED_DATA_ROUND_LEN: usize = 4;
/// Bytes used to encode the inner transaction gas limit in big-endian order.
pub const ENCRYPTED_DATA_GAS_LEN: usize = 4;
/// Bytes used for the committed inner transaction hash.
pub const ENCRYPTED_DATA_HASH_LEN: usize = 32;
/// Serialized TPKE ciphertext size: compressed G1 + compressed G1 + compressed G2.
pub const TPKE_CIPHERTEXT_LEN: usize = 48 + 48 + 96;
/// Minimum gas limit of an encrypted inner transaction.
pub const MIN_ENCRYPTED_GAS_LIMIT: u32 = 21_000;
/// Minimum padded AES-CBC ciphertext used by the reference client.
pub const MIN_ENCRYPTED_MESSAGE_LEN: usize = 112;
/// Minimum calldata length that is recognized as an Envelope.
pub const MIN_ENVELOPE_DATA_LEN: usize = ENCRYPTED_DATA_PREFIX.len() +
    ENCRYPTED_DATA_ROUND_LEN +
    ENCRYPTED_DATA_GAS_LEN +
    ENCRYPTED_DATA_HASH_LEN +
    TPKE_CIPHERTEXT_LEN +
    MIN_ENCRYPTED_MESSAGE_LEN;

const ROUND_OFFSET: usize = ENCRYPTED_DATA_PREFIX.len();
const GAS_OFFSET: usize = ROUND_OFFSET + ENCRYPTED_DATA_ROUND_LEN;
const HASH_OFFSET: usize = GAS_OFFSET + ENCRYPTED_DATA_GAS_LEN;
const CIPHERTEXT_OFFSET: usize = HASH_OFFSET + ENCRYPTED_DATA_HASH_LEN;
const MESSAGE_OFFSET: usize = CIPHERTEXT_OFFSET + TPKE_CIPHERTEXT_LEN;

/// Returns whether a regular Ethereum transaction carries an Anti-MEV Envelope for counting,
/// decryption, and pool admission.
///
/// Neo X does not define a new EIP-2718 transaction type. Envelopes are legacy, EIP-2930, or
/// EIP-1559 transactions sent to the governance reward proxy with a reserved calldata prefix and
/// minimum length. Blob and EIP-7702 transactions are explicitly excluded from those
/// transaction-type-sensitive paths.
pub fn is_envelope(tx_type: u8, target: Option<Address>, data: &[u8]) -> bool {
    tx_type != TxType::Eip4844 as u8 &&
        tx_type != TxType::Eip7702 as u8 &&
        target == Some(ENVELOPE_TARGET) &&
        is_envelope_data(data)
}

/// Returns whether a transaction is subject to the block-level Envelope policy.
///
/// Consensus execution applies the `PolicyProxy` gas and fee rules from the target and calldata
/// alone. In particular, EIP-4844 and EIP-7702 transactions can still carry Envelope-shaped data
/// and must not bypass those rules merely because their transaction type is different.
pub fn is_envelope_policy(target: Option<Address>, data: &[u8]) -> bool {
    target == Some(ENVELOPE_TARGET) && is_envelope_data(data)
}

/// Returns whether calldata satisfies the reference client's Envelope recognition rule.
pub fn is_envelope_data(data: &[u8]) -> bool {
    data.len() >= MIN_ENVELOPE_DATA_LEN && data.starts_with(&ENCRYPTED_DATA_PREFIX)
}

/// Returns the declared encrypted inner-transaction gas limit.
///
/// The caller must first establish [`is_envelope_data`].
pub fn encrypted_gas(data: &[u8]) -> u32 {
    u32::from_be_bytes(
        data[GAS_OFFSET..HASH_OFFSET].try_into().expect("recognized Envelope contains gas bytes"),
    )
}

/// Returns the committed encrypted inner-transaction hash.
///
/// The caller must first establish [`is_envelope_data`].
pub fn encrypted_hash(data: &[u8]) -> B256 {
    B256::from_slice(&data[HASH_OFFSET..CIPHERTEXT_OFFSET])
}

/// Parsed unencrypted and encrypted portions of an Envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeData<'a> {
    /// DKG round whose global key encrypted the payload.
    pub dkg_round: u32,
    /// Gas reserved for the decrypted inner transaction.
    pub encrypted_gas: u32,
    /// Hash committed to the signed decrypted transaction.
    pub encrypted_hash: B256,
    /// Serialized TPKE-encrypted AES key.
    pub encrypted_key: TpkeCiphertext,
    /// AES-CBC encrypted EIP-2718 transaction bytes.
    pub encrypted_message: &'a [u8],
}

impl<'a> EnvelopeData<'a> {
    /// Parses recognized Envelope calldata and validates the nonzero DKG round.
    pub fn decode(data: &'a [u8]) -> Result<Self, EnvelopeDecodeError> {
        if !is_envelope_data(data) {
            return Err(EnvelopeDecodeError::NotEnvelope);
        }
        let dkg_round = u32::from_be_bytes(
            data[ROUND_OFFSET..GAS_OFFSET]
                .try_into()
                .expect("recognized Envelope contains round bytes"),
        );
        if dkg_round == 0 {
            return Err(EnvelopeDecodeError::ZeroDkgRound);
        }
        Ok(Self {
            dkg_round,
            encrypted_gas: encrypted_gas(data),
            encrypted_hash: encrypted_hash(data),
            encrypted_key: TpkeCiphertext::decode(&data[CIPHERTEXT_OFFSET..MESSAGE_OFFSET])?,
            encrypted_message: &data[MESSAGE_OFFSET..],
        })
    }
}

/// Envelope calldata parsing failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeDecodeError {
    /// Calldata does not satisfy the Envelope prefix and minimum-size rule.
    #[error("calldata is not a Neo X Envelope")]
    NotEnvelope,
    /// DKG round zero is never valid for encrypted content.
    #[error("Envelope declares invalid DKG round zero")]
    ZeroDkgRound,
    /// The encrypted key does not contain three valid compressed curve points.
    #[error(transparent)]
    Tpke(#[from] crate::TpkeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_bytes(round: u32, gas: u32) -> [u8; MIN_ENVELOPE_DATA_LEN] {
        let mut data = [0_u8; MIN_ENVELOPE_DATA_LEN];
        data[..4].copy_from_slice(&ENCRYPTED_DATA_PREFIX);
        data[ROUND_OFFSET..GAS_OFFSET].copy_from_slice(&round.to_be_bytes());
        data[GAS_OFFSET..HASH_OFFSET].copy_from_slice(&gas.to_be_bytes());
        data[HASH_OFFSET..CIPHERTEXT_OFFSET].fill(0x42);
        // Compressed points at infinity are valid gnark/blst encodings. Envelope decoding only
        // parses points; the separate ciphertext verification step rejects invalid commitments.
        data[CIPHERTEXT_OFFSET] = 0xc0;
        data[CIPHERTEXT_OFFSET + crate::G1_COMPRESSED_LEN] = 0xc0;
        data[CIPHERTEXT_OFFSET + crate::G1_COMPRESSED_LEN * 2] = 0xc0;
        data
    }

    #[test]
    fn recognizes_envelopes_without_a_custom_transaction_type() {
        let data = envelope_bytes(7, 35_000);
        assert!(is_envelope(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &data));
        assert!(is_envelope(TxType::Eip2930 as u8, Some(ENVELOPE_TARGET), &data));
        assert!(is_envelope(TxType::Eip1559 as u8, Some(ENVELOPE_TARGET), &data));
        assert!(!is_envelope(TxType::Eip4844 as u8, Some(ENVELOPE_TARGET), &data));
        assert!(!is_envelope(TxType::Eip7702 as u8, Some(ENVELOPE_TARGET), &data));
        assert!(is_envelope_policy(Some(ENVELOPE_TARGET), &data));
        assert!(!is_envelope(TxType::Legacy as u8, Some(Address::ZERO), &data));
        assert!(!is_envelope_policy(Some(Address::ZERO), &data));
    }

    #[test]
    fn parses_reference_layout() {
        let data = envelope_bytes(0x0102_0304, 35_000);
        let decoded = EnvelopeData::decode(&data).unwrap();
        assert_eq!(decoded.dkg_round, 0x0102_0304);
        assert_eq!(decoded.encrypted_gas, 35_000);
        assert_eq!(decoded.encrypted_hash, B256::repeat_byte(0x42));
        assert_eq!(decoded.encrypted_key.to_bytes().len(), TPKE_CIPHERTEXT_LEN);
        assert_eq!(decoded.encrypted_message.len(), MIN_ENCRYPTED_MESSAGE_LEN);
    }

    #[test]
    fn recognition_and_decoding_match_reference_zero_round_behavior() {
        let data = envelope_bytes(0, MIN_ENCRYPTED_GAS_LIMIT);
        assert!(is_envelope_data(&data));
        assert_eq!(EnvelopeData::decode(&data), Err(EnvelopeDecodeError::ZeroDkgRound));
    }

    #[test]
    fn decoding_rejects_invalid_tpke_points() {
        let mut data = envelope_bytes(1, MIN_ENCRYPTED_GAS_LIMIT);
        data[CIPHERTEXT_OFFSET] = 0;
        assert!(matches!(
            EnvelopeData::decode(&data),
            Err(EnvelopeDecodeError::Tpke(crate::TpkeError::InvalidG1Point("encrypted message")))
        ));
    }
}
