//! Direct canonical-storage readers for DKG task preparation.

use alloy_primitives::{keccak256, Address, B256, U256};
use k256::PublicKey;
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use reth_neox_evm::{
    address_mapping_storage_key, nested_uint_mapping_storage_key,
    KEY_MANAGEMENT_MESSAGE_PUBKEYS_SLOT, KEY_MANAGEMENT_PROXY_ADDRESS,
    KEY_MANAGEMENT_RESHARE_MSGS_SLOT, KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
    KEY_MANAGEMENT_SHARE_MSGS_SLOT,
};
use reth_provider::StateProvider;
use thiserror::Error;

const MAX_MESSAGE_KEY_BYTES_LEN: usize = 1024;
const UNCOMPRESSED_SECP256K1_KEY_LEN: usize = 65;

/// On-chain facts used by the DKG checkpoint planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgTaskContractState {
    /// Last DKG round accepted by `KeyManagement`.
    pub current_round: u64,
    /// Round for which validators are currently sharing, equal to `current_round + 1`.
    pub next_round: u64,
    /// Whether every pending validator has all seven encrypted share messages.
    pub share_ready: bool,
    /// One-based pending-validator positions with no reshare messages for `next_round`.
    pub recovery_indices: Vec<u64>,
}

/// Reads share completeness and missing reshares using the deployed nested-mapping layout.
pub fn read_dkg_task_contract_state(
    state: &dyn StateProvider,
) -> Result<DkgTaskContractState, DkgTaskContractStateError> {
    read_dkg_task_contract_state_from_storage(|key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgTaskContractStateError::Provider(error.to_string()))
    })
}

fn read_dkg_task_contract_state_from_storage(
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgTaskContractStateError>,
) -> Result<DkgTaskContractState, DkgTaskContractStateError> {
    let current_round =
        storage(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into())?.unwrap_or_default();
    let current_round =
        u64::try_from(current_round).map_err(|_| DkgTaskContractStateError::RoundOverflow)?;
    let next_round =
        current_round.checked_add(1).ok_or(DkgTaskContractStateError::RoundOverflow)?;

    let mut share_ready = true;
    let mut recovery_indices = Vec::new();
    for index in 1..=NEOX_VALIDATOR_COUNT as u64 {
        let share_slot = nested_uint_mapping_storage_key(
            KEY_MANAGEMENT_SHARE_MSGS_SLOT,
            &[U256::from(next_round), U256::from(index)],
        );
        let share_count = storage(share_slot.into())?.unwrap_or_default();
        if share_count < U256::from(NEOX_VALIDATOR_COUNT) {
            share_ready = false;
        }

        if next_round > 1 {
            let reshare_slot = nested_uint_mapping_storage_key(
                KEY_MANAGEMENT_RESHARE_MSGS_SLOT,
                &[U256::from(next_round), U256::from(index)],
            );
            if storage(reshare_slot.into())?.unwrap_or_default().is_zero() {
                recovery_indices.push(index);
            }
        }
    }

    Ok(DkgTaskContractState { current_round, next_round, share_ready, recovery_indices })
}

/// Reads and validates one uncompressed Secp256k1 message-encryption public key.
pub fn read_dkg_message_public_key(
    state: &dyn StateProvider,
    validator: Address,
) -> Result<[u8; UNCOMPRESSED_SECP256K1_KEY_LEN], DkgTaskContractStateError> {
    read_dkg_message_public_key_from_storage(validator, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgTaskContractStateError::Provider(error.to_string()))
    })
}

/// Reads message-encryption keys in pending-consensus order.
pub fn read_dkg_message_public_keys(
    state: &dyn StateProvider,
    validators: &[Address],
) -> Result<Vec<[u8; UNCOMPRESSED_SECP256K1_KEY_LEN]>, DkgTaskContractStateError> {
    validators.iter().map(|validator| read_dkg_message_public_key(state, *validator)).collect()
}

fn read_dkg_message_public_key_from_storage(
    validator: Address,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgTaskContractStateError>,
) -> Result<[u8; UNCOMPRESSED_SECP256K1_KEY_LEN], DkgTaskContractStateError> {
    let slot = address_mapping_storage_key(KEY_MANAGEMENT_MESSAGE_PUBKEYS_SLOT, validator);
    let encoded = read_solidity_bytes(&mut storage, slot)?;
    if encoded.is_empty() {
        return Err(DkgTaskContractStateError::MissingMessageKey(validator))
    }
    let key: [u8; UNCOMPRESSED_SECP256K1_KEY_LEN] =
        encoded.try_into().map_err(|encoded: Vec<u8>| {
            DkgTaskContractStateError::InvalidMessageKeyLength { validator, actual: encoded.len() }
        })?;
    PublicKey::from_sec1_bytes(&key)
        .map_err(|_| DkgTaskContractStateError::InvalidMessageKey(validator))?;
    Ok(key)
}

fn read_solidity_bytes(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgTaskContractStateError>,
    slot: U256,
) -> Result<Vec<u8>, DkgTaskContractStateError> {
    let header = storage(slot.into())?.unwrap_or_default();
    let header_bytes = header.to_be_bytes::<32>();
    if header.bit(0) {
        let length = usize::try_from((header - U256::from(1)) / U256::from(2))
            .map_err(|_| DkgTaskContractStateError::BytesTooLarge(MAX_MESSAGE_KEY_BYTES_LEN + 1))?;
        if length > MAX_MESSAGE_KEY_BYTES_LEN {
            return Err(DkgTaskContractStateError::BytesTooLarge(length))
        }
        let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
        let mut value = Vec::with_capacity(length);
        for index in 0..length.div_ceil(32) {
            let word = storage(base.wrapping_add(U256::from(index)).into())?
                .unwrap_or_default()
                .to_be_bytes::<32>();
            value.extend_from_slice(&word);
        }
        value.truncate(length);
        Ok(value)
    } else {
        let length = usize::from(header_bytes[31] / 2);
        if length > 31 {
            return Err(DkgTaskContractStateError::InvalidShortBytesLength(length))
        }
        Ok(header_bytes[..length].to_vec())
    }
}

/// Failure to derive DKG task inputs from canonical `KeyManagement` storage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgTaskContractStateError {
    /// Canonical state could not be read.
    #[error("failed to read Neo X KeyManagement task state: {0}")]
    Provider(String),
    /// A round number did not fit the node's 64-bit protocol representation.
    #[error("Neo X KeyManagement round number exceeds u64")]
    RoundOverflow,
    /// The validator has not registered a message-encryption key.
    #[error("Neo X validator {0} has no DKG message public key")]
    MissingMessageKey(Address),
    /// Message keys must use uncompressed Secp256k1 encoding.
    #[error("invalid DKG message public-key length for {validator}: {actual}")]
    InvalidMessageKeyLength {
        /// Validator whose mapping value was malformed.
        validator: Address,
        /// Actual encoded length.
        actual: usize,
    },
    /// The 65-byte message key was not a valid Secp256k1 point.
    #[error("invalid DKG message public key for {0}")]
    InvalidMessageKey(Address),
    /// A Solidity short byte string encoded an impossible length.
    #[error("invalid Solidity short-bytes length {0}")]
    InvalidShortBytesLength(usize),
    /// A dynamic message key exceeded the defensive allocation ceiling.
    #[error("Solidity dynamic bytes value is too large: {0}")]
    BytesTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use std::collections::HashMap;

    #[test]
    fn reads_share_readiness_and_missing_reshares() {
        let mut storage = HashMap::from([(
            B256::from(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT)),
            U256::from(1),
        )]);
        for index in 1..=NEOX_VALIDATOR_COUNT as u64 {
            storage.insert(
                nested_uint_mapping_storage_key(
                    KEY_MANAGEMENT_SHARE_MSGS_SLOT,
                    &[U256::from(2), U256::from(index)],
                )
                .into(),
                U256::from(NEOX_VALIDATOR_COUNT),
            );
            if ![2, 7].contains(&index) {
                storage.insert(
                    nested_uint_mapping_storage_key(
                        KEY_MANAGEMENT_RESHARE_MSGS_SLOT,
                        &[U256::from(2), U256::from(index)],
                    )
                    .into(),
                    U256::from(NEOX_VALIDATOR_COUNT),
                );
            }
        }

        let state = read_dkg_task_contract_state_from_storage(|key| Ok(storage.get(&key).copied()))
            .unwrap();
        assert_eq!(state.current_round, 1);
        assert_eq!(state.next_round, 2);
        assert!(state.share_ready);
        assert_eq!(state.recovery_indices, vec![2, 7]);

        let incomplete = nested_uint_mapping_storage_key(
            KEY_MANAGEMENT_SHARE_MSGS_SLOT,
            &[U256::from(2), U256::from(4)],
        );
        storage.insert(incomplete.into(), U256::from(6));
        let state = read_dkg_task_contract_state_from_storage(|key| Ok(storage.get(&key).copied()))
            .unwrap();
        assert!(!state.share_ready);
    }

    #[test]
    fn reads_and_validates_dynamic_message_public_key() {
        let validator = Address::repeat_byte(0x11);
        let secret = SecretKey::from_slice(&[1_u8; 32]).unwrap();
        let encoded = secret.public_key().to_encoded_point(false);
        let expected: [u8; UNCOMPRESSED_SECP256K1_KEY_LEN] = encoded.as_bytes().try_into().unwrap();
        let slot = address_mapping_storage_key(KEY_MANAGEMENT_MESSAGE_PUBKEYS_SLOT, validator);
        let mut storage = HashMap::new();
        store_long_bytes(&mut storage, slot, &expected);

        let actual = read_dkg_message_public_key_from_storage(validator, |key| {
            Ok(storage.get(&key).copied())
        })
        .unwrap();
        assert_eq!(actual, expected);

        storage.clear();
        assert_eq!(
            read_dkg_message_public_key_from_storage(validator, |key| {
                Ok(storage.get(&key).copied())
            }),
            Err(DkgTaskContractStateError::MissingMessageKey(validator))
        );
    }

    fn store_long_bytes(storage: &mut HashMap<B256, U256>, slot: U256, value: &[u8]) {
        storage.insert(slot.into(), U256::from(value.len() * 2 + 1));
        let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
        for (index, chunk) in value.chunks(32).enumerate() {
            let mut word = [0_u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            storage.insert(base.wrapping_add(U256::from(index)).into(), U256::from_be_bytes(word));
        }
    }
}
