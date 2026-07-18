//! Canonical `KeyManagement` DKG state discovery.

use alloy_primitives::{keccak256, B256, U256};
use reth_neox_antimev::{
    global_public_key_from_commitment, G1_COMPRESSED_LEN, G1_EIP2537_LEN, NEOX_DKG_SCALER,
};
use reth_neox_evm::{
    uint_mapping_storage_key, KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT,
    KEY_MANAGEMENT_PROXY_ADDRESS, KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
};
use reth_provider::StateProvider;
use thiserror::Error;

const MAX_SOLIDITY_BYTES_LEN: usize = 4 * 1024 * 1024;

/// One successful `KeyManagement` DKG round and its scaled global public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgPublicKey {
    /// Contract round number, starting at one.
    pub round: u64,
    /// Unscaled 128-byte EIP-2537 commitment stored by `KeyManagement`.
    pub commitment: [u8; G1_EIP2537_LEN],
    /// Compressed global G1 key after applying Neo X's 5-of-7 scaler.
    pub global_public_key: [u8; G1_COMPRESSED_LEN],
}

/// Current and preceding DKG keys required by cross-epoch Envelope decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgState {
    /// Latest successful round selected by `roundNumber`.
    pub current: DkgPublicKey,
    /// Prior successful round, when it still exists.
    pub previous: Option<DkgPublicKey>,
}

/// Reads `KeyManagement`'s current and previous global keys directly from canonical storage.
pub fn read_dkg_state(state: &dyn StateProvider) -> Result<DkgState, DkgStateError> {
    read_dkg_state_from_storage(|key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStateError::Provider(error.to_string()))
    })
}

fn read_dkg_state_from_storage(
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
) -> Result<DkgState, DkgStateError> {
    let round = storage(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into())?.unwrap_or_default();
    let round = u64::try_from(round).map_err(|_| DkgStateError::RoundOverflow)?;
    if round == 0 {
        return Err(DkgStateError::MissingCurrentRound)
    }
    let current =
        read_public_key(&mut storage, round)?.ok_or(DkgStateError::MissingCommitment { round })?;
    let previous = if round > 1 { read_public_key(&mut storage, round - 1)? } else { None };
    Ok(DkgState { current, previous })
}

fn read_public_key(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
    round: u64,
) -> Result<Option<DkgPublicKey>, DkgStateError> {
    let slot =
        uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(round));
    let encoded = read_solidity_bytes(storage, slot)?;
    if encoded.is_empty() {
        return Ok(None)
    }
    let commitment: [u8; G1_EIP2537_LEN] = encoded.try_into().map_err(|encoded: Vec<u8>| {
        DkgStateError::InvalidCommitmentLength { round, actual: encoded.len() }
    })?;
    let global_public_key = global_public_key_from_commitment(&commitment, NEOX_DKG_SCALER)
        .map_err(|error| DkgStateError::InvalidCommitment { round, reason: error.to_string() })?;
    Ok(Some(DkgPublicKey { round, commitment, global_public_key }))
}

fn read_solidity_bytes(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
    slot: U256,
) -> Result<Vec<u8>, DkgStateError> {
    let header = storage(slot.into())?.unwrap_or_default();
    let header_bytes = header.to_be_bytes::<32>();
    if header.bit(0) {
        let length = usize::try_from((header - U256::from(1)) / U256::from(2))
            .map_err(|_| DkgStateError::BytesTooLarge(MAX_SOLIDITY_BYTES_LEN + 1))?;
        if length > MAX_SOLIDITY_BYTES_LEN {
            return Err(DkgStateError::BytesTooLarge(length))
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
            return Err(DkgStateError::InvalidShortBytesLength(length))
        }
        Ok(header_bytes[..length].to_vec())
    }
}

/// `KeyManagement` canonical-state decoding failure.
#[derive(Debug, Error)]
pub enum DkgStateError {
    /// Canonical state could not be read.
    #[error("failed to read Neo X KeyManagement state: {0}")]
    Provider(String),
    /// `roundNumber` does not fit the protocol's 64-bit round representation.
    #[error("Neo X KeyManagement round number exceeds u64")]
    RoundOverflow,
    /// DKG has not completed its first round.
    #[error("Neo X KeyManagement has no successful DKG round")]
    MissingCurrentRound,
    /// The mapping has no commitment for the selected current round.
    #[error("Neo X KeyManagement is missing aggregated commitment for round {round}")]
    MissingCommitment {
        /// Missing round.
        round: u64,
    },
    /// A Solidity short byte string encoded an impossible length.
    #[error("invalid Solidity short-bytes length {0}")]
    InvalidShortBytesLength(usize),
    /// A dynamic byte array exceeded the defensive allocation ceiling.
    #[error("Solidity dynamic bytes value is too large: {0}")]
    BytesTooLarge(usize),
    /// `KeyManagement` commitments must contain exactly two padded EIP-2537 coordinates.
    #[error("invalid KeyManagement commitment length for round {round}: {actual}")]
    InvalidCommitmentLength {
        /// DKG round.
        round: u64,
        /// Actual byte length.
        actual: usize,
    },
    /// The commitment was malformed or outside the BLS12-381 subgroup.
    #[error("invalid KeyManagement commitment for round {round}: {reason}")]
    InvalidCommitment {
        /// DKG round.
        round: u64,
        /// Curve validation reason.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, hex};
    use std::collections::HashMap;

    #[test]
    fn reads_live_testnet_round_from_raw_solidity_storage() {
        let mapping_slot =
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(88));
        assert_eq!(
            B256::from(mapping_slot),
            b256!("08ae31aff3dbe84432d25da21feb6e62c57099b18e584c914d98179fde33a980")
        );
        let data_base = U256::from_be_bytes(keccak256(mapping_slot.to_be_bytes::<32>()).0);
        assert_eq!(
            B256::from(data_base),
            b256!("1122f13eab05ff0398349324c17fb519c06daf51795adb6f868c378f3a4aca96")
        );

        let words = [
            hex!("0000000000000000000000000000000014c3bd13c1d7fcf70d288e1be25e5fed"),
            hex!("75ecd9de009614311862bf53a630de41b688d3dc2dd8ab6418b7ff74d16e1d31"),
            hex!("0000000000000000000000000000000011172e2b1d5f21c54ba685ff04703657"),
            hex!("f74630886044a3b8884c5a2077fa0776da2cc1a4dbdfa64dd1092bcb0c3fe192"),
        ];
        let mut storage = HashMap::new();
        storage.insert(B256::ZERO, U256::from(88));
        storage.insert(B256::from(mapping_slot), U256::from(257));
        for (index, word) in words.into_iter().enumerate() {
            storage.insert(
                B256::from(data_base.wrapping_add(U256::from(index))),
                U256::from_be_bytes(word),
            );
        }

        let state = read_dkg_state_from_storage(|key| Ok(storage.get(&key).copied())).unwrap();
        assert_eq!(state.current.round, 88);
        assert!(state.previous.is_none());
        assert_eq!(
            state.current.global_public_key,
            hex!(
                "94d0b75f3e08312e972fc319b25d2d58ca20f077704a7b351cb264716b8e75409e8c463c1da64f288cce8d961e592019"
            )
        );
    }
}
