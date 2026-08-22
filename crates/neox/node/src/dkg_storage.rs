//! Canonical `KeyManagement` storage readers for crash and reorg-safe DKG replay.

use crate::NEOX_DKG_MESSAGE_LEN;
use alloy_primitives::{keccak256, Bytes, B256, U256};
use reth_neox_antimev::{DkgParameters, G1_EIP2537_LEN};
use reth_neox_evm::{
    nested_uint_mapping_storage_key, uint_mapping_storage_key,
    KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, KEY_MANAGEMENT_PROXY_ADDRESS,
    KEY_MANAGEMENT_RECOVER_MSGS_SLOT, KEY_MANAGEMENT_RESHARE_MSGS_SLOT,
    KEY_MANAGEMENT_RESHARE_PVSS_SLOT, KEY_MANAGEMENT_SHARE_MSGS_SLOT,
    KEY_MANAGEMENT_SHARE_PVSS_SLOT,
};
use reth_provider::StateProvider;
use thiserror::Error;

/// One canonical share or reshare contribution stored by `KeyManagement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgStoredContribution {
    /// Implicit DKG round of the contribution.
    pub round: u64,
    /// One-based sender position in the corresponding validator set.
    pub sender_index: u64,
    /// Exact public PVSS bytes verified by the contract.
    pub pvss: Bytes,
    /// Seven encrypted messages in pending-validator order.
    pub messages: Vec<Bytes>,
}

/// One canonical recovery message addressed to a missing pending validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgStoredRecovery {
    /// Implicit DKG round of the recovery contribution.
    pub round: u64,
    /// One-based current-validator sender position.
    pub sender_index: u64,
    /// One-based pending-validator recipient position.
    pub recipient_index: u64,
    /// Exact encrypted scalar message verified by the contract proof.
    pub message: Bytes,
}

/// Reads one accepted fresh-share contribution from canonical storage.
pub fn read_dkg_share_contribution(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    read_dkg_share_contribution_with_parameters(
        state,
        round,
        sender_index,
        DkgParameters::canonical(),
    )
}

/// Parameterized variant of [`read_dkg_share_contribution`].
pub fn read_dkg_share_contribution_with_parameters(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    parameters: DkgParameters,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    read_dkg_contribution(state, round, sender_index, DkgContributionKind::Share, parameters)
}

/// Reads one accepted old-key reshare contribution from canonical storage.
pub fn read_dkg_reshare_contribution(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    read_dkg_reshare_contribution_with_parameters(
        state,
        round,
        sender_index,
        DkgParameters::canonical(),
    )
}

/// Parameterized variant of [`read_dkg_reshare_contribution`].
pub fn read_dkg_reshare_contribution_with_parameters(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    parameters: DkgParameters,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    read_dkg_contribution(state, round, sender_index, DkgContributionKind::Reshare, parameters)
}

/// Reads one accepted fresh-share PVSS value from canonical storage.
///
/// This reader intentionally does not inspect the encrypted message array.  Neo X clears those
/// arrays when a round is settled, while retaining the PVSS values needed to reconstruct the
/// canonical epoch boundary.
pub fn read_dkg_share_pvss(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
) -> Result<Option<Bytes>, DkgStorageError> {
    read_dkg_share_pvss_with_parameters(state, round, sender_index, DkgParameters::canonical())
}

/// Parameterized variant of [`read_dkg_share_pvss`].
pub fn read_dkg_share_pvss_with_parameters(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    parameters: DkgParameters,
) -> Result<Option<Bytes>, DkgStorageError> {
    read_dkg_pvss(state, round, sender_index, DkgContributionKind::Share, parameters)
}

/// Reads one accepted old-key reshare PVSS value from canonical storage.
///
/// This reader intentionally does not inspect the encrypted message array.  Neo X clears those
/// arrays when a round is settled, while retaining the PVSS values needed to reconstruct the
/// canonical epoch boundary.
pub fn read_dkg_reshare_pvss(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
) -> Result<Option<Bytes>, DkgStorageError> {
    read_dkg_reshare_pvss_with_parameters(state, round, sender_index, DkgParameters::canonical())
}

/// Parameterized variant of [`read_dkg_reshare_pvss`].
pub fn read_dkg_reshare_pvss_with_parameters(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    parameters: DkgParameters,
) -> Result<Option<Bytes>, DkgStorageError> {
    read_dkg_pvss(state, round, sender_index, DkgContributionKind::Reshare, parameters)
}

/// Reads all canonical recovery messages addressed to one pending-validator position.
pub fn read_dkg_recovery_messages(
    state: &dyn StateProvider,
    round: u64,
    recipient_index: u64,
) -> Result<Vec<DkgStoredRecovery>, DkgStorageError> {
    read_dkg_recovery_messages_with_parameters(
        state,
        round,
        recipient_index,
        DkgParameters::canonical(),
    )
}

/// Parameterized variant of [`read_dkg_recovery_messages`].
pub fn read_dkg_recovery_messages_with_parameters(
    state: &dyn StateProvider,
    round: u64,
    recipient_index: u64,
    parameters: DkgParameters,
) -> Result<Vec<DkgStoredRecovery>, DkgStorageError> {
    validate_round(round)?;
    validate_index(recipient_index, parameters)?;
    read_dkg_recovery_messages_from_storage(round, recipient_index, parameters, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStorageError::Provider(error.to_string()))
    })
}

/// Reads a successful round's aggregate G1 commitment, if one exists.
///
/// The commitment has a fixed EIP-2537 G1 length for every committee size, so unlike the other
/// storage readers this read takes no DKG parameters.
pub fn read_dkg_aggregated_commitment(
    state: &dyn StateProvider,
    round: u64,
) -> Result<Option<[u8; G1_EIP2537_LEN]>, DkgStorageError> {
    validate_round(round)?;
    read_dkg_aggregated_commitment_from_storage(round, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStorageError::Provider(error.to_string()))
    })
}

#[derive(Debug, Clone, Copy)]
enum DkgContributionKind {
    Share,
    Reshare,
}

impl DkgContributionKind {
    const fn slots(self) -> (u64, u64) {
        match self {
            Self::Share => (KEY_MANAGEMENT_SHARE_PVSS_SLOT, KEY_MANAGEMENT_SHARE_MSGS_SLOT),
            Self::Reshare => (KEY_MANAGEMENT_RESHARE_PVSS_SLOT, KEY_MANAGEMENT_RESHARE_MSGS_SLOT),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Share => "share",
            Self::Reshare => "reshare",
        }
    }
}

fn read_dkg_contribution(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    kind: DkgContributionKind,
    parameters: DkgParameters,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    validate_round(round)?;
    validate_index(sender_index, parameters)?;
    read_dkg_contribution_from_storage(round, sender_index, kind, parameters, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStorageError::Provider(error.to_string()))
    })
}

fn read_dkg_pvss(
    state: &dyn StateProvider,
    round: u64,
    sender_index: u64,
    kind: DkgContributionKind,
    parameters: DkgParameters,
) -> Result<Option<Bytes>, DkgStorageError> {
    validate_round(round)?;
    validate_index(sender_index, parameters)?;
    read_dkg_pvss_from_storage(round, sender_index, kind, parameters, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStorageError::Provider(error.to_string()))
    })
}

fn read_dkg_pvss_from_storage(
    round: u64,
    sender_index: u64,
    kind: DkgContributionKind,
    parameters: DkgParameters,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
) -> Result<Option<Bytes>, DkgStorageError> {
    let (pvss_slot, _) = kind.slots();
    let pvss_slot =
        nested_uint_mapping_storage_key(pvss_slot, &[U256::from(round), U256::from(sender_index)]);
    let pvss = read_solidity_bytes(&mut storage, pvss_slot, parameters.pvss_len())?;
    if pvss.is_empty() {
        return Ok(None)
    }
    if pvss.len() != parameters.pvss_len() {
        return Err(DkgStorageError::InvalidPvssLength {
            kind: kind.name(),
            round,
            sender_index,
            actual: pvss.len(),
        })
    }
    Ok(Some(pvss.into()))
}

fn read_dkg_contribution_from_storage(
    round: u64,
    sender_index: u64,
    kind: DkgContributionKind,
    parameters: DkgParameters,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
) -> Result<Option<DkgStoredContribution>, DkgStorageError> {
    let (pvss_slot, messages_slot) = kind.slots();
    let keys = [U256::from(round), U256::from(sender_index)];
    let pvss_slot = nested_uint_mapping_storage_key(pvss_slot, &keys);
    let messages_slot = nested_uint_mapping_storage_key(messages_slot, &keys);
    let pvss = read_solidity_bytes(&mut storage, pvss_slot, parameters.pvss_len())?;
    let messages =
        read_solidity_bytes_array(&mut storage, messages_slot, parameters.participants())?;

    if pvss.is_empty() && messages.is_empty() {
        return Ok(None)
    }
    if pvss.is_empty() || messages.is_empty() {
        return Err(DkgStorageError::IncompleteContribution {
            kind: kind.name(),
            round,
            sender_index,
        })
    }
    if pvss.len() != parameters.pvss_len() {
        return Err(DkgStorageError::InvalidPvssLength {
            kind: kind.name(),
            round,
            sender_index,
            actual: pvss.len(),
        })
    }
    if messages.len() != parameters.participants() {
        return Err(DkgStorageError::InvalidMessageCount {
            kind: kind.name(),
            round,
            sender_index,
            actual: messages.len(),
        })
    }
    validate_messages(kind.name(), round, sender_index, &messages)?;
    Ok(Some(DkgStoredContribution {
        round,
        sender_index,
        pvss: pvss.into(),
        messages: messages.into_iter().map(Into::into).collect(),
    }))
}

fn read_dkg_recovery_messages_from_storage(
    round: u64,
    recipient_index: u64,
    parameters: DkgParameters,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
) -> Result<Vec<DkgStoredRecovery>, DkgStorageError> {
    let recipient_array_index = recipient_index - 1;
    let mut messages = Vec::with_capacity(parameters.participants());
    for sender_index in 1..=parameters.participants() as u64 {
        let slot = nested_uint_mapping_storage_key(
            KEY_MANAGEMENT_RECOVER_MSGS_SLOT,
            &[U256::from(round), U256::from(sender_index), U256::from(recipient_array_index)],
        );
        let message = read_solidity_bytes(&mut storage, slot, NEOX_DKG_MESSAGE_LEN)?;
        if message.is_empty() {
            continue
        }
        if message.len() != NEOX_DKG_MESSAGE_LEN {
            return Err(DkgStorageError::InvalidRecoveryMessageLength {
                round,
                sender_index,
                recipient_index,
                actual: message.len(),
            })
        }
        messages.push(DkgStoredRecovery {
            round,
            sender_index,
            recipient_index,
            message: message.into(),
        });
    }
    Ok(messages)
}

fn read_dkg_aggregated_commitment_from_storage(
    round: u64,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
) -> Result<Option<[u8; G1_EIP2537_LEN]>, DkgStorageError> {
    let slot =
        uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(round));
    let commitment = read_solidity_bytes(&mut storage, slot, G1_EIP2537_LEN)?;
    if commitment.is_empty() {
        return Ok(None)
    }
    commitment.try_into().map(Some).map_err(|commitment: Vec<u8>| {
        DkgStorageError::InvalidCommitmentLength { round, actual: commitment.len() }
    })
}

fn read_solidity_bytes_array(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
    slot: U256,
    maximum: usize,
) -> Result<Vec<Vec<u8>>, DkgStorageError> {
    let length = storage(slot.into())?.unwrap_or_default();
    let length = usize::try_from(length)
        .map_err(|_| DkgStorageError::BytesArrayTooLarge { actual: usize::MAX, maximum })?;
    if length > maximum {
        return Err(DkgStorageError::BytesArrayTooLarge { actual: length, maximum })
    }
    let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
    (0..length)
        .map(|index| {
            read_solidity_bytes(storage, base.wrapping_add(U256::from(index)), NEOX_DKG_MESSAGE_LEN)
        })
        .collect()
}

fn read_solidity_bytes(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgStorageError>,
    slot: U256,
    maximum: usize,
) -> Result<Vec<u8>, DkgStorageError> {
    let header = storage(slot.into())?.unwrap_or_default();
    let header_bytes = header.to_be_bytes::<32>();
    if header.bit(0) {
        let length = usize::try_from((header - U256::from(1)) / U256::from(2))
            .map_err(|_| DkgStorageError::BytesTooLarge { actual: usize::MAX, maximum })?;
        if length > maximum {
            return Err(DkgStorageError::BytesTooLarge { actual: length, maximum })
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
            return Err(DkgStorageError::InvalidShortBytesLength(length))
        }
        if length > maximum {
            return Err(DkgStorageError::BytesTooLarge { actual: length, maximum })
        }
        Ok(header_bytes[..length].to_vec())
    }
}

fn validate_messages(
    kind: &'static str,
    round: u64,
    sender_index: u64,
    messages: &[Vec<u8>],
) -> Result<(), DkgStorageError> {
    for (message_index, message) in messages.iter().enumerate() {
        if message.len() != NEOX_DKG_MESSAGE_LEN {
            return Err(DkgStorageError::InvalidMessageLength {
                kind,
                round,
                sender_index,
                message_index,
                actual: message.len(),
            })
        }
    }
    Ok(())
}

const fn validate_round(round: u64) -> Result<(), DkgStorageError> {
    if round == 0 {
        Err(DkgStorageError::InvalidRound)
    } else {
        Ok(())
    }
}

fn validate_index(index: u64, parameters: DkgParameters) -> Result<(), DkgStorageError> {
    if (1..=parameters.participants() as u64).contains(&index) {
        Ok(())
    } else {
        Err(DkgStorageError::InvalidParticipantIndex(index))
    }
}

/// Malformed or unavailable canonical DKG contract storage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgStorageError {
    /// Canonical state could not be read.
    #[error("failed to read Neo X KeyManagement DKG material: {0}")]
    Provider(String),
    /// Round zero never contains active or settled DKG material.
    #[error("Neo X DKG storage round must be non-zero")]
    InvalidRound,
    /// Validator positions are one-based within the fixed committee.
    #[error("invalid Neo X DKG storage participant index {0}")]
    InvalidParticipantIndex(u64),
    /// A Solidity short byte string encoded an impossible length.
    #[error("invalid Neo X DKG Solidity short-bytes length {0}")]
    InvalidShortBytesLength(usize),
    /// A dynamic byte string exceeded the field-specific allocation ceiling.
    #[error("Neo X DKG Solidity bytes length {actual} exceeds maximum {maximum}")]
    BytesTooLarge {
        /// Encoded or overflow-saturated length.
        actual: usize,
        /// Field-specific defensive ceiling.
        maximum: usize,
    },
    /// A message array exceeded the deployed seven-member committee size.
    #[error("Neo X DKG bytes-array length {actual} exceeds maximum {maximum}")]
    BytesArrayTooLarge {
        /// Encoded or overflow-saturated length.
        actual: usize,
        /// Deployed maximum.
        maximum: usize,
    },
    /// A partially populated PVSS/message pair cannot be replayed safely.
    #[error("incomplete Neo X DKG {kind} contribution for round {round}, sender {sender_index}")]
    IncompleteContribution {
        /// Contribution type.
        kind: &'static str,
        /// DKG round.
        round: u64,
        /// One-based sender position.
        sender_index: u64,
    },
    /// Share and reshare PVSS data has one exact deployed length.
    #[error(
        "invalid Neo X DKG {kind} PVSS length for round {round}, sender {sender_index}: {actual}"
    )]
    InvalidPvssLength {
        /// Contribution type.
        kind: &'static str,
        /// DKG round.
        round: u64,
        /// One-based sender position.
        sender_index: u64,
        /// Actual byte length.
        actual: usize,
    },
    /// Share and reshare calls must store seven messages.
    #[error(
        "invalid Neo X DKG {kind} message count for round {round}, sender {sender_index}: {actual}"
    )]
    InvalidMessageCount {
        /// Contribution type.
        kind: &'static str,
        /// DKG round.
        round: u64,
        /// One-based sender position.
        sender_index: u64,
        /// Actual array length.
        actual: usize,
    },
    /// Each stored encrypted scalar has one exact ECIES length.
    #[error(
        "invalid Neo X DKG {kind} message length for round {round}, sender {sender_index}, message {message_index}: {actual}"
    )]
    InvalidMessageLength {
        /// Contribution type.
        kind: &'static str,
        /// DKG round.
        round: u64,
        /// One-based sender position.
        sender_index: u64,
        /// Zero-based encrypted-message position.
        message_index: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Recovery messages use the same exact ECIES encoding as share messages.
    #[error(
        "invalid Neo X DKG recovery message length for round {round}, sender {sender_index}, recipient {recipient_index}: {actual}"
    )]
    InvalidRecoveryMessageLength {
        /// DKG round.
        round: u64,
        /// One-based current-validator sender position.
        sender_index: u64,
        /// One-based pending-validator recipient position.
        recipient_index: u64,
        /// Actual byte length.
        actual: usize,
    },
    /// Aggregate commitments contain one EIP-2537 G1 point.
    #[error("invalid Neo X DKG aggregate commitment length for round {round}: {actual}")]
    InvalidCommitmentLength {
        /// DKG round.
        round: u64,
        /// Actual byte length.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NEOX_DKG_PVSS_LEN;
    use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
    use std::collections::HashMap;

    fn store_bytes(storage: &mut HashMap<B256, U256>, slot: U256, value: &[u8]) {
        if value.len() <= 31 {
            let mut word = [0_u8; 32];
            word[..value.len()].copy_from_slice(value);
            word[31] = (value.len() * 2) as u8;
            storage.insert(slot.into(), U256::from_be_bytes(word));
            return
        }
        storage.insert(slot.into(), U256::from(value.len() * 2 + 1));
        let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
        for (index, chunk) in value.chunks(32).enumerate() {
            let mut word = [0_u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            storage.insert(base.wrapping_add(U256::from(index)).into(), U256::from_be_bytes(word));
        }
    }

    fn store_bytes_array(storage: &mut HashMap<B256, U256>, slot: U256, values: &[Vec<u8>]) {
        storage.insert(slot.into(), U256::from(values.len()));
        let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
        for (index, value) in values.iter().enumerate() {
            store_bytes(storage, base.wrapping_add(U256::from(index)), value);
        }
    }

    #[test]
    fn reads_complete_share_and_reshare_contributions() {
        for kind in [DkgContributionKind::Share, DkgContributionKind::Reshare] {
            let (pvss_mapping, messages_mapping) = kind.slots();
            let keys = [U256::from(18), U256::from(3)];
            let pvss_slot = nested_uint_mapping_storage_key(pvss_mapping, &keys);
            let messages_slot = nested_uint_mapping_storage_key(messages_mapping, &keys);
            let mut storage = HashMap::new();
            store_bytes(&mut storage, pvss_slot, &vec![0x11; NEOX_DKG_PVSS_LEN]);
            store_bytes_array(
                &mut storage,
                messages_slot,
                &vec![vec![0x22; NEOX_DKG_MESSAGE_LEN]; NEOX_VALIDATOR_COUNT],
            );

            let contribution = read_dkg_contribution_from_storage(
                18,
                3,
                kind,
                DkgParameters::canonical(),
                |key| Ok(storage.get(&key).copied()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(contribution.round, 18);
            assert_eq!(contribution.sender_index, 3);
            assert_eq!(contribution.pvss.len(), NEOX_DKG_PVSS_LEN);
            assert_eq!(contribution.messages.len(), NEOX_VALIDATOR_COUNT);
        }
    }

    #[test]
    fn distinguishes_absent_and_incomplete_contributions() {
        assert_eq!(
            read_dkg_contribution_from_storage(
                1,
                1,
                DkgContributionKind::Share,
                DkgParameters::canonical(),
                |_| Ok(None),
            )
            .unwrap(),
            None
        );

        let slot = nested_uint_mapping_storage_key(
            KEY_MANAGEMENT_SHARE_PVSS_SLOT,
            &[U256::from(1), U256::from(1)],
        );
        let mut storage = HashMap::new();
        store_bytes(&mut storage, slot, &vec![0x11; NEOX_DKG_PVSS_LEN]);
        assert!(matches!(
            read_dkg_contribution_from_storage(
                1,
                1,
                DkgContributionKind::Share,
                DkgParameters::canonical(),
                |key| Ok(storage.get(&key).copied()),
            ),
            Err(DkgStorageError::IncompleteContribution { .. })
        ));
    }

    #[test]
    fn reads_settled_pvss_after_message_arrays_are_cleared() {
        for kind in [DkgContributionKind::Share, DkgContributionKind::Reshare] {
            let (pvss_mapping, _) = kind.slots();
            let pvss_slot =
                nested_uint_mapping_storage_key(pvss_mapping, &[U256::from(12), U256::from(5)]);
            let expected = vec![0x45; NEOX_DKG_PVSS_LEN];
            let mut storage = HashMap::new();
            store_bytes(&mut storage, pvss_slot, &expected);

            assert_eq!(
                read_dkg_pvss_from_storage(12, 5, kind, DkgParameters::canonical(), |key| Ok(
                    storage.get(&key).copied()
                ),)
                .unwrap(),
                Some(expected.into())
            );
            assert!(matches!(
                read_dkg_contribution_from_storage(
                    12,
                    5,
                    kind,
                    DkgParameters::canonical(),
                    |key| Ok(storage.get(&key).copied()),
                ),
                Err(DkgStorageError::IncompleteContribution { round: 12, sender_index: 5, .. })
            ));
        }
    }

    #[test]
    fn reads_recovery_messages_by_one_based_recipient() {
        let mut storage = HashMap::new();
        for sender_index in [1_u64, 4, 7] {
            let slot = nested_uint_mapping_storage_key(
                KEY_MANAGEMENT_RECOVER_MSGS_SLOT,
                &[U256::from(9), U256::from(sender_index), U256::from(1)],
            );
            store_bytes(&mut storage, slot, &[sender_index as u8; NEOX_DKG_MESSAGE_LEN]);
        }
        let messages =
            read_dkg_recovery_messages_from_storage(9, 2, DkgParameters::canonical(), |key| {
                Ok(storage.get(&key).copied())
            })
            .unwrap();
        assert_eq!(messages.iter().map(|item| item.sender_index).collect::<Vec<_>>(), [1, 4, 7]);
        assert!(messages.iter().all(|item| item.recipient_index == 2));
    }

    #[test]
    fn validates_aggregate_commitment_length_and_allocation_limits() {
        let slot =
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(5));
        let mut storage = HashMap::new();
        store_bytes(&mut storage, slot, &[0x33; G1_EIP2537_LEN]);
        assert_eq!(
            read_dkg_aggregated_commitment_from_storage(5, |key| {
                Ok(storage.get(&key).copied())
            })
            .unwrap()
            .unwrap(),
            [0x33; G1_EIP2537_LEN]
        );

        storage.insert(slot.into(), U256::from((G1_EIP2537_LEN + 1) * 2 + 1));
        assert!(matches!(
            read_dkg_aggregated_commitment_from_storage(5, |key| {
                Ok(storage.get(&key).copied())
            }),
            Err(DkgStorageError::BytesTooLarge { .. })
        ));
    }
}
