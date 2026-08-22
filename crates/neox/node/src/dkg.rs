//! Canonical `KeyManagement` DKG state discovery.

use alloy_primitives::{keccak256, B256, U256};
use reth_neox_antimev::{
    global_public_key_from_commitment, DkgParameters, G1_COMPRESSED_LEN, G1_EIP2537_LEN,
};
use reth_neox_evm::{
    uint_mapping_storage_key, GOVERNANCE_CURRENT_EPOCH_START_HEIGHT_SLOT,
    GOVERNANCE_EPOCH_DURATION_SLOT, GOVERNANCE_PROXY_ADDRESS,
    GOVERNANCE_SHARE_PERIOD_DURATION_SLOT, KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT,
    KEY_MANAGEMENT_PROXY_ADDRESS, KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
};
use reth_provider::StateProvider;
use thiserror::Error;

const MAX_SOLIDITY_BYTES_LEN: usize = 4 * 1024 * 1024;

/// Height-driven phase of one validator DKG epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgPhase {
    /// Normal consensus before the two DKG share periods begin.
    Idle,
    /// New and incumbent validators publish share/reshare material.
    Share,
    /// Incumbent validators publish recovery material for missing new-validator shares.
    Recover,
    /// Recovered validators publish their final reshared contribution.
    ReshareRecover,
    /// The epoch target height has been reached and the new aggregate key must be activated.
    EpochChange,
}

/// Canonical DKG checkpoint heights derived from Governance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgSchedule {
    /// Height at which the current Governance epoch began.
    pub epoch_start: u64,
    /// First height at which share and reshare transactions may be sent.
    pub share_start: u64,
    /// First height at which recovery transactions may be sent.
    pub recover_start: u64,
    /// First height at which recovered validators may reshare.
    pub recover_check: u64,
    /// Height at which the new DKG round becomes active.
    pub target: u64,
}

impl DkgSchedule {
    /// Builds the same four DKG checkpoints as Neo X Geth.
    pub fn new(
        epoch_start: u64,
        epoch_duration: u64,
        share_period_duration: u64,
    ) -> Result<Self, DkgScheduleError> {
        if share_period_duration == 0 {
            return Err(DkgScheduleError::EmptySharePeriod)
        }
        let two_share_periods =
            share_period_duration.checked_mul(2).ok_or(DkgScheduleError::HeightOverflow)?;
        if epoch_duration < two_share_periods {
            return Err(DkgScheduleError::SharePeriodsExceedEpoch {
                epoch_duration,
                share_period_duration,
            })
        }
        let target =
            epoch_start.checked_add(epoch_duration).ok_or(DkgScheduleError::HeightOverflow)?;
        let share_start = target - two_share_periods;
        let recover_start = share_start + share_period_duration;
        let recover_check = recover_start + share_period_duration / 2;
        Ok(Self { epoch_start, share_start, recover_start, recover_check, target })
    }

    /// Returns the active DKG phase at `height`.
    pub const fn phase_at(&self, height: u64) -> DkgPhase {
        if height < self.share_start {
            DkgPhase::Idle
        } else if height < self.recover_start {
            DkgPhase::Share
        } else if height < self.recover_check {
            DkgPhase::Recover
        } else if height < self.target {
            DkgPhase::ReshareRecover
        } else {
            DkgPhase::EpochChange
        }
    }
}

/// Reads the live Governance epoch timing used by the validator DKG task engine.
pub fn read_dkg_schedule(state: &dyn StateProvider) -> Result<DkgSchedule, DkgScheduleStateError> {
    read_dkg_schedule_from_storage(|key| {
        state
            .storage(GOVERNANCE_PROXY_ADDRESS, key)
            .map_err(|error| DkgScheduleStateError::Provider(error.to_string()))
    })
}

/// Reads all three schedule inputs live from `Governance`.
///
/// Geth recomputes the checkpoints from live `epochDuration` and `sharePeriodDuration` every block
/// but keeps `EpochStartHeight` pinned in its DKG snapshot. The two are nonetheless equal at every
/// block: `Governance.onPersistV2` only ever assigns `currentEpochStartHeight = block.number`, and
/// only once `block.number >= currentEpochStartHeight + epochDuration`, so the value cannot move
/// mid-epoch; Geth in turn re-reads it into the snapshot at startup and after every epoch reset. A
/// shortened `epochDuration` advances the epoch and satisfies Geth's reset condition at the same
/// height, so no live read can observe a start height Geth's snapshot has not yet adopted.
pub(crate) fn read_dkg_schedule_from_storage(
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgScheduleStateError>,
) -> Result<DkgSchedule, DkgScheduleStateError> {
    let mut read = |slot, field| {
        let value = storage(U256::from(slot).into())?.unwrap_or_default();
        u64::try_from(value).map_err(|_| DkgScheduleStateError::ValueOverflow { field })
    };
    DkgSchedule::new(
        read(GOVERNANCE_CURRENT_EPOCH_START_HEIGHT_SLOT, "currentEpochStartHeight")?,
        read(GOVERNANCE_EPOCH_DURATION_SLOT, "epochDuration")?,
        read(GOVERNANCE_SHARE_PERIOD_DURATION_SLOT, "sharePeriodDuration")?,
    )
    .map_err(DkgScheduleStateError::InvalidSchedule)
}

/// Receipt state observed by the DKG transaction watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgReceiptState {
    /// The transaction is not yet canonical or its receipt request failed.
    Missing,
    /// The transaction executed successfully.
    Succeeded,
    /// The transaction was included but reverted.
    Failed,
}

/// Next deterministic action for one submitted DKG contract transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgTaskAction {
    /// Wait until the three-block confirmation delay has elapsed.
    Wait,
    /// Query the transaction receipt before deciding whether to retry.
    CheckReceipt,
    /// Resubmit the same method and proof parameters.
    Retry,
    /// Stop retrying because the phase deadline was reached.
    Expire,
    /// Remove the task after successful canonical execution.
    Confirm,
}

/// Confirmation and retry metadata for a DKG contract transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgTaskWatch {
    /// Height of the most recent submission attempt.
    pub send_height: u64,
    /// Exclusive phase deadline after which the task must not be sent.
    pub end_height: u64,
    /// Whether the most recent submission returned a transaction hash.
    pub submitted: bool,
}

impl DkgTaskWatch {
    /// Selects the next watcher action using Neo X's three-block confirmation delay.
    pub const fn action(
        &self,
        current_height: u64,
        receipt: Option<DkgReceiptState>,
    ) -> DkgTaskAction {
        if current_height >= self.end_height {
            return DkgTaskAction::Expire
        }
        if !self.submitted {
            return DkgTaskAction::Retry
        }
        if current_height < self.send_height.saturating_add(3) {
            return DkgTaskAction::Wait
        }
        match receipt {
            None => DkgTaskAction::CheckReceipt,
            Some(DkgReceiptState::Succeeded) => DkgTaskAction::Confirm,
            Some(DkgReceiptState::Missing | DkgReceiptState::Failed) => DkgTaskAction::Retry,
        }
    }
}

/// Invalid Governance DKG timing configuration.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DkgScheduleError {
    /// A zero share period cannot provide a transaction window.
    #[error("Neo X DKG share period duration must be non-zero")]
    EmptySharePeriod,
    /// The two share periods do not fit before the epoch target.
    #[error(
        "Neo X DKG share periods exceed epoch duration: epoch {epoch_duration}, share {share_period_duration}"
    )]
    SharePeriodsExceedEpoch {
        /// Governance epoch duration.
        epoch_duration: u64,
        /// Length of one share period.
        share_period_duration: u64,
    },
    /// A configured height calculation overflowed `u64`.
    #[error("Neo X DKG checkpoint height overflow")]
    HeightOverflow,
}

/// Failure to discover canonical Governance DKG timing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgScheduleStateError {
    /// Canonical state could not be read.
    #[error("failed to read Neo X Governance DKG schedule: {0}")]
    Provider(String),
    /// A Governance scalar does not fit the protocol's 64-bit height representation.
    #[error("Neo X Governance {field} exceeds u64")]
    ValueOverflow {
        /// Solidity field whose value overflowed.
        field: &'static str,
    },
    /// Governance supplied an impossible relationship between epoch and share periods.
    #[error(transparent)]
    InvalidSchedule(DkgScheduleError),
}

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
    /// Runtime DKG dimensions used to derive and consume the keys.
    pub parameters: DkgParameters,
    /// Latest successful round selected by `roundNumber`.
    pub current: DkgPublicKey,
    /// Prior successful round, when it still exists.
    pub previous: Option<DkgPublicKey>,
}

/// Reads `KeyManagement`'s current and previous global keys directly from canonical storage.
pub fn read_dkg_state(state: &dyn StateProvider) -> Result<DkgState, DkgStateError> {
    read_dkg_state_with_parameters(state, DkgParameters::canonical())
}

/// Reads DKG state using a runtime-sized Geth committee.
pub fn read_dkg_state_with_parameters(
    state: &dyn StateProvider,
    parameters: DkgParameters,
) -> Result<DkgState, DkgStateError> {
    read_dkg_state_from_storage(parameters, |key| {
        state
            .storage(KEY_MANAGEMENT_PROXY_ADDRESS, key)
            .map_err(|error| DkgStateError::Provider(error.to_string()))
    })
}

pub(crate) fn read_dkg_state_from_storage(
    parameters: DkgParameters,
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
) -> Result<DkgState, DkgStateError> {
    let round = storage(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into())?.unwrap_or_default();
    let round = u64::try_from(round).map_err(|_| DkgStateError::RoundOverflow)?;
    if round == 0 {
        return Err(DkgStateError::MissingCurrentRound)
    }
    let current = read_public_key(&mut storage, round, parameters)?
        .ok_or(DkgStateError::MissingCommitment { round })?;
    let previous =
        if round > 1 { read_public_key(&mut storage, round - 1, parameters)? } else { None };
    Ok(DkgState { parameters, current, previous })
}

fn read_public_key(
    storage: &mut impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
    round: u64,
    parameters: DkgParameters,
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
    let global_public_key = global_public_key_from_commitment(&commitment, parameters.scaler())
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
    fn reads_live_mainnet_governance_dkg_schedule() {
        let storage: HashMap<B256, U256> = HashMap::from([
            (U256::from(GOVERNANCE_CURRENT_EPOCH_START_HEIGHT_SLOT).into(), U256::from(7_136_640)),
            (U256::from(GOVERNANCE_EPOCH_DURATION_SLOT).into(), U256::from(60_480)),
            (U256::from(GOVERNANCE_SHARE_PERIOD_DURATION_SLOT).into(), U256::from(2_880)),
        ]);
        let schedule =
            read_dkg_schedule_from_storage(|key| Ok(storage.get(&key).copied())).unwrap();
        assert_eq!(schedule.epoch_start, 7_136_640);
        assert_eq!(schedule.share_start, 7_191_360);
        assert_eq!(schedule.recover_start, 7_194_240);
        assert_eq!(schedule.recover_check, 7_195_680);
        assert_eq!(schedule.target, 7_197_120);
    }

    #[test]
    fn dkg_schedule_matches_geth_checkpoint_boundaries() {
        let schedule = DkgSchedule::new(1_000, 600, 100).unwrap();
        assert_eq!(schedule.share_start, 1_400);
        assert_eq!(schedule.recover_start, 1_500);
        assert_eq!(schedule.recover_check, 1_550);
        assert_eq!(schedule.target, 1_600);
        assert_eq!(schedule.phase_at(1_399), DkgPhase::Idle);
        assert_eq!(schedule.phase_at(1_400), DkgPhase::Share);
        assert_eq!(schedule.phase_at(1_500), DkgPhase::Recover);
        assert_eq!(schedule.phase_at(1_550), DkgPhase::ReshareRecover);
        assert_eq!(schedule.phase_at(1_600), DkgPhase::EpochChange);
    }

    #[test]
    fn dkg_schedule_rejects_impossible_governance_timing() {
        assert_eq!(DkgSchedule::new(0, 100, 0), Err(DkgScheduleError::EmptySharePeriod));
        assert!(matches!(
            DkgSchedule::new(0, 100, 51),
            Err(DkgScheduleError::SharePeriodsExceedEpoch { .. })
        ));
        assert_eq!(DkgSchedule::new(u64::MAX, 2, 1), Err(DkgScheduleError::HeightOverflow));
    }

    #[test]
    fn dkg_task_watcher_waits_checks_retries_and_expires() {
        let submitted = DkgTaskWatch { send_height: 10, end_height: 20, submitted: true };
        assert_eq!(submitted.action(12, None), DkgTaskAction::Wait);
        assert_eq!(submitted.action(13, None), DkgTaskAction::CheckReceipt);
        assert_eq!(submitted.action(13, Some(DkgReceiptState::Missing)), DkgTaskAction::Retry);
        assert_eq!(submitted.action(13, Some(DkgReceiptState::Failed)), DkgTaskAction::Retry);
        assert_eq!(submitted.action(13, Some(DkgReceiptState::Succeeded)), DkgTaskAction::Confirm);
        assert_eq!(submitted.action(20, None), DkgTaskAction::Expire);

        let unsent = DkgTaskWatch { submitted: false, ..submitted };
        assert_eq!(unsent.action(10, None), DkgTaskAction::Retry);
    }

    /// Geth's `dkgTaskWatcher` reads a receipt only when it observes the task at a gap of exactly
    /// three blocks, and marks every other submitted task `ConfirmedSuccess` without checking. The
    /// gap depends on how long Groth16 proving took, so a reverted contribution is normally
    /// abandoned. This client keeps checking past three. See `docs/neox/README.md`.
    #[test]
    fn checks_receipts_the_geth_oracle_confirms_blindly() {
        let watch = DkgTaskWatch { send_height: 10, end_height: 40, submitted: true };
        for gap in 3..=10 {
            assert_eq!(watch.action(10 + gap, None), DkgTaskAction::CheckReceipt);
            assert_eq!(
                watch.action(10 + gap, Some(DkgReceiptState::Failed)),
                DkgTaskAction::Retry,
                "reverted contribution must be resubmitted at gap {gap}"
            );
        }
    }

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

        let state = read_dkg_state_from_storage(DkgParameters::canonical(), |key| {
            Ok(storage.get(&key).copied())
        })
        .unwrap();
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
