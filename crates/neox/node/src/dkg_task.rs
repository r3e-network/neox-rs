//! Height-driven planning for validator DKG contract transactions.

use crate::{DkgContractMethod, DkgSchedule, DkgTaskWatch};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use thiserror::Error;

/// Canonical-chain inputs needed to plan one validator's DKG work at a block height.
#[derive(Debug, Clone, Copy)]
pub struct DkgTaskContext<'a> {
    /// Current Governance DKG checkpoint schedule.
    pub schedule: DkgSchedule,
    /// Canonical head height that triggered planning.
    pub current_height: u64,
    /// `KeyManagement` round being prepared, equal to the current on-chain round plus one.
    pub next_round: u64,
    /// One-based position of this validator in the current consensus set.
    pub current_index: Option<u64>,
    /// One-based position of this validator in the pending consensus set.
    pub pending_index: Option<u64>,
    /// Whether `KeyManagement.isShareReady()` succeeded at the recover checkpoint.
    pub share_ready: bool,
    /// One-based pending-validator indices returned by `indexCurrentNeedRecovering()`.
    pub recovery_indices: &'a [u64],
}

/// One transaction that should be prepared, proved, and sent before its deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgTaskPlan {
    /// `KeyManagement` method to call.
    pub method: DkgContractMethod,
    /// One-based sender position in the current or pending validator set, depending on the method.
    pub sender_index: u64,
    /// Height at which this attempt was planned.
    pub send_height: u64,
    /// Exclusive phase deadline after which the call must not be submitted.
    pub end_height: u64,
    /// Missing pending-validator indices used only by a `recover` task.
    pub recovery_indices: Vec<u64>,
}

impl DkgTaskPlan {
    /// Creates watcher metadata for the task before its first submission attempt.
    pub const fn watch(&self) -> DkgTaskWatch {
        DkgTaskWatch {
            send_height: self.send_height,
            end_height: self.end_height,
            submitted: false,
        }
    }
}

/// Per-epoch checkpoint state preventing duplicate proof generation and submissions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DkgTaskPlanner {
    epoch: Option<(u64, u64)>,
    share_tasked: bool,
    recover_tasked: bool,
    reshare_recovered_tasked: bool,
    recovering: bool,
    recovery_indices: Vec<u64>,
}

impl DkgTaskPlanner {
    /// Plans all newly reached checkpoints in the same order as Neo X Geth.
    ///
    /// This method may cross more than one checkpoint after downtime. Tasks whose exclusive
    /// deadline has already passed are marked handled but are not emitted.
    pub fn take_tasks(
        &mut self,
        context: DkgTaskContext<'_>,
    ) -> Result<Vec<DkgTaskPlan>, DkgTaskPlanError> {
        validate_context(&context)?;
        let epoch = (context.schedule.epoch_start, context.next_round);
        if self.epoch != Some(epoch) {
            *self = Self { epoch: Some(epoch), ..Self::default() };
        }

        let mut tasks = Vec::with_capacity(2);
        if context.current_height >= context.schedule.target {
            return Ok(tasks)
        }

        if context.current_height >= context.schedule.share_start && !self.share_tasked {
            self.share_tasked = true;
            if context.current_height < context.schedule.recover_start {
                if context.next_round > 1 &&
                    let Some(sender_index) = context.current_index
                {
                    tasks.push(DkgTaskPlan {
                        method: DkgContractMethod::Reshare,
                        sender_index,
                        send_height: context.current_height,
                        end_height: context.schedule.recover_start,
                        recovery_indices: Vec::new(),
                    });
                }
                if let Some(sender_index) = context.pending_index {
                    tasks.push(DkgTaskPlan {
                        method: DkgContractMethod::Share,
                        sender_index,
                        send_height: context.current_height,
                        end_height: context.schedule.recover_start,
                        recovery_indices: Vec::new(),
                    });
                }
            }
        }

        if context.current_height >= context.schedule.recover_start && !self.recover_tasked {
            self.recover_tasked = true;
            if context.share_ready && (1..=2).contains(&context.recovery_indices.len()) {
                self.recovering = true;
                self.recovery_indices = context.recovery_indices.to_vec();
                if context.current_height < context.schedule.recover_check &&
                    let Some(sender_index) = context.current_index
                {
                    tasks.push(DkgTaskPlan {
                        method: DkgContractMethod::Recover,
                        sender_index,
                        send_height: context.current_height,
                        end_height: context.schedule.recover_check,
                        recovery_indices: self.recovery_indices.clone(),
                    });
                }
            }
        }

        if self.recovering &&
            context.current_height >= context.schedule.recover_check &&
            !self.reshare_recovered_tasked
        {
            self.reshare_recovered_tasked = true;
            if context.current_height < context.schedule.target &&
                let Some(sender_index) = context.pending_index &&
                self.recovery_indices.contains(&sender_index)
            {
                tasks.push(DkgTaskPlan {
                    method: DkgContractMethod::ReshareRecovered,
                    sender_index,
                    send_height: context.current_height,
                    end_height: context.schedule.target,
                    recovery_indices: Vec::new(),
                });
            }
        }

        Ok(tasks)
    }

    /// Returns whether this epoch entered the recovery path for one or two missing members.
    pub const fn is_recovering(&self) -> bool {
        self.recovering
    }

    /// Returns the recovery indices captured at the recover checkpoint.
    pub fn recovery_indices(&self) -> &[u64] {
        &self.recovery_indices
    }
}

fn validate_context(context: &DkgTaskContext<'_>) -> Result<(), DkgTaskPlanError> {
    if context.next_round == 0 {
        return Err(DkgTaskPlanError::InvalidRound)
    }
    for (set, index) in [("current", context.current_index), ("pending", context.pending_index)] {
        if let Some(index) = index &&
            (index == 0 || index > NEOX_VALIDATOR_COUNT as u64)
        {
            return Err(DkgTaskPlanError::InvalidParticipantIndex { set, index })
        }
    }
    for (position, &index) in context.recovery_indices.iter().enumerate() {
        if index == 0 || index > NEOX_VALIDATOR_COUNT as u64 {
            return Err(DkgTaskPlanError::InvalidRecoveryIndex(index))
        }
        if context.recovery_indices[..position].contains(&index) {
            return Err(DkgTaskPlanError::DuplicateRecoveryIndex(index))
        }
    }
    Ok(())
}

/// Invalid Governance or `KeyManagement` values supplied to the task planner.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgTaskPlanError {
    /// Round zero represents no active DKG and cannot be planned.
    #[error("Neo X DKG next round must be non-zero")]
    InvalidRound,
    /// Validator set positions are one-based and bounded by the Neo X validator count.
    #[error("invalid Neo X DKG {set} participant index {index}")]
    InvalidParticipantIndex {
        /// Validator set that contained the bad index.
        set: &'static str,
        /// Invalid one-based index.
        index: u64,
    },
    /// Recovery positions are one-based and bounded by the pending validator count.
    #[error("invalid Neo X DKG recovery index {0}")]
    InvalidRecoveryIndex(u64),
    /// Each missing pending validator may appear only once.
    #[error("duplicate Neo X DKG recovery index {0}")]
    DuplicateRecoveryIndex(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schedule(epoch_start: u64) -> DkgSchedule {
        DkgSchedule::new(epoch_start, 600, 100).unwrap()
    }

    fn context<'a>(
        schedule: DkgSchedule,
        current_height: u64,
        recovery_indices: &'a [u64],
    ) -> DkgTaskContext<'a> {
        DkgTaskContext {
            schedule,
            current_height,
            next_round: 2,
            current_index: Some(3),
            pending_index: Some(2),
            share_ready: false,
            recovery_indices,
        }
    }

    #[test]
    fn plans_reshare_before_share_once_per_epoch() {
        let schedule = test_schedule(1_000);
        let mut planner = DkgTaskPlanner::default();
        let tasks = planner.take_tasks(context(schedule, schedule.share_start, &[])).unwrap();
        assert_eq!(
            tasks.iter().map(|task| task.method).collect::<Vec<_>>(),
            vec![DkgContractMethod::Reshare, DkgContractMethod::Share]
        );
        assert_eq!(tasks[0].sender_index, 3);
        assert_eq!(tasks[1].sender_index, 2);
        assert_eq!(tasks[0].end_height, schedule.recover_start);
        assert!(planner
            .take_tasks(context(schedule, schedule.share_start + 1, &[]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn first_round_shares_without_resharing() {
        let schedule = test_schedule(1_000);
        let mut input = context(schedule, schedule.share_start, &[]);
        input.next_round = 1;
        let tasks = DkgTaskPlanner::default().take_tasks(input).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].method, DkgContractMethod::Share);
    }

    #[test]
    fn plans_recover_then_only_the_missing_pending_member_reshare() {
        let schedule = test_schedule(1_000);
        let missing = [2, 7];
        let mut planner = DkgTaskPlanner::default();
        let mut recover = context(schedule, schedule.recover_start, &missing);
        recover.share_ready = true;
        let tasks = planner.take_tasks(recover).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].method, DkgContractMethod::Recover);
        assert_eq!(tasks[0].recovery_indices, missing);
        assert_eq!(tasks[0].end_height, schedule.recover_check);
        assert!(planner.is_recovering());

        let tasks = planner.take_tasks(context(schedule, schedule.recover_check, &[])).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].method, DkgContractMethod::ReshareRecovered);
        assert_eq!(tasks[0].sender_index, 2);
        assert_eq!(tasks[0].end_height, schedule.target);
    }

    #[test]
    fn catches_up_checkpoints_without_emitting_expired_tasks() {
        let schedule = test_schedule(1_000);
        let missing = [2];
        let mut input = context(schedule, schedule.recover_check, &missing);
        input.share_ready = true;
        let mut planner = DkgTaskPlanner::default();
        let tasks = planner.take_tasks(input).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].method, DkgContractMethod::ReshareRecovered);

        let mut next_epoch = context(test_schedule(1_600), 2_000, &[]);
        next_epoch.next_round = 3;
        let tasks = planner.take_tasks(next_epoch).unwrap();
        assert_eq!(
            tasks.iter().map(|task| task.method).collect::<Vec<_>>(),
            vec![DkgContractMethod::Reshare, DkgContractMethod::Share]
        );
    }

    #[test]
    fn skips_unrecoverable_or_expired_rounds() {
        let schedule = test_schedule(1_000);
        let missing = [1, 2, 3];
        let mut input = context(schedule, schedule.recover_start, &missing);
        input.share_ready = true;
        let mut planner = DkgTaskPlanner::default();
        assert!(planner.take_tasks(input).unwrap().is_empty());
        assert!(!planner.is_recovering());

        let mut target = context(schedule, schedule.target, &[]);
        target.share_ready = true;
        assert!(DkgTaskPlanner::default().take_tasks(target).unwrap().is_empty());
    }

    #[test]
    fn rejects_invalid_one_based_indices() {
        let schedule = test_schedule(1_000);
        let mut input = context(schedule, schedule.share_start, &[]);
        input.pending_index = Some(0);
        assert_eq!(
            DkgTaskPlanner::default().take_tasks(input),
            Err(DkgTaskPlanError::InvalidParticipantIndex { set: "pending", index: 0 })
        );

        let duplicate = [2, 2];
        let input = context(schedule, schedule.recover_start, &duplicate);
        assert_eq!(
            DkgTaskPlanner::default().take_tasks(input),
            Err(DkgTaskPlanError::DuplicateRecoveryIndex(2))
        );
    }
}
