//! Asynchronous-operation-neutral DKG task execution and retry queue.

use crate::{DkgContractMethod, DkgReceiptState, DkgTaskPlan};
use alloy_primitives::{Address, Bytes, B256};
use reth_neox_evm::KEY_MANAGEMENT_PROXY_ADDRESS;
use std::collections::{hash_map::Entry, HashMap};
use thiserror::Error;

/// Stable identity of one validator task within a DKG round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DkgTaskId {
    /// `KeyManagement` round being prepared.
    pub round: u64,
    /// Contract method being submitted.
    pub method: DkgContractMethod,
    /// One-based sender index in the relevant validator set.
    pub sender_index: u64,
}

impl From<&DkgTaskPlan> for DkgTaskId {
    fn from(plan: &DkgTaskPlan) -> Self {
        Self { round: plan.round, method: plan.method, sender_index: plan.sender_index }
    }
}

/// External work requested by the execution queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgExecutorAction {
    /// Generate DKG material and, for ZK-v1, its Groth16 proof and ABI calldata.
    Prepare {
        /// Task to pass to the material generator.
        id: DkgTaskId,
        /// Immutable planning inputs.
        plan: DkgTaskPlan,
    },
    /// Sign and submit the already-prepared calldata to `KeyManagement`.
    Submit {
        /// Task whose transaction is being sent.
        id: DkgTaskId,
        /// Fixed Neo X system-contract destination.
        to: Address,
        /// Stable calldata reused by every retry.
        calldata: Bytes,
    },
    /// Query the canonical receipt after the three-block confirmation delay.
    CheckReceipt {
        /// Task whose most recent transaction is being checked.
        id: DkgTaskId,
        /// Most recently submitted transaction hash.
        transaction_hash: B256,
    },
    /// Report that the exclusive phase deadline elapsed.
    Expire {
        /// Task removed without confirmation.
        id: DkgTaskId,
    },
}

/// Observable result of completing one requested external action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgExecutorOutcome {
    /// Valid calldata is cached and ready to submit.
    Prepared {
        /// Prepared task.
        id: DkgTaskId,
    },
    /// Material generation or proof construction failed and will be retried on the next heartbeat.
    PreparationFailed {
        /// Failed task.
        id: DkgTaskId,
        /// Backend error text suitable for validator logs.
        error: String,
    },
    /// The transaction was accepted for submission.
    Submitted {
        /// Submitted task.
        id: DkgTaskId,
        /// New transaction hash.
        transaction_hash: B256,
    },
    /// Signing or transaction submission failed; cached calldata will be retried.
    SubmissionFailed {
        /// Failed task.
        id: DkgTaskId,
        /// Backend error text suitable for validator logs.
        error: String,
    },
    /// A missing or reverted receipt returned the task to its ready-to-submit state.
    RetryScheduled {
        /// Task to resubmit.
        id: DkgTaskId,
        /// Receipt state that triggered the retry.
        receipt: DkgReceiptState,
    },
    /// A canonical successful receipt completed and removed the task.
    Confirmed {
        /// Completed task.
        id: DkgTaskId,
        /// Confirmed transaction hash.
        transaction_hash: B256,
    },
    /// Receipt lookup failed and the same calldata will be resubmitted.
    ReceiptCheckFailed {
        /// Task whose receipt could not be read.
        id: DkgTaskId,
        /// Backend error text suitable for validator logs.
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DkgExecutionState {
    Unprepared,
    Preparing,
    Ready(Bytes),
    Submitting(Bytes),
    Submitted { calldata: Bytes, transaction_hash: B256, send_height: u64 },
    Checking { calldata: Bytes, transaction_hash: B256, send_height: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DkgExecutionTask {
    plan: DkgTaskPlan,
    state: DkgExecutionState,
}

/// Reliable per-validator execution queue driven by canonical-block heartbeats.
#[derive(Debug, Default)]
pub struct DkgTaskExecutor {
    tasks: HashMap<DkgTaskId, DkgExecutionTask>,
    order: Vec<DkgTaskId>,
}

impl DkgTaskExecutor {
    /// Adds newly planned tasks, returning the number not already queued.
    pub fn enqueue(&mut self, plans: impl IntoIterator<Item = DkgTaskPlan>) -> usize {
        let mut inserted = 0;
        for plan in plans {
            let id = DkgTaskId::from(&plan);
            if let Entry::Vacant(entry) = self.tasks.entry(id) {
                entry.insert(DkgExecutionTask { plan, state: DkgExecutionState::Unprepared });
                self.order.push(id);
                inserted += 1;
            }
        }
        inserted
    }

    /// Returns external actions that can start at `current_height` and marks them in flight.
    ///
    /// Call this again after recording a completed action to advance immediately from preparation
    /// to submission without waiting for another block.
    pub fn actions(&mut self, current_height: u64) -> Vec<DkgExecutorAction> {
        self.actions_with_preparation_limit(current_height, usize::MAX)
    }

    /// Returns actions while limiting the number of new external prover jobs.
    ///
    /// A validator should normally keep this at one: Neo X's seven-message proving key is large,
    /// and starting two proofs at once can exceed the node's memory budget. Other actions remain
    /// eligible, so a prepared task can still submit while another task is proving.
    pub fn actions_with_preparation_limit(
        &mut self,
        current_height: u64,
        max_preparations: usize,
    ) -> Vec<DkgExecutorAction> {
        let expired = self
            .order
            .iter()
            .filter_map(|id| {
                self.tasks
                    .get(id)
                    .is_some_and(|task| current_height >= task.plan.end_height)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        let mut actions =
            expired.iter().map(|id| DkgExecutorAction::Expire { id: *id }).collect::<Vec<_>>();
        for id in expired {
            self.tasks.remove(&id);
        }
        self.order.retain(|id| self.tasks.contains_key(id));

        let mut preparations = 0;
        for id in self.order.iter().copied() {
            let task = self.tasks.get_mut(&id).expect("execution order references queued task");
            match &task.state {
                DkgExecutionState::Unprepared => {
                    if preparations >= max_preparations {
                        continue
                    }
                    task.state = DkgExecutionState::Preparing;
                    preparations += 1;
                    actions.push(DkgExecutorAction::Prepare { id, plan: task.plan.clone() });
                }
                DkgExecutionState::Ready(calldata) => {
                    let calldata = calldata.clone();
                    task.state = DkgExecutionState::Submitting(calldata.clone());
                    actions.push(DkgExecutorAction::Submit {
                        id,
                        to: KEY_MANAGEMENT_PROXY_ADDRESS,
                        calldata,
                    });
                }
                DkgExecutionState::Submitted { calldata, transaction_hash, send_height }
                    if current_height >= send_height.saturating_add(3) =>
                {
                    let calldata = calldata.clone();
                    let transaction_hash = *transaction_hash;
                    let send_height = *send_height;
                    task.state =
                        DkgExecutionState::Checking { calldata, transaction_hash, send_height };
                    actions.push(DkgExecutorAction::CheckReceipt { id, transaction_hash });
                }
                DkgExecutionState::Preparing |
                DkgExecutionState::Submitting(_) |
                DkgExecutionState::Submitted { .. } |
                DkgExecutionState::Checking { .. } => {}
            }
        }
        actions
    }

    /// Records preparation or proof-generation completion.
    pub fn record_prepared(
        &mut self,
        id: DkgTaskId,
        result: Result<Bytes, String>,
    ) -> Result<DkgExecutorOutcome, DkgExecutorError> {
        let task = self.task_in_state(id, |state| matches!(state, DkgExecutionState::Preparing))?;
        match result {
            Ok(calldata) if calldata.len() >= 4 => {
                task.state = DkgExecutionState::Ready(calldata);
                Ok(DkgExecutorOutcome::Prepared { id })
            }
            Ok(calldata) => {
                task.state = DkgExecutionState::Unprepared;
                Err(DkgExecutorError::InvalidCalldata(calldata.len()))
            }
            Err(error) => {
                task.state = DkgExecutionState::Unprepared;
                Ok(DkgExecutorOutcome::PreparationFailed { id, error })
            }
        }
    }

    /// Records the result of signing and submitting cached calldata.
    pub fn record_submitted(
        &mut self,
        id: DkgTaskId,
        current_height: u64,
        result: Result<B256, String>,
    ) -> Result<DkgExecutorOutcome, DkgExecutorError> {
        let task =
            self.task_in_state(id, |state| matches!(state, DkgExecutionState::Submitting(_)))?;
        let DkgExecutionState::Submitting(calldata) = &task.state else { unreachable!() };
        let calldata = calldata.clone();
        match result {
            Ok(transaction_hash) => {
                task.state = DkgExecutionState::Submitted {
                    calldata,
                    transaction_hash,
                    send_height: current_height,
                };
                Ok(DkgExecutorOutcome::Submitted { id, transaction_hash })
            }
            Err(error) => {
                task.state = DkgExecutionState::Ready(calldata);
                Ok(DkgExecutorOutcome::SubmissionFailed { id, error })
            }
        }
    }

    /// Records a receipt lookup, completing or rescheduling the task.
    pub fn record_receipt(
        &mut self,
        id: DkgTaskId,
        result: Result<DkgReceiptState, String>,
    ) -> Result<DkgExecutorOutcome, DkgExecutorError> {
        let task =
            self.task_in_state(id, |state| matches!(state, DkgExecutionState::Checking { .. }))?;
        let DkgExecutionState::Checking { calldata, transaction_hash, .. } = &task.state else {
            unreachable!()
        };
        let calldata = calldata.clone();
        let transaction_hash = *transaction_hash;
        match result {
            Ok(DkgReceiptState::Succeeded) => {
                self.tasks.remove(&id);
                self.order.retain(|queued| *queued != id);
                Ok(DkgExecutorOutcome::Confirmed { id, transaction_hash })
            }
            Ok(receipt @ (DkgReceiptState::Missing | DkgReceiptState::Failed)) => {
                task.state = DkgExecutionState::Ready(calldata);
                Ok(DkgExecutorOutcome::RetryScheduled { id, receipt })
            }
            Err(error) => {
                task.state = DkgExecutionState::Ready(calldata);
                Ok(DkgExecutorOutcome::ReceiptCheckFailed { id, error })
            }
        }
    }

    /// Number of tasks still awaiting confirmation or expiry.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns whether no DKG tasks remain queued.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn task_in_state(
        &mut self,
        id: DkgTaskId,
        expected: impl FnOnce(&DkgExecutionState) -> bool,
    ) -> Result<&mut DkgExecutionTask, DkgExecutorError> {
        let task = self.tasks.get_mut(&id).ok_or(DkgExecutorError::UnknownTask(id))?;
        if !expected(&task.state) {
            return Err(DkgExecutorError::UnexpectedState(id))
        }
        Ok(task)
    }
}

/// Invalid completion callback supplied to the DKG execution queue.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgExecutorError {
    /// The task expired, completed, or was never enqueued.
    #[error("unknown Neo X DKG task {0:?}")]
    UnknownTask(DkgTaskId),
    /// The completion callback did not match the action currently in flight.
    #[error("unexpected completion state for Neo X DKG task {0:?}")]
    UnexpectedState(DkgTaskId),
    /// Prepared transaction data must include a four-byte selector.
    #[error("invalid Neo X DKG calldata length {0}")]
    InvalidCalldata(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(end_height: u64) -> DkgTaskPlan {
        DkgTaskPlan {
            round: 18,
            method: DkgContractMethod::Share,
            sender_index: 2,
            send_height: 10,
            end_height,
            recovery_indices: Vec::new(),
        }
    }

    #[test]
    fn prepares_submits_checks_and_retries_stable_calldata() {
        let mut executor = DkgTaskExecutor::default();
        assert_eq!(executor.enqueue([plan(20)]), 1);
        assert_eq!(executor.enqueue([plan(20)]), 0);
        let id = DkgTaskId::from(&plan(20));

        assert_eq!(executor.actions(10), vec![DkgExecutorAction::Prepare { id, plan: plan(20) }]);
        let calldata = Bytes::from_static(&[1, 2, 3, 4, 5]);
        assert_eq!(
            executor.record_prepared(id, Ok(calldata.clone())).unwrap(),
            DkgExecutorOutcome::Prepared { id }
        );
        assert_eq!(
            executor.actions(10),
            vec![DkgExecutorAction::Submit {
                id,
                to: KEY_MANAGEMENT_PROXY_ADDRESS,
                calldata: calldata.clone(),
            }]
        );
        let first_hash = B256::repeat_byte(0x11);
        executor.record_submitted(id, 10, Ok(first_hash)).unwrap();
        assert!(executor.actions(12).is_empty());
        assert_eq!(
            executor.actions(13),
            vec![DkgExecutorAction::CheckReceipt { id, transaction_hash: first_hash }]
        );
        assert_eq!(
            executor.record_receipt(id, Ok(DkgReceiptState::Failed)).unwrap(),
            DkgExecutorOutcome::RetryScheduled { id, receipt: DkgReceiptState::Failed }
        );
        assert_eq!(
            executor.actions(13),
            vec![DkgExecutorAction::Submit { id, to: KEY_MANAGEMENT_PROXY_ADDRESS, calldata }]
        );
        let second_hash = B256::repeat_byte(0x22);
        executor.record_submitted(id, 13, Ok(second_hash)).unwrap();
        assert_eq!(
            executor.actions(16),
            vec![DkgExecutorAction::CheckReceipt { id, transaction_hash: second_hash }]
        );
        assert_eq!(
            executor.record_receipt(id, Ok(DkgReceiptState::Succeeded)).unwrap(),
            DkgExecutorOutcome::Confirmed { id, transaction_hash: second_hash }
        );
        assert!(executor.is_empty());
    }

    #[test]
    fn retries_each_failed_stage_until_deadline() {
        let mut executor = DkgTaskExecutor::default();
        executor.enqueue([plan(15)]);
        let id = DkgTaskId::from(&plan(15));
        executor.actions(10);
        assert_eq!(
            executor.record_prepared(id, Err("proof failed".into())).unwrap(),
            DkgExecutorOutcome::PreparationFailed { id, error: "proof failed".into() }
        );
        assert!(matches!(executor.actions(11)[0], DkgExecutorAction::Prepare { .. }));
        executor.record_prepared(id, Ok(Bytes::from_static(&[1, 2, 3, 4]))).unwrap();
        executor.actions(11);
        assert_eq!(
            executor.record_submitted(id, 11, Err("nonce busy".into())).unwrap(),
            DkgExecutorOutcome::SubmissionFailed { id, error: "nonce busy".into() }
        );
        assert!(matches!(executor.actions(12)[0], DkgExecutorAction::Submit { .. }));
        assert_eq!(executor.actions(15), vec![DkgExecutorAction::Expire { id }]);
        assert!(executor.is_empty());
    }

    #[test]
    fn rejects_out_of_order_or_malformed_completions() {
        let mut executor = DkgTaskExecutor::default();
        executor.enqueue([plan(20)]);
        let id = DkgTaskId::from(&plan(20));
        assert_eq!(
            executor.record_submitted(id, 10, Ok(B256::ZERO)),
            Err(DkgExecutorError::UnexpectedState(id))
        );
        executor.actions(10);
        assert_eq!(
            executor.record_prepared(id, Ok(Bytes::from_static(&[1, 2, 3]))),
            Err(DkgExecutorError::InvalidCalldata(3))
        );
        assert_eq!(executor.len(), 1);
    }

    #[test]
    fn preserves_planner_order_for_shared_prover_setup() {
        let mut reshare = plan(20);
        reshare.method = DkgContractMethod::Reshare;
        reshare.sender_index = 3;
        let share = plan(20);
        let reshare_id = DkgTaskId::from(&reshare);
        let share_id = DkgTaskId::from(&share);
        let mut executor = DkgTaskExecutor::default();
        executor.enqueue([reshare.clone(), share.clone()]);
        assert_eq!(
            executor.actions(10),
            vec![
                DkgExecutorAction::Prepare { id: reshare_id, plan: reshare },
                DkgExecutorAction::Prepare { id: share_id, plan: share },
            ]
        );
    }

    #[test]
    fn limits_external_preparation_jobs_without_reordering_tasks() {
        let mut first = plan(20);
        first.sender_index = 3;
        let second = plan(20);
        let first_id = DkgTaskId::from(&first);
        let second_id = DkgTaskId::from(&second);
        let mut executor = DkgTaskExecutor::default();
        executor.enqueue([first.clone(), second.clone()]);

        assert_eq!(
            executor.actions_with_preparation_limit(10, 1),
            vec![DkgExecutorAction::Prepare { id: first_id, plan: first.clone() }]
        );
        executor.record_prepared(first_id, Err("proof still running".into())).unwrap();
        assert_eq!(
            executor.actions_with_preparation_limit(11, 1),
            vec![DkgExecutorAction::Prepare { id: first_id, plan: first }]
        );

        executor.record_prepared(first_id, Ok(Bytes::from_static(&[1, 2, 3, 4]))).unwrap();
        assert_eq!(
            executor.actions_with_preparation_limit(11, 1),
            vec![
                DkgExecutorAction::Submit {
                    id: first_id,
                    to: KEY_MANAGEMENT_PROXY_ADDRESS,
                    calldata: Bytes::from_static(&[1, 2, 3, 4]),
                },
                DkgExecutorAction::Prepare { id: second_id, plan: second },
            ]
        );
    }
}
