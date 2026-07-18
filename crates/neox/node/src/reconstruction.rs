//! Final Anti-MEV block reconstruction from a verified outer pre-block.

use crate::{AntiMevEnvelopeResolution, AntiMevFallbackReason, AntiMevProposal, VerifiedProposal};
use alloy_consensus::{
    proofs::{calculate_receipt_root, calculate_transaction_root},
    transaction::Recovered,
    Transaction as _, TxReceipt,
};
use alloy_primitives::{Address, B256};
use reth_evm::{execute::BlockExecutor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_neox_evm::NeoXEvmConfig;
use reth_neox_network::BeaconBlobSidecar;
use reth_primitives_traits::{logs_bloom, RecoveredBlock};
use reth_provider::StateProviderFactory;
use reth_revm::{
    database::StateProviderDatabase,
    db::{states::bundle_state::BundleRetention, State},
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Why an outer Envelope was retained instead of its decrypted transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiMevReplacementFallback {
    /// Decryption or static replacement validation selected the outer transaction.
    Static(AntiMevFallbackReason),
    /// The statically valid inner transaction failed sequential execution.
    Execution(String),
}

/// Final deterministic disposition of one outer pre-block transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiMevTransactionDecision {
    /// An ordinary transaction remained in the final block.
    IncludedOriginal {
        /// Position in the primary's outer pre-block.
        transaction_index: usize,
    },
    /// A valid decrypted transaction replaced its Envelope.
    IncludedDecrypted {
        /// Position of the replaced Envelope.
        transaction_index: usize,
    },
    /// The original Envelope executed after its replacement was rejected.
    IncludedFallback {
        /// Position of the retained Envelope.
        transaction_index: usize,
        /// Reason the replacement was not used.
        reason: AntiMevReplacementFallback,
    },
    /// Neither the selected transaction nor its required fallback could be included.
    Dropped {
        /// Position in the outer pre-block.
        transaction_index: usize,
        /// Deterministic sequential-execution failure.
        reason: AntiMevDropReason,
    },
}

/// Reason an outer pre-block transaction disappeared from the reconstructed final block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiMevDropReason {
    /// An earlier transaction from this sender already failed both inclusion paths.
    PriorSenderFailure,
    /// An ordinary outer transaction could no longer execute against reconstructed state.
    OuterExecution(String),
    /// A rejected replacement was followed by an outer Envelope that also failed execution.
    FallbackExecution {
        /// Why the replacement path was rejected.
        replacement: AntiMevReplacementFallback,
        /// Failure produced by the original outer transaction.
        outer_error: String,
    },
}

/// A final execution-ready proposal and its auditable per-transaction decisions.
#[derive(Debug)]
pub struct AntiMevReconstruction {
    /// Proposal with final transactions, execution roots, receipts, gas, and post-state.
    pub proposal: VerifiedProposal,
    /// Decisions in original outer transaction order.
    pub decisions: Vec<AntiMevTransactionDecision>,
}

/// Fatal reconstruction error. Individual transaction failures are deterministic decisions.
#[derive(Debug, Error)]
pub enum AntiMevReconstructionError {
    /// The supplied verified proposal did not originate from the Anti-MEV pre-block path.
    #[error("verified proposal is missing Anti-MEV Envelope metadata")]
    MissingMetadata,
    /// Resolution count must exactly match the valid Envelope set.
    #[error("Anti-MEV resolution count mismatch: expected {expected}, got {actual}")]
    ResolutionCount {
        /// Valid Envelope count.
        expected: usize,
        /// Supplied resolution count.
        actual: usize,
    },
    /// Valid Envelope metadata cannot contain the same outer index twice.
    #[error("duplicate Anti-MEV Envelope metadata at transaction {0}")]
    DuplicateEnvelope(usize),
    /// Two resolution records attempted to replace the same outer transaction.
    #[error("duplicate Anti-MEV resolution at transaction {0}")]
    DuplicateResolution(usize),
    /// A resolution referenced a transaction that was not a valid Envelope.
    #[error("unexpected Anti-MEV resolution at transaction {0}")]
    UnexpectedResolution(usize),
    /// Canonical parent state could not be opened or hashed.
    #[error("failed to access Neo X parent state: {0}")]
    Provider(String),
    /// Block-level pre- or post-execution changes failed.
    #[error("failed to reconstruct Neo X Anti-MEV block: {0}")]
    Execution(String),
    /// Verified proposal sidecars must cover every outer blob transaction exactly once.
    #[error("Neo X blob sidecar count mismatch: expected {expected}, got {actual}")]
    BlobSidecarCount {
        /// Number of blob transactions in the verified outer pre-block.
        expected: usize,
        /// Number of supplied transaction sidecars.
        actual: usize,
    },
    /// A blob transaction retained by reconstruction lost its authenticated sidecar.
    #[error("missing Neo X blob sidecar for retained transaction {0}")]
    MissingBlobSidecar(B256),
}

/// Re-executes a verified pre-block from its canonical parent and builds the final Anti-MEV block.
///
/// Transaction execution errors are not fatal. A failed decrypted transaction is retried as its
/// original Envelope; if that also fails, later transactions from the same sender are dropped.
pub fn reconstruct_antimev_proposal<Provider>(
    mut proposal: VerifiedProposal,
    resolutions: Vec<AntiMevEnvelopeResolution>,
    provider: &Provider,
    evm_config: &NeoXEvmConfig,
) -> Result<AntiMevReconstruction, AntiMevReconstructionError>
where
    Provider: StateProviderFactory,
{
    let anti_mev = proposal.anti_mev.as_ref().ok_or(AntiMevReconstructionError::MissingMetadata)?;
    let resolutions = index_resolutions(anti_mev, resolutions)?;
    let state_provider = provider
        .state_by_block_hash(proposal.parent_state_hash)
        .map_err(|error| AntiMevReconstructionError::Provider(error.to_string()))?;
    let outer_transactions = proposal.block.body().transactions.clone();
    let outer_senders = proposal.block.senders().to_vec();
    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(state_provider.as_ref()))
        .with_bundle_update()
        .build();

    let (sequence, result) = {
        let mut executor = evm_config
            .executor_for_block(&mut state, proposal.block.sealed_block())
            .unwrap_or_else(|never| match never {});
        executor
            .apply_pre_execution_changes()
            .map_err(|error| AntiMevReconstructionError::Execution(error.to_string()))?;
        let sequence = execute_sequence(
            &outer_transactions,
            &outer_senders,
            resolutions,
            |transaction, sender| {
                let recovered = Recovered::new_unchecked(transaction.clone(), sender);
                let output = executor
                    .execute_transaction_without_commit(recovered)
                    .map_err(|error| error.to_string())?;
                executor.commit_transaction(output);
                Ok(())
            },
        );
        let result = executor
            .apply_post_execution_changes()
            .map_err(|error| AntiMevReconstructionError::Execution(error.to_string()))?;
        (sequence, result)
    };

    state.merge_transitions(BundleRetention::Reverts);
    let bundle = state.take_bundle();
    let state_root = state_provider
        .state_root(state_provider.hashed_post_state(&bundle))
        .map_err(|error| AntiMevReconstructionError::Provider(error.to_string()))?;
    let receipts_with_bloom =
        result.receipts.iter().map(|receipt| receipt.with_bloom_ref()).collect::<Vec<_>>();

    let mut block = proposal.block.clone().into_block();
    block.body.transactions = sequence.transactions;
    proposal.sidecars = retain_blob_sidecars(
        &outer_transactions,
        &block.body.transactions,
        std::mem::take(&mut proposal.sidecars),
    )?;
    block.header.state_root = state_root;
    block.header.transactions_root = calculate_transaction_root(&block.body.transactions);
    block.header.receipts_root = calculate_receipt_root(&receipts_with_bloom);
    block.header.logs_bloom = logs_bloom(result.receipts.iter().flat_map(|receipt| receipt.logs()));
    block.header.gas_used = result.gas_used;
    if block.header.blob_gas_used.is_some() {
        block.header.blob_gas_used =
            Some(block.body.transactions.iter().filter_map(|tx| tx.blob_gas_used()).sum());
    }
    proposal.block = RecoveredBlock::new_unhashed(block, sequence.senders);
    proposal.execution = BlockExecutionOutput { state: bundle, result };

    Ok(AntiMevReconstruction { proposal, decisions: sequence.decisions })
}

fn retain_blob_sidecars(
    outer_transactions: &[reth_ethereum_primitives::TransactionSigned],
    final_transactions: &[reth_ethereum_primitives::TransactionSigned],
    sidecars: Vec<BeaconBlobSidecar>,
) -> Result<Vec<BeaconBlobSidecar>, AntiMevReconstructionError> {
    let outer_blob_hashes = outer_transactions
        .iter()
        .filter_map(|transaction| transaction.blob_count().map(|_| *transaction.tx_hash()))
        .collect::<Vec<_>>();
    if outer_blob_hashes.len() != sidecars.len() {
        return Err(AntiMevReconstructionError::BlobSidecarCount {
            expected: outer_blob_hashes.len(),
            actual: sidecars.len(),
        })
    }
    let mut sidecars_by_transaction =
        outer_blob_hashes.into_iter().zip(sidecars).collect::<HashMap<_, _>>();
    final_transactions
        .iter()
        .filter_map(|transaction| transaction.blob_count().map(|_| transaction))
        .map(|transaction| {
            let transaction_hash = *transaction.tx_hash();
            sidecars_by_transaction
                .remove(&transaction_hash)
                .ok_or(AntiMevReconstructionError::MissingBlobSidecar(transaction_hash))
        })
        .collect()
}

fn index_resolutions(
    proposal: &AntiMevProposal,
    resolutions: Vec<AntiMevEnvelopeResolution>,
) -> Result<HashMap<usize, AntiMevEnvelopeResolution>, AntiMevReconstructionError> {
    if resolutions.len() != proposal.envelopes.len() {
        return Err(AntiMevReconstructionError::ResolutionCount {
            expected: proposal.envelopes.len(),
            actual: resolutions.len(),
        })
    }
    let mut envelope_indices = HashSet::with_capacity(proposal.envelopes.len());
    for envelope in &proposal.envelopes {
        if !envelope_indices.insert(envelope.transaction_index) {
            return Err(AntiMevReconstructionError::DuplicateEnvelope(envelope.transaction_index))
        }
    }
    let mut indexed = HashMap::with_capacity(resolutions.len());
    for resolution in resolutions {
        let transaction_index = match &resolution {
            AntiMevEnvelopeResolution::Decrypted { transaction_index, .. } |
            AntiMevEnvelopeResolution::Fallback { transaction_index, .. } => *transaction_index,
        };
        if !envelope_indices.contains(&transaction_index) {
            return Err(AntiMevReconstructionError::UnexpectedResolution(transaction_index))
        }
        if indexed.insert(transaction_index, resolution).is_some() {
            return Err(AntiMevReconstructionError::DuplicateResolution(transaction_index))
        }
    }
    Ok(indexed)
}

struct ReconstructedSequence {
    transactions: Vec<reth_ethereum_primitives::TransactionSigned>,
    senders: Vec<Address>,
    decisions: Vec<AntiMevTransactionDecision>,
}

fn execute_sequence(
    outer_transactions: &[reth_ethereum_primitives::TransactionSigned],
    outer_senders: &[Address],
    mut resolutions: HashMap<usize, AntiMevEnvelopeResolution>,
    mut execute: impl FnMut(&reth_ethereum_primitives::TransactionSigned, Address) -> Result<(), String>,
) -> ReconstructedSequence {
    debug_assert_eq!(outer_transactions.len(), outer_senders.len());
    let mut transactions = Vec::with_capacity(outer_transactions.len());
    let mut senders = Vec::with_capacity(outer_transactions.len());
    let mut decisions = Vec::with_capacity(outer_transactions.len());
    let mut failed_senders = HashSet::new();

    for (transaction_index, (outer, sender)) in
        outer_transactions.iter().zip(outer_senders).enumerate()
    {
        let sender = *sender;
        if failed_senders.contains(&sender) {
            decisions.push(AntiMevTransactionDecision::Dropped {
                transaction_index,
                reason: AntiMevDropReason::PriorSenderFailure,
            });
            continue
        }

        match resolutions.remove(&transaction_index) {
            Some(AntiMevEnvelopeResolution::Decrypted { transaction, .. }) => {
                let transaction = *transaction;
                match execute(&transaction, sender) {
                    Ok(()) => {
                        transactions.push(transaction);
                        senders.push(sender);
                        decisions.push(AntiMevTransactionDecision::IncludedDecrypted {
                            transaction_index,
                        });
                    }
                    Err(inner_error) => {
                        let replacement = AntiMevReplacementFallback::Execution(inner_error);
                        include_fallback(
                            transaction_index,
                            outer,
                            sender,
                            replacement,
                            &mut execute,
                            &mut transactions,
                            &mut senders,
                            &mut decisions,
                            &mut failed_senders,
                        );
                    }
                }
            }
            Some(AntiMevEnvelopeResolution::Fallback { reason, .. }) => {
                include_fallback(
                    transaction_index,
                    outer,
                    sender,
                    AntiMevReplacementFallback::Static(reason),
                    &mut execute,
                    &mut transactions,
                    &mut senders,
                    &mut decisions,
                    &mut failed_senders,
                );
            }
            None => match execute(outer, sender) {
                Ok(()) => {
                    transactions.push(outer.clone());
                    senders.push(sender);
                    decisions
                        .push(AntiMevTransactionDecision::IncludedOriginal { transaction_index });
                }
                Err(error) => {
                    failed_senders.insert(sender);
                    decisions.push(AntiMevTransactionDecision::Dropped {
                        transaction_index,
                        reason: AntiMevDropReason::OuterExecution(error),
                    });
                }
            },
        }
    }
    debug_assert!(resolutions.is_empty());
    ReconstructedSequence { transactions, senders, decisions }
}

#[expect(clippy::too_many_arguments)]
fn include_fallback(
    transaction_index: usize,
    outer: &reth_ethereum_primitives::TransactionSigned,
    sender: Address,
    replacement: AntiMevReplacementFallback,
    execute: &mut impl FnMut(
        &reth_ethereum_primitives::TransactionSigned,
        Address,
    ) -> Result<(), String>,
    transactions: &mut Vec<reth_ethereum_primitives::TransactionSigned>,
    senders: &mut Vec<Address>,
    decisions: &mut Vec<AntiMevTransactionDecision>,
    failed_senders: &mut HashSet<Address>,
) {
    match execute(outer, sender) {
        Ok(()) => {
            transactions.push(outer.clone());
            senders.push(sender);
            decisions.push(AntiMevTransactionDecision::IncludedFallback {
                transaction_index,
                reason: replacement,
            });
        }
        Err(outer_error) => {
            failed_senders.insert(sender);
            decisions.push(AntiMevTransactionDecision::Dropped {
                transaction_index,
                reason: AntiMevDropReason::FallbackExecution { replacement, outer_error },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, Transaction, TxEip4844, TxLegacy};
    use alloy_eips::eip4844::BlobTransactionSidecar;
    use alloy_primitives::{Signature, TxKind};
    use reth_ethereum_primitives::{Transaction as EthereumTransaction, TransactionSigned};

    fn transaction(gas_limit: u64) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                gas_limit,
                to: TxKind::Call(Address::repeat_byte(gas_limit as u8)),
                ..Default::default()
            }),
            Signature::test_signature(),
        )
    }

    fn blob_transaction(versioned_hash: B256) -> TransactionSigned {
        TransactionSigned::Eip4844(Signed::new_unhashed(
            TxEip4844 { blob_versioned_hashes: vec![versioned_hash], ..Default::default() },
            Signature::test_signature(),
        ))
    }

    #[test]
    fn retries_envelopes_and_drops_later_transactions_from_failed_senders() {
        let sender_a = Address::repeat_byte(0xaa);
        let sender_b = Address::repeat_byte(0xbb);
        let outer = [transaction(10), transaction(20), transaction(30), transaction(40)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(100)),
            },
        );
        resolutions.insert(
            2,
            AntiMevEnvelopeResolution::Fallback {
                transaction_index: 2,
                reason: AntiMevFallbackReason::TransactionDecoding,
            },
        );

        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b, sender_a],
            resolutions,
            |transaction, _| match transaction.gas_limit() {
                20 | 100 => Err(format!("rejected {}", transaction.gas_limit())),
                _ => Ok(()),
            },
        );

        assert_eq!(
            sequence.transactions.iter().map(|tx| tx.gas_limit()).collect::<Vec<_>>(),
            [10, 30]
        );
        assert_eq!(sequence.senders, [sender_a, sender_b]);
        assert_eq!(
            sequence.decisions,
            [
                AntiMevTransactionDecision::IncludedFallback {
                    transaction_index: 0,
                    reason: AntiMevReplacementFallback::Execution("rejected 100".to_string()),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 1,
                    reason: AntiMevDropReason::OuterExecution("rejected 20".to_string()),
                },
                AntiMevTransactionDecision::IncludedFallback {
                    transaction_index: 2,
                    reason: AntiMevReplacementFallback::Static(
                        AntiMevFallbackReason::TransactionDecoding
                    ),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 3,
                    reason: AntiMevDropReason::PriorSenderFailure,
                },
            ]
        );
    }

    #[test]
    fn includes_successful_decrypted_replacements() {
        let sender = Address::repeat_byte(0xaa);
        let outer = [transaction(10)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(50)),
            },
        );

        let sequence = execute_sequence(&outer, &[sender], resolutions, |_, _| Ok(()));
        assert_eq!(sequence.transactions[0].gas_limit(), 50);
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::IncludedDecrypted { transaction_index: 0 }]
        );
    }

    #[test]
    fn retains_only_sidecars_for_blob_transactions_left_after_reconstruction() {
        let first = blob_transaction(B256::repeat_byte(0x11));
        let ordinary = transaction(21_000);
        let second = blob_transaction(B256::repeat_byte(0x22));
        let sidecars = vec![
            BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default()),
            BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default()),
        ];

        let retained = retain_blob_sidecars(
            &[first, ordinary.clone(), second.clone()],
            &[ordinary, second],
            sidecars,
        )
        .unwrap();

        assert_eq!(retained.len(), 1);
    }

    #[test]
    fn rejects_incomplete_and_unmatched_reconstruction_sidecars() {
        let first = blob_transaction(B256::repeat_byte(0x11));
        let replacement = blob_transaction(B256::repeat_byte(0x22));
        assert!(matches!(
            retain_blob_sidecars(
                std::slice::from_ref(&first),
                std::slice::from_ref(&first),
                Vec::new()
            ),
            Err(AntiMevReconstructionError::BlobSidecarCount { expected: 1, actual: 0 })
        ));
        assert!(matches!(
            retain_blob_sidecars(
                &[blob_transaction(B256::repeat_byte(0x11))],
                &[replacement],
                vec![BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default())],
            ),
            Err(AntiMevReconstructionError::MissingBlobSidecar(_))
        ));
    }
}
