//! Final Anti-MEV block reconstruction from a verified outer pre-block.

use crate::{
    producer::{apply_next_consensus_commitments, read_next_dkg_or_fallback},
    validator::read_governance_validator_set_from_storage,
    AntiMevEnvelopeResolution, AntiMevFallbackReason, AntiMevProposal, DbftStateError, DkgState,
    DkgStateError, GovernanceValidatorSet, VerifiedProposal,
};
use alloy_consensus::{
    proofs::{calculate_receipt_root, calculate_transaction_root},
    transaction::Recovered,
    Transaction as _, TxReceipt,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bloom, B256, U256};
use reth_ethereum_primitives::{Receipt, TransactionSigned};
use reth_evm::{execute::BlockExecutor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_neox_consensus::{DbftExtraError, DbftExtraPrefix};
use reth_neox_evm::{NeoXEvmConfig, GOVERNANCE_PROXY_ADDRESS, KEY_MANAGEMENT_PROXY_ADDRESS};
use reth_neox_network::BeaconBlobSidecar;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{StateProvider, StateProviderFactory};
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
    /// The inner transaction was refused by the reference client's reconstruction pool.
    PoolRejection(StaticPoolRejection),
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
    /// The transaction that had to be included was refused by the reconstruction pool.
    PoolRejection(StaticPoolRejection),
}

/// A reconstruction-pool refusal reproduced from the reference client.
///
/// The reference client re-admits every transaction it reconstructs into a scratch legacy pool
/// before executing it, and drops whatever that pool refuses. Only the refusals that sequential
/// execution does not already imply are modelled here; the pool's nonce and balance checks run
/// against the parent state and are strictly weaker than execution, and its capacity limits cannot
/// bind for a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StaticPoolRejection {
    /// The reconstruction pool is a legacy pool and does not accept blob transactions.
    #[error("blob transactions are not accepted by the reconstruction pool")]
    BlobTransaction,
    /// EIP-7702 transactions must carry at least one authorization.
    #[error("set-code transaction carries no authorization")]
    EmptySetCodeAuthorizations,
    /// Encoded size above the reconstruction pool's per-transaction ceiling.
    #[error(
        "encoded size {size} exceeds the reconstruction pool limit of {STATIC_POOL_MAX_TX_SIZE}"
    )]
    Oversized {
        /// Encoded EIP-2718 length.
        size: usize,
    },
    /// Gas limit above the ceiling the pool admits against, which is the parent's gas limit.
    #[error("gas limit {gas_limit} exceeds the parent gas limit of {parent_gas_limit}")]
    GasLimitAboveParent {
        /// Declared transaction gas limit.
        gas_limit: u64,
        /// Gas limit of the header the pool was initialized from.
        parent_gas_limit: u64,
    },
    /// Tip below the reconstruction pool's price floor.
    #[error("gas tip cap {tip} is below the reconstruction pool floor of {STATIC_POOL_MIN_TIP}")]
    TipTooLow {
        /// Declared tip cap.
        tip: u128,
    },
}

/// Per-transaction encoded size ceiling of the reference client's reconstruction pool.
pub const STATIC_POOL_MAX_TX_SIZE: usize = 4 * 32 * 1024;

/// Price floor of the reference client's reconstruction pool, in wei.
///
/// The pool is created with the default legacy-pool configuration, whose price limit is 1 wei, so a
/// zero-tip transaction is refused regardless of what the on-chain Policy minimum allows.
pub const STATIC_POOL_MIN_TIP: u128 = 1;

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
    /// Governance post-state could not be decoded.
    #[error(transparent)]
    Governance(#[from] DbftStateError),
    /// DKG post-state could not be decoded.
    #[error(transparent)]
    Dkg(#[from] DkgStateError),
    /// The reconstructed header's dBFT prefix could not be decoded or rebuilt.
    #[error(transparent)]
    Extra(#[from] DbftExtraError),
    /// No height follows `u64::MAX`.
    #[error("reconstructed Neo X block height overflow")]
    HeightOverflow,
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
    let envelope_indices =
        anti_mev.envelopes.iter().map(|envelope| envelope.transaction_index).collect::<Vec<_>>();
    let resolutions = index_resolutions(anti_mev, resolutions)?;
    let state_provider = provider
        .state_by_block_hash(proposal.parent_state_hash)
        .map_err(|error| AntiMevReconstructionError::Provider(error.to_string()))?;
    let outer_transactions = &proposal.block.body().transactions;
    let outer_senders = proposal.block.senders();
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
            outer_transactions,
            outer_senders,
            &envelope_indices,
            proposal.parent_gas_limit,
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
    let (receipts_root, logs_bloom) = {
        let receipts_with_bloom =
            result.receipts.iter().map(|receipt| receipt.with_bloom_ref()).collect::<Vec<_>>();
        let receipts_root = calculate_receipt_root(&receipts_with_bloom);
        // The block logs bloom is the bitwise-OR union of every log's bloom bits; OR-ing the
        // per-receipt blooms already computed above is bit-identical to re-hashing all logs,
        // without the rehash.
        let logs_bloom = receipts_with_bloom
            .iter()
            .fold(Bloom::ZERO, |bloom, receipt| bloom | receipt.logs_bloom);
        (receipts_root, logs_bloom)
    };

    let mut block = proposal.block.clone().into_block();
    block.body.transactions = sequence.transactions;
    proposal.sidecars = retain_blob_sidecars(
        outer_transactions,
        &block.body.transactions,
        std::mem::take(&mut proposal.sidecars),
    )?;
    block.header.state_root = state_root;
    block.header.transactions_root = calculate_transaction_root(&block.body.transactions);
    block.header.receipts_root = receipts_root;
    block.header.logs_bloom = logs_bloom;
    block.header.gas_used = result.gas_used;
    if block.header.blob_gas_used.is_some() {
        block.header.blob_gas_used =
            Some(block.body.transactions.iter().filter_map(|tx| tx.blob_gas_used()).sum());
    }
    let execution = BlockExecutionOutput { state: bundle, result };
    let (next_validators, next_dkg) = recompute_next_consensus(
        &mut block.header,
        &execution,
        state_provider.as_ref(),
        evm_config,
    )?;
    proposal.block = RecoveredBlock::new_unhashed(block, sequence.senders);
    proposal.execution = execution;
    proposal.next_validators = next_validators;
    proposal.next_dkg = next_dkg;

    Ok(AntiMevReconstruction { proposal, decisions: sequence.decisions })
}

fn recompute_next_consensus(
    header: &mut alloy_consensus::Header,
    execution: &BlockExecutionOutput<Receipt>,
    state: &dyn StateProvider,
    evm_config: &NeoXEvmConfig,
) -> Result<(GovernanceValidatorSet, Option<DkgState>), AntiMevReconstructionError> {
    let next_validators = read_governance_validator_set_from_storage(|key| {
        post_storage(execution, state, GOVERNANCE_PROXY_ADDRESS, key)
            .map_err(DbftStateError::Provider)
    })?;
    let next_height =
        header.number.checked_add(1).ok_or(AntiMevReconstructionError::HeightOverflow)?;
    let next_dkg = read_next_dkg_or_fallback(
        evm_config.chain_spec().is_anti_mev_active_at_block(next_height),
        |key| {
            post_storage(execution, state, KEY_MANAGEMENT_PROXY_ADDRESS, key)
                .map_err(DkgStateError::Provider)
        },
    );
    let signature_scheme = DbftExtraPrefix::decode(&header.extra_data)?.signature_scheme();
    apply_next_consensus_commitments(
        header,
        signature_scheme,
        &next_validators,
        next_dkg.as_ref().map(|state| state.current.global_public_key),
        evm_config.chain_spec(),
    )?;
    Ok((next_validators, next_dkg))
}

fn post_storage(
    execution: &BlockExecutionOutput<Receipt>,
    state: &dyn StateProvider,
    address: Address,
    key: B256,
) -> Result<Option<U256>, String> {
    let key = U256::from_be_bytes(key.0);
    if let Some(value) = execution.storage(&address, key) {
        return Ok(Some(value));
    }
    state.storage(address, key.into()).map_err(|error| error.to_string())
}

fn retain_blob_sidecars(
    outer_transactions: &[TransactionSigned],
    final_transactions: &[TransactionSigned],
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
    transactions: Vec<TransactionSigned>,
    senders: Vec<Address>,
    decisions: Vec<AntiMevTransactionDecision>,
    failed_senders: HashSet<Address>,
}

/// Applies the reference client's static-pool admission rules to one transaction.
///
/// The reference client keeps a scratch legacy pool, reinitialized from the parent header and state
/// once per height, and pushes transactions through it in two places: proposal verification, which
/// refuses the whole proposal if the pool refuses anything, and Anti-MEV reconstruction, which
/// drops whatever the pool refuses. Both use the same rules, so both call this.
///
/// `parent_gas_limit` is the gas limit of the header the pool was initialized from, which is the
/// parent of the block being checked, not the block itself. A block may raise its own gas limit
/// above its parent's, so a transaction can fit the block it sits in and still exceed the pool's
/// ceiling.
///
/// Only refusals that the caller does not already imply are modelled. The pool's nonce and balance
/// checks run against the parent state and are strictly weaker than executing the block; its
/// capacity limits cannot bind for a single block; and its fork gating cannot bind for an
/// Anti-MEV-era parent.
pub fn static_pool_admission(
    transaction: &TransactionSigned,
    parent_gas_limit: u64,
) -> Result<(), StaticPoolRejection> {
    if transaction.is_eip4844() {
        return Err(StaticPoolRejection::BlobTransaction)
    }
    if transaction.is_eip7702() && transaction.authorization_list().is_none_or(<[_]>::is_empty) {
        return Err(StaticPoolRejection::EmptySetCodeAuthorizations)
    }
    let size = transaction.encode_2718_len();
    if size > STATIC_POOL_MAX_TX_SIZE {
        return Err(StaticPoolRejection::Oversized { size })
    }
    if transaction.gas_limit() > parent_gas_limit {
        return Err(StaticPoolRejection::GasLimitAboveParent {
            gas_limit: transaction.gas_limit(),
            parent_gas_limit,
        })
    }
    let tip =
        transaction.max_priority_fee_per_gas().unwrap_or_else(|| transaction.max_fee_per_gas());
    if tip < STATIC_POOL_MIN_TIP {
        return Err(StaticPoolRejection::TipTooLow { tip })
    }
    Ok(())
}

impl ReconstructedSequence {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            transactions: Vec::with_capacity(capacity),
            senders: Vec::with_capacity(capacity),
            decisions: Vec::with_capacity(capacity),
            failed_senders: HashSet::new(),
        }
    }

    fn include_fallback(
        &mut self,
        transaction_index: usize,
        outer: &TransactionSigned,
        sender: Address,
        replacement: AntiMevReplacementFallback,
        parent_gas_limit: u64,
        execute: &mut impl FnMut(&TransactionSigned, Address) -> Result<(), String>,
    ) {
        if let Err(rejection) = static_pool_admission(outer, parent_gas_limit) {
            self.failed_senders.insert(sender);
            self.decisions.push(AntiMevTransactionDecision::Dropped {
                transaction_index,
                reason: AntiMevDropReason::PoolRejection(rejection),
            });
            return
        }
        match execute(outer, sender) {
            Ok(()) => {
                self.transactions.push(outer.clone());
                self.senders.push(sender);
                self.decisions.push(AntiMevTransactionDecision::IncludedFallback {
                    transaction_index,
                    reason: replacement,
                });
            }
            Err(outer_error) => {
                self.failed_senders.insert(sender);
                self.decisions.push(AntiMevTransactionDecision::Dropped {
                    transaction_index,
                    reason: AntiMevDropReason::FallbackExecution { replacement, outer_error },
                });
            }
        }
    }
}

/// Replays the outer pre-block, substituting resolved Envelopes, and returns the final sequence.
///
/// `envelope_indices` holds the outer positions of the proposal's valid Envelopes in ascending
/// order. Envelope recognition walks that list with a cursor rather than looking each position up
/// directly, because the reference client does the same and its cursor is observable: it advances
/// only for an Envelope the loop actually reaches, so an Envelope skipped for a prior failure by
/// the same sender leaves the cursor parked on that position. Every later position then compares
/// against an index that is already behind it, so no remaining Envelope in the block is recognized
/// and all of them are included undecrypted. Looking resolutions up by position instead would
/// decrypt them and fork the chain, so the cursor is reproduced deliberately. See `SetTransactions`
/// and the reconstruction loop in the reference client's `consensus/dbft`.
fn execute_sequence(
    outer_transactions: &[TransactionSigned],
    outer_senders: &[Address],
    envelope_indices: &[usize],
    parent_gas_limit: u64,
    mut resolutions: HashMap<usize, AntiMevEnvelopeResolution>,
    mut execute: impl FnMut(&TransactionSigned, Address) -> Result<(), String>,
) -> ReconstructedSequence {
    debug_assert_eq!(outer_transactions.len(), outer_senders.len());
    let mut sequence = ReconstructedSequence::with_capacity(outer_transactions.len());
    let mut envelope_cursor = 0_usize;

    for (transaction_index, (outer, sender)) in
        outer_transactions.iter().zip(outer_senders).enumerate()
    {
        let sender = *sender;
        if sequence.failed_senders.contains(&sender) {
            sequence.decisions.push(AntiMevTransactionDecision::Dropped {
                transaction_index,
                reason: AntiMevDropReason::PriorSenderFailure,
            });
            continue
        }

        let resolution = if envelope_indices.get(envelope_cursor) == Some(&transaction_index) {
            envelope_cursor += 1;
            resolutions.remove(&transaction_index)
        } else {
            None
        };
        match resolution {
            Some(AntiMevEnvelopeResolution::Decrypted { transaction, .. }) => {
                let transaction = *transaction;
                if let Err(rejection) = static_pool_admission(&transaction, parent_gas_limit) {
                    sequence.include_fallback(
                        transaction_index,
                        outer,
                        sender,
                        AntiMevReplacementFallback::PoolRejection(rejection),
                        parent_gas_limit,
                        &mut execute,
                    );
                    continue
                }
                match execute(&transaction, sender) {
                    Ok(()) => {
                        sequence.transactions.push(transaction);
                        sequence.senders.push(sender);
                        sequence.decisions.push(AntiMevTransactionDecision::IncludedDecrypted {
                            transaction_index,
                        });
                    }
                    Err(inner_error) => {
                        let replacement = AntiMevReplacementFallback::Execution(inner_error);
                        sequence.include_fallback(
                            transaction_index,
                            outer,
                            sender,
                            replacement,
                            parent_gas_limit,
                            &mut execute,
                        );
                    }
                }
            }
            Some(AntiMevEnvelopeResolution::Fallback { reason, .. }) => {
                sequence.include_fallback(
                    transaction_index,
                    outer,
                    sender,
                    AntiMevReplacementFallback::Static(reason),
                    parent_gas_limit,
                    &mut execute,
                );
            }
            None => {
                if let Err(rejection) = static_pool_admission(outer, parent_gas_limit) {
                    sequence.failed_senders.insert(sender);
                    sequence.decisions.push(AntiMevTransactionDecision::Dropped {
                        transaction_index,
                        reason: AntiMevDropReason::PoolRejection(rejection),
                    });
                    continue
                }
                match execute(outer, sender) {
                    Ok(()) => {
                        sequence.transactions.push(outer.clone());
                        sequence.senders.push(sender);
                        sequence.decisions.push(AntiMevTransactionDecision::IncludedOriginal {
                            transaction_index,
                        });
                    }
                    Err(error) => {
                        sequence.failed_senders.insert(sender);
                        sequence.decisions.push(AntiMevTransactionDecision::Dropped {
                            transaction_index,
                            reason: AntiMevDropReason::OuterExecution(error),
                        });
                    }
                }
            }
        }
    }
    sequence
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, Transaction, TxEip4844, TxLegacy};
    use alloy_eips::eip4844::BlobTransactionSidecar;
    use alloy_primitives::{keccak256, Signature, TxKind};
    use reth_ethereum_primitives::{EthPrimitives, Transaction as EthereumTransaction};
    use reth_neox_antimev::{
        global_public_key_from_commitment, DkgPolynomial, G1_EIP2537_LEN, NEOX_DKG_SCALER,
    };
    use reth_neox_consensus::{next_consensus_hash, SignatureScheme};
    use reth_neox_evm::{
        dynamic_array_element_storage_key, uint_mapping_storage_key,
        GOVERNANCE_CURRENT_CONSENSUS_SLOT, KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT,
        KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
    };
    use reth_provider::test_utils::MockEthProvider;
    use reth_revm::{db::states::BundleState, primitives::StorageKeyMap};

    /// Parent gas limit used by the sequencing tests, above every gas limit they build.
    const TEST_PARENT_GAS_LIMIT: u64 = 30_000_000;

    fn transaction(gas_limit: u64) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                gas_limit,
                // Above the reconstruction pool's 1 wei floor, which every included transaction
                // must clear.
                gas_price: 1,
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

    fn validator_set(seed: u8) -> GovernanceValidatorSet {
        let original =
            (0..7).map(|index| Address::repeat_byte(seed.wrapping_add(index))).collect::<Vec<_>>();
        let mut sorted = original.clone();
        sorted.sort_unstable();
        GovernanceValidatorSet { original, sorted, dkg_indices: (1..=7).collect() }
    }

    fn governance_storage(validators: &GovernanceValidatorSet) -> StorageKeyMap<(U256, U256)> {
        let mut storage = StorageKeyMap::default();
        storage.insert(
            U256::from(GOVERNANCE_CURRENT_CONSENSUS_SLOT),
            (U256::ZERO, U256::from(validators.original.len())),
        );
        for (index, validator) in validators.original.iter().enumerate() {
            storage.insert(
                dynamic_array_element_storage_key(GOVERNANCE_CURRENT_CONSENSUS_SLOT, index as u64),
                (U256::ZERO, U256::from_be_slice(validator.as_slice())),
            );
        }
        storage
    }

    fn dkg_commitment(seed: u8, round: u64) -> [u8; G1_EIP2537_LEN] {
        DkgPolynomial::deterministic(&[seed; 32], U256::from(47763), round).unwrap().commitment()
            [..G1_EIP2537_LEN]
            .try_into()
            .unwrap()
    }

    fn dkg_storage(round: u64, commitment: &[u8; G1_EIP2537_LEN]) -> StorageKeyMap<(U256, U256)> {
        let mut storage = StorageKeyMap::default();
        storage
            .insert(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT), (U256::ZERO, U256::from(round)));
        let slot =
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(round));
        storage.insert(slot, (U256::ZERO, U256::from(G1_EIP2537_LEN * 2 + 1)));
        let data_base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
        for (index, word) in commitment.as_chunks::<32>().0.iter().enumerate() {
            storage.insert(
                data_base.wrapping_add(U256::from(index)),
                (U256::ZERO, U256::from_be_slice(word)),
            );
        }
        storage
    }

    fn reconstructed_execution(
        validators: &GovernanceValidatorSet,
        dkg_round: u64,
        commitment: &[u8; G1_EIP2537_LEN],
    ) -> BlockExecutionOutput<Receipt> {
        reconstructed_execution_with_dkg_storage(validators, dkg_storage(dkg_round, commitment))
    }

    fn reconstructed_execution_with_dkg_storage(
        validators: &GovernanceValidatorSet,
        dkg_storage: StorageKeyMap<(U256, U256)>,
    ) -> BlockExecutionOutput<Receipt> {
        let state = BundleState::builder(0..=0)
            .state_present_account_info(GOVERNANCE_PROXY_ADDRESS, Default::default())
            .state_storage(GOVERNANCE_PROXY_ADDRESS, governance_storage(validators))
            .state_present_account_info(KEY_MANAGEMENT_PROXY_ADDRESS, Default::default())
            .state_storage(KEY_MANAGEMENT_PROXY_ADDRESS, dkg_storage)
            .build();
        BlockExecutionOutput { state, ..Default::default() }
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
            &[0, 2],
            TEST_PARENT_GAS_LIMIT,
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

        let sequence = execute_sequence(
            &outer,
            &[sender],
            &[0],
            TEST_PARENT_GAS_LIMIT,
            resolutions,
            |_, _| Ok(()),
        );
        assert_eq!(sequence.transactions[0].gas_limit(), 50);
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::IncludedDecrypted { transaction_index: 0 }]
        );
    }

    #[test]
    fn reconstruction_pool_drops_blob_transactions_and_later_transactions_from_their_sender() {
        let sender_a = Address::repeat_byte(0xaa);
        let sender_b = Address::repeat_byte(0xbb);
        let outer = [blob_transaction(B256::repeat_byte(1)), transaction(20), transaction(30)];

        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b],
            &[],
            TEST_PARENT_GAS_LIMIT,
            HashMap::new(),
            |_, _| Ok(()),
        );

        assert_eq!(sequence.transactions.iter().map(|tx| tx.gas_limit()).collect::<Vec<_>>(), [30]);
        assert_eq!(
            sequence.decisions,
            [
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 0,
                    reason: AntiMevDropReason::PoolRejection(StaticPoolRejection::BlobTransaction),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 1,
                    reason: AntiMevDropReason::PriorSenderFailure,
                },
                AntiMevTransactionDecision::IncludedOriginal { transaction_index: 2 },
            ]
        );
    }

    #[test]
    fn reconstruction_pool_rejects_zero_tip_and_falls_back_to_the_envelope() {
        let sender = Address::repeat_byte(0xaa);
        let outer = [transaction(10)];
        let zero_tip = TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy { gas_limit: 50, ..Default::default() }),
            Signature::test_signature(),
        );
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(zero_tip),
            },
        );

        let sequence = execute_sequence(
            &outer,
            &[sender],
            &[0],
            TEST_PARENT_GAS_LIMIT,
            resolutions,
            |_, _| Ok(()),
        );

        assert_eq!(sequence.transactions[0].gas_limit(), 10);
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::IncludedFallback {
                transaction_index: 0,
                reason: AntiMevReplacementFallback::PoolRejection(StaticPoolRejection::TipTooLow {
                    tip: 0
                }),
            }]
        );
    }

    #[test]
    fn skipped_envelope_parks_the_cursor_and_leaves_later_envelopes_undecrypted() {
        let sender_a = Address::repeat_byte(0xaa);
        let sender_b = Address::repeat_byte(0xbb);
        let sender_c = Address::repeat_byte(0xcc);
        // Outer: a plain transaction from A that fails, then Envelopes at 1 (A), 2 (B) and 3 (C).
        let outer = [transaction(10), transaction(20), transaction(30), transaction(40)];
        let mut resolutions = HashMap::new();
        for (index, gas) in [(1, 200), (2, 300), (3, 400)] {
            resolutions.insert(
                index,
                AntiMevEnvelopeResolution::Decrypted {
                    transaction_index: index,
                    transaction: Box::new(transaction(gas)),
                },
            );
        }

        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b, sender_c],
            &[1, 2, 3],
            TEST_PARENT_GAS_LIMIT,
            resolutions,
            |transaction, _| match transaction.gas_limit() {
                10 => Err("rejected 10".to_string()),
                _ => Ok(()),
            },
        );

        // A's Envelope is dropped for the prior failure without consuming the cursor, so the
        // Envelopes from B and C are no longer recognized and their outer transactions stand.
        assert_eq!(
            sequence.transactions.iter().map(|tx| tx.gas_limit()).collect::<Vec<_>>(),
            [30, 40]
        );
        assert_eq!(sequence.senders, [sender_b, sender_c]);
        assert_eq!(
            sequence.decisions,
            [
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 0,
                    reason: AntiMevDropReason::OuterExecution("rejected 10".to_string()),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 1,
                    reason: AntiMevDropReason::PriorSenderFailure,
                },
                AntiMevTransactionDecision::IncludedOriginal { transaction_index: 2 },
                AntiMevTransactionDecision::IncludedOriginal { transaction_index: 3 },
            ]
        );
    }

    #[test]
    fn reconstructed_governance_state_replaces_stale_fallback_commitment() {
        let chain_spec = reth_neox_chainspec::NeoXChainSpec::mainnet().unwrap();
        let evm_config = NeoXEvmConfig::new(chain_spec.clone());
        let stale_validators = validator_set(0x10);
        let final_validators = validator_set(0x30);
        let commitment = dkg_commitment(0x51, 1);
        let public_key = global_public_key_from_commitment(&commitment, NEOX_DKG_SCALER).unwrap();
        let execution = reconstructed_execution(&final_validators, 1, &commitment);
        let state = MockEthProvider::<EthPrimitives>::new();
        let mut header = alloy_consensus::Header {
            number: chain_spec.neox.anti_mev_block,
            ..Default::default()
        };
        apply_next_consensus_commitments(
            &mut header,
            SignatureScheme::Threshold,
            &stale_validators,
            Some(public_key),
            chain_spec.as_ref(),
        )
        .unwrap();

        let (next_validators, next_dkg) =
            recompute_next_consensus(&mut header, &execution, &state, &evm_config).unwrap();

        assert_eq!(next_validators, final_validators);
        assert_eq!(next_dkg.unwrap().current.global_public_key, public_key);
        let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
        assert_eq!(
            prefix.fallback_next_consensus(),
            Some(next_consensus_hash(&final_validators.sorted))
        );
        assert_eq!(header.mix_hash, keccak256(public_key));
    }

    #[test]
    fn reconstructed_dkg_state_replaces_stale_threshold_commitment() {
        let chain_spec = reth_neox_chainspec::NeoXChainSpec::mainnet().unwrap();
        let evm_config = NeoXEvmConfig::new(chain_spec.clone());
        let validators = validator_set(0x20);
        let stale_commitment = dkg_commitment(0x61, 1);
        let final_commitment = dkg_commitment(0x62, 2);
        let stale_public_key =
            global_public_key_from_commitment(&stale_commitment, NEOX_DKG_SCALER).unwrap();
        let final_public_key =
            global_public_key_from_commitment(&final_commitment, NEOX_DKG_SCALER).unwrap();
        let execution = reconstructed_execution(&validators, 2, &final_commitment);
        let state = MockEthProvider::<EthPrimitives>::new();
        let mut header = alloy_consensus::Header {
            number: chain_spec.neox.anti_mev_block,
            ..Default::default()
        };
        apply_next_consensus_commitments(
            &mut header,
            SignatureScheme::Threshold,
            &validators,
            Some(stale_public_key),
            chain_spec.as_ref(),
        )
        .unwrap();
        assert_eq!(header.mix_hash, keccak256(stale_public_key));

        let (next_validators, next_dkg) =
            recompute_next_consensus(&mut header, &execution, &state, &evm_config).unwrap();

        assert_eq!(next_validators, validators);
        assert_eq!(next_dkg.unwrap().current.global_public_key, final_public_key);
        assert_eq!(header.mix_hash, keccak256(final_public_key));
    }

    #[test]
    fn unavailable_reconstructed_dkg_state_uses_ecdsa_fallback_and_zero_mix_hash() {
        let chain_spec = reth_neox_chainspec::NeoXChainSpec::mainnet().unwrap();
        let evm_config = NeoXEvmConfig::new(chain_spec.clone());
        let validators = validator_set(0x20);
        let missing = StorageKeyMap::default();
        let mut malformed = StorageKeyMap::default();
        malformed.insert(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT), (U256::ZERO, U256::from(1)));
        malformed.insert(
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(1)),
            (U256::ZERO, U256::from(4)),
        );

        for dkg_storage in [missing, malformed] {
            let execution = reconstructed_execution_with_dkg_storage(&validators, dkg_storage);
            let state = MockEthProvider::<EthPrimitives>::new();
            let mut header = alloy_consensus::Header {
                number: chain_spec.neox.anti_mev_block,
                ..Default::default()
            };
            apply_next_consensus_commitments(
                &mut header,
                SignatureScheme::Threshold,
                &validators,
                Some([0x42; 48]),
                chain_spec.as_ref(),
            )
            .unwrap();
            assert_ne!(header.mix_hash, B256::ZERO);

            let (next_validators, next_dkg) =
                recompute_next_consensus(&mut header, &execution, &state, &evm_config).unwrap();

            assert_eq!(next_validators, validators);
            assert!(next_dkg.is_none());
            let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
            assert_eq!(
                prefix.fallback_next_consensus(),
                Some(next_consensus_hash(&validators.sorted))
            );
            assert_eq!(header.mix_hash, B256::ZERO);
        }
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
