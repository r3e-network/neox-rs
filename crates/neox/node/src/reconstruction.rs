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
use alloy_eips::{eip2718::Encodable2718, Typed2718};
use alloy_primitives::{Address, Bloom, B256, U256};
use reth_ethereum_primitives::{Receipt, TransactionSigned};
use reth_evm::{execute::BlockExecutor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_neox_antimev::{encrypted_gas, is_envelope, DkgParameters, MIN_ENCRYPTED_GAS_LIMIT};
use reth_neox_consensus::{DbftExtraError, DbftExtraPrefix};
use reth_neox_evm::{
    policy_blacklist_storage_key, policy_storage_key, NeoXEvmConfig, GOVERNANCE_PROXY_ADDRESS,
    KEY_MANAGEMENT_PROXY_ADDRESS, POLICY_BASE_FEE_SLOT, POLICY_ENVELOPE_FEE_SLOT,
    POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_network::BeaconBlobSidecar;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{ProviderResult, StateProvider, StateProviderFactory};
use reth_revm::{
    context_interface::cfg::gas_params::Eip2780TxInfo,
    database::StateProviderDatabase,
    db::{states::bundle_state::BundleRetention, State},
    interpreter::gas::calculate_initial_tx_gas,
    primitives::{eip3860, eip7825, eip7954, hardfork::SpecId},
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
/// rooted at the parent state, and drops whatever that pool refuses. The modelled refusals are
/// the pool's static rules, its stateful rules against the parent state (nonce, Policy, balance),
/// its EIP-7702 in-flight limits, and its same-nonce replacement rule. Sequential execution does
/// not imply the stateful ones, because the pool never sees earlier block effects; its capacity
/// limits cannot bind for a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StaticPoolRejection {
    /// The reconstruction pool is a legacy pool and does not accept blob transactions.
    #[error("blob transactions are not accepted by the reconstruction pool")]
    BlobTransaction,
    /// The transaction type is not active under the parent header's fork rules.
    #[error("transaction type {0} is not active at the parent header")]
    TypeNotActive(u8),
    /// EIP-7702 transactions must carry at least one authorization.
    #[error("set-code transaction carries no authorization")]
    EmptySetCodeAuthorizations,
    /// Contract-creation input above the parent fork's init-code ceiling.
    #[error("init code size {size} exceeds the limit of {limit}")]
    InitCodeTooLarge {
        /// Input length.
        size: usize,
        /// Active init-code ceiling.
        limit: usize,
    },
    /// Gas limit above the Osaka per-transaction cap.
    #[error("gas limit {0} exceeds the per-transaction cap")]
    GasLimitAboveTxCap(u64),
    /// Fee cap below tip cap.
    #[error("tip cap exceeds fee cap")]
    TipAboveFeeCap,
    /// EIP-2681 nonce ceiling.
    #[error("nonce has reached its maximum")]
    NonceMax,
    /// Gas limit below the intrinsic cost or the EIP-7623 calldata floor.
    #[error("gas limit {gas_limit} is below the intrinsic requirement {required}")]
    IntrinsicGas {
        /// Declared transaction gas limit.
        gas_limit: u64,
        /// Larger of the intrinsic gas and the calldata floor.
        required: u64,
    },
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
    /// The same transaction hash is already in the pool.
    #[error("transaction is already known to the reconstruction pool")]
    AlreadyKnown,
    /// Transaction nonce below the sender's parent-state nonce.
    #[error("transaction nonce {nonce} is below the parent-state nonce {next}")]
    NonceTooLow {
        /// Declared transaction nonce.
        nonce: u64,
        /// Parent-state nonce of the sender.
        next: u64,
    },
    /// Envelope gas limit above the parent Policy maximum.
    #[error("Envelope gas limit {gas_limit} exceeds the Policy maximum {maximum_gas}")]
    EnvelopeGasAbovePolicy {
        /// Envelope gas limit.
        gas_limit: u64,
        /// Policy `maxEnvelopeGasLimit`.
        maximum_gas: U256,
    },
    /// Declared encrypted gas below the minimum simple-transfer cost.
    #[error("Envelope encrypted gas {0} is below the minimum")]
    EncryptedGasBelowMinimum(u32),
    /// Envelope gas limit cannot cover its declared encrypted gas.
    #[error("Envelope gas limit {gas_limit} is below its encrypted gas {inner_gas}")]
    EnvelopeGasBelowEncrypted {
        /// Envelope gas limit.
        gas_limit: u64,
        /// Declared encrypted gas.
        inner_gas: u32,
    },
    /// Effective tip against the parent Policy base fee is below the Policy minimum tip (plus the
    /// Envelope fee for Envelopes). A fee cap below the base fee is a negative tip.
    #[error("effective tip below Policy minimum {minimum_tip} at Policy base fee {base_fee}")]
    TipBelowPolicy {
        /// Policy minimum tip, including the Envelope fee for Envelopes.
        minimum_tip: U256,
        /// Policy base fee.
        base_fee: U256,
    },
    /// The sender is blacklisted in the parent Policy state.
    #[error("sender is blacklisted by the Policy contract")]
    BlockedSender,
    /// Maximum cost above the sender's parent-state balance.
    #[error("maximum cost {cost} wei exceeds the sender's parent balance of {balance} wei")]
    InsufficientFunds {
        /// Transaction's maximum cost.
        cost: U256,
        /// Parent-state balance of the sender.
        balance: U256,
    },
    /// A delegated sender, or one named by a queued authorization, may only use its parent nonce.
    #[error("delegated sender nonce {nonce} differs from the parent-state nonce {next}")]
    DelegatedNonceGap {
        /// Declared transaction nonce.
        nonce: u64,
        /// Parent-state nonce of the sender.
        next: u64,
    },
    /// An authorization names an account that already has more than one queued transaction.
    #[error("authority {0} is reserved by queued transactions")]
    AuthorityReserved(Address),
    /// A queued transaction with the same nonce is not outbid by the required price bump.
    #[error(
        "replacement for nonce {nonce} does not meet the {STATIC_POOL_PRICE_BUMP}% price bump"
    )]
    ReplaceUnderpriced {
        /// Contested nonce.
        nonce: u64,
    },
}

/// Per-transaction encoded size ceiling of the reference client's reconstruction pool.
pub const STATIC_POOL_MAX_TX_SIZE: usize = 4 * 32 * 1024;

/// Price floor of the reference client's reconstruction pool, in wei.
///
/// The pool is created with the default legacy-pool configuration, whose price limit is 1 wei, so a
/// zero-tip transaction is refused regardless of what the on-chain Policy minimum allows.
pub const STATIC_POOL_MIN_TIP: u128 = 1;

/// Percentage by which a same-nonce replacement must outbid both fee fields of the queued
/// transaction (the default legacy-pool `PriceBump`).
pub const STATIC_POOL_PRICE_BUMP: u128 = 10;

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
    let head = StaticPoolHead { gas_limit: proposal.parent_gas_limit, spec: proposal.parent_spec };
    let mut admission = StaticPoolAdmission::new(state_provider.as_ref(), head, outer_senders)
        .map_err(|error| AntiMevReconstructionError::Provider(error.to_string()))?;
    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(
            state_provider.as_ref().into_evm_state_provider(),
        ))
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
            &mut admission,
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
        .state_root(
            state_provider
                .hashed_post_state(&bundle)
                .map_err(|error| AntiMevReconstructionError::Provider(error.to_string()))?,
        )
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
    let parameters = DkgParameters::new(next_validators.sorted.len()).map_err(|error| {
        AntiMevReconstructionError::Dkg(DkgStateError::Provider(error.to_string()))
    })?;
    let next_dkg = read_next_dkg_or_fallback(
        evm_config.chain_spec().is_anti_mev_active_at_block(next_height),
        parameters,
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

/// Parent header values the reference client's static pool validates against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticPoolHead {
    /// Gas limit of the parent header.
    pub gas_limit: u64,
    /// EVM specification active at the parent header.
    pub spec: SpecId,
}

/// Applies the reference client's stateless static-pool rules (`ValidateTxBasics`) to one
/// transaction.
///
/// The reference client keeps a scratch legacy pool, reinitialized from the parent header and state
/// once per height, and pushes transactions through it in two places: proposal verification, which
/// refuses the whole proposal if the pool refuses anything, and Anti-MEV reconstruction, which
/// drops whatever the pool refuses. Both use the same rules, so both go through
/// [`StaticPoolAdmission`], which layers the stateful checks on this static core.
///
/// Fork rules are those of the parent header the pool was initialized from, not of the block being
/// checked. A block may raise its own gas limit above its parent's, so a transaction can fit the
/// block it sits in and still exceed the pool's ceiling.
pub fn static_pool_admission(
    transaction: &TransactionSigned,
    sender: Address,
    head: StaticPoolHead,
) -> Result<(), StaticPoolRejection> {
    let spec = head.spec;
    if transaction.is_eip4844() {
        return Err(StaticPoolRejection::BlobTransaction)
    }
    let size = transaction.encode_2718_len();
    if size > STATIC_POOL_MAX_TX_SIZE {
        return Err(StaticPoolRejection::Oversized { size })
    }
    let active = match transaction.ty() {
        0 => true,
        1 => spec.is_enabled_in(SpecId::BERLIN),
        2 => spec.is_enabled_in(SpecId::LONDON),
        4 => spec.is_enabled_in(SpecId::PRAGUE),
        _ => false,
    };
    if !active {
        return Err(StaticPoolRejection::TypeNotActive(transaction.ty()))
    }
    if transaction.is_create() && spec.is_enabled_in(SpecId::SHANGHAI) {
        let limit = if spec.is_enabled_in(SpecId::AMSTERDAM) {
            eip7954::MAX_INITCODE_SIZE
        } else {
            eip3860::MAX_INITCODE_SIZE
        };
        let size = transaction.input().len();
        if size > limit {
            return Err(StaticPoolRejection::InitCodeTooLarge { size, limit })
        }
    }
    let gas_limit = transaction.gas_limit();
    if spec.is_enabled_in(SpecId::OSAKA) &&
        !spec.is_enabled_in(SpecId::AMSTERDAM) &&
        gas_limit > eip7825::TX_GAS_LIMIT_CAP
    {
        return Err(StaticPoolRejection::GasLimitAboveTxCap(gas_limit))
    }
    if gas_limit > head.gas_limit {
        return Err(StaticPoolRejection::GasLimitAboveParent {
            gas_limit,
            parent_gas_limit: head.gas_limit,
        })
    }
    let tip =
        transaction.max_priority_fee_per_gas().unwrap_or_else(|| transaction.max_fee_per_gas());
    if transaction.max_fee_per_gas() < tip {
        return Err(StaticPoolRejection::TipAboveFeeCap)
    }
    if transaction.nonce() == u64::MAX {
        return Err(StaticPoolRejection::NonceMax)
    }
    let eip2780 = spec.is_enabled_in(SpecId::AMSTERDAM).then(|| Eip2780TxInfo {
        value: transaction.value(),
        is_self_transfer: transaction.to() == Some(sender),
    });
    let intrinsic = calculate_initial_tx_gas(
        spec,
        transaction.input(),
        transaction.is_create(),
        transaction.access_list().map(|list| list.len()).unwrap_or_default() as u64,
        transaction.access_list().map(|list| list.storage_keys_count()).unwrap_or_default() as u64,
        transaction.authorization_count().unwrap_or_default(),
        eip2780,
    );
    let required = intrinsic.initial_total_gas().max(intrinsic.floor_gas());
    if gas_limit < required {
        return Err(StaticPoolRejection::IntrinsicGas { gas_limit, required })
    }
    if spec.is_enabled_in(SpecId::AMSTERDAM) && required > eip7825::TX_GAS_LIMIT_CAP {
        return Err(StaticPoolRejection::GasLimitAboveTxCap(required))
    }
    if tip < STATIC_POOL_MIN_TIP {
        return Err(StaticPoolRejection::TipTooLow { tip })
    }
    if transaction.is_eip7702() && transaction.authorization_list().is_none_or(<[_]>::is_empty) {
        return Err(StaticPoolRejection::EmptySetCodeAuthorizations)
    }
    Ok(())
}

/// The reference client's scratch reconstruction pool, rooted at the parent state.
///
/// The pool is created without promotion loops, so every admitted transaction stays queued and the
/// pending set is always empty. Each [`Self::add`] therefore validates against the parent-state
/// account and Policy values only (nonce, Policy fee and blacklist rules, and the full maximum cost
/// against the parent balance, independently per transaction), and it keeps whatever it admitted
/// even when execution later fails. Queued transactions matter only through the legacy pool's
/// queue rules: a duplicate hash is refused, a same-nonce transaction must outbid the queued one
/// by [`STATIC_POOL_PRICE_BUMP`] percent, and EIP-7702 delegation limits read the queued
/// authorizations.
#[derive(Debug)]
pub struct StaticPoolAdmission {
    head: StaticPoolHead,
    policy: StaticPoolPolicy,
    accounts: HashMap<Address, ParentAccount>,
    queued: HashMap<Address, HashMap<u64, QueuedTransaction>>,
    known: HashSet<B256>,
}

/// Parent-state Policy values the pool reads for every transaction.
#[derive(Debug, Clone, Copy)]
struct StaticPoolPolicy {
    min_gas_tip_cap: U256,
    base_fee: U256,
    envelope_fee: U256,
    max_envelope_gas_limit: U256,
}

/// Parent-state view of one sender.
#[derive(Debug, Clone, Copy)]
struct ParentAccount {
    nonce: u64,
    balance: U256,
    has_code: bool,
    blacklisted: bool,
}

#[derive(Debug, Clone)]
struct QueuedTransaction {
    hash: B256,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    authorities: Vec<Address>,
}

impl StaticPoolAdmission {
    /// Creates the pool for the parent `head`, preloading the parent Policy values and every
    /// sender's parent-state account so the per-transaction checks cannot fail on a state read.
    ///
    /// `senders` must cover every transaction the caller will add, keyed by the block's sender
    /// list; decrypted Envelope replacements are attributed to their Envelope's sender.
    pub fn new(
        state: &dyn StateProvider,
        head: StaticPoolHead,
        senders: &[Address],
    ) -> ProviderResult<Self> {
        let policy_slot = |slot| {
            state
                .storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())
                .map(Option::unwrap_or_default)
        };
        let policy = StaticPoolPolicy {
            min_gas_tip_cap: policy_slot(POLICY_MIN_GAS_TIP_CAP_SLOT)?,
            base_fee: policy_slot(POLICY_BASE_FEE_SLOT)?,
            envelope_fee: policy_slot(POLICY_ENVELOPE_FEE_SLOT)?,
            max_envelope_gas_limit: policy_slot(POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT)?,
        };
        let mut accounts = HashMap::with_capacity(senders.len());
        for sender in senders {
            if accounts.contains_key(sender) {
                continue
            }
            let account = state.basic_account(sender)?;
            let blacklisted = !state
                .storage(POLICY_PROXY_ADDRESS, policy_blacklist_storage_key(*sender).into())?
                .unwrap_or_default()
                .is_zero();
            accounts.insert(
                *sender,
                ParentAccount {
                    nonce: account.map_or(0, |account| account.nonce),
                    balance: account.map_or(U256::ZERO, |account| account.balance),
                    // Geth reads a missing account's code hash as zero, which is not the empty-code
                    // hash, so the delegation limit also applies to it.
                    has_code: account.is_none_or(|account| account.has_bytecode()),
                    blacklisted,
                },
            );
        }
        Ok(Self { head, policy, accounts, queued: HashMap::new(), known: HashSet::new() })
    }

    /// Validates `transaction` from `sender` and queues it, exactly like the legacy pool's `add`.
    ///
    /// An admitted transaction stays queued whether or not it later executes.
    pub fn add(
        &mut self,
        sender: Address,
        transaction: &TransactionSigned,
    ) -> Result<(), StaticPoolRejection> {
        static_pool_admission(transaction, sender, self.head)?;
        let hash = *transaction.tx_hash();
        if self.known.contains(&hash) {
            return Err(StaticPoolRejection::AlreadyKnown)
        }
        let account =
            *self.accounts.get(&sender).expect("admission preload covers the block's senders");
        let nonce = transaction.nonce();
        if nonce < account.nonce {
            return Err(StaticPoolRejection::NonceTooLow { nonce, next: account.nonce })
        }
        self.check_policy(transaction, account)?;
        let cost = static_pool_max_cost(transaction);
        if cost > account.balance {
            return Err(StaticPoolRejection::InsufficientFunds { cost, balance: account.balance })
        }

        // Pending is always empty, so the delegation limit admits only the parent nonce.
        let has_queued_authorization = || {
            self.queued
                .values()
                .flat_map(HashMap::values)
                .any(|queued| queued.authorities.contains(&sender))
        };
        if (account.has_code || has_queued_authorization()) && nonce != account.nonce {
            return Err(StaticPoolRejection::DelegatedNonceGap { nonce, next: account.nonce })
        }
        let authorities = set_code_authorities(transaction);
        for authority in &authorities {
            if self.queued.get(authority).is_some_and(|queue| queue.len() > 1) {
                return Err(StaticPoolRejection::AuthorityReserved(*authority))
            }
        }

        let queue = self.queued.entry(sender).or_default();
        let max_fee_per_gas = transaction.max_fee_per_gas();
        let max_priority_fee_per_gas =
            transaction.max_priority_fee_per_gas().unwrap_or(max_fee_per_gas);
        if let Some(old) = queue.get(&nonce) &&
            !outbids(old, max_fee_per_gas, max_priority_fee_per_gas)
        {
            return Err(StaticPoolRejection::ReplaceUnderpriced { nonce })
        }
        let queued =
            QueuedTransaction { hash, max_fee_per_gas, max_priority_fee_per_gas, authorities };
        if let Some(old) = queue.insert(nonce, queued) {
            self.known.remove(&old.hash);
        }
        self.known.insert(hash);
        Ok(())
    }

    /// Geth's `ValidateTransactionWithState` Policy rules, read from the parent state.
    fn check_policy(
        &self,
        transaction: &TransactionSigned,
        account: ParentAccount,
    ) -> Result<(), StaticPoolRejection> {
        let mut minimum_tip = self.policy.min_gas_tip_cap;
        if is_envelope(transaction.ty(), transaction.to(), transaction.input()) {
            let gas_limit = transaction.gas_limit();
            if U256::from(gas_limit) > self.policy.max_envelope_gas_limit {
                return Err(StaticPoolRejection::EnvelopeGasAbovePolicy {
                    gas_limit,
                    maximum_gas: self.policy.max_envelope_gas_limit,
                })
            }
            let inner_gas = encrypted_gas(transaction.input());
            if inner_gas < MIN_ENCRYPTED_GAS_LIMIT {
                return Err(StaticPoolRejection::EncryptedGasBelowMinimum(inner_gas))
            }
            if gas_limit < u64::from(inner_gas) {
                return Err(StaticPoolRejection::EnvelopeGasBelowEncrypted { gas_limit, inner_gas })
            }
            minimum_tip = minimum_tip.saturating_add(self.policy.envelope_fee);
        }
        let fee_cap = U256::from(transaction.max_fee_per_gas());
        let tip_cap = U256::from(transaction.priority_fee_or_price());
        // Geth computes a signed `feeCap - baseFee`; a negative value is below any minimum.
        let below_minimum = fee_cap
            .checked_sub(self.policy.base_fee)
            .is_none_or(|headroom| headroom.min(tip_cap) < minimum_tip);
        if below_minimum {
            return Err(StaticPoolRejection::TipBelowPolicy {
                minimum_tip,
                base_fee: self.policy.base_fee,
            })
        }
        if account.blacklisted {
            return Err(StaticPoolRejection::BlockedSender)
        }
        Ok(())
    }
}

/// Geth's `list.Add` replacement rule: both fee fields must strictly exceed the queued ones and
/// reach `old * (100 + PriceBump) / 100`.
fn outbids(old: &QueuedTransaction, max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> bool {
    let threshold =
        |old: u128| U256::from(old) * U256::from(100 + STATIC_POOL_PRICE_BUMP) / U256::from(100);
    max_fee_per_gas > old.max_fee_per_gas &&
        max_priority_fee_per_gas > old.max_priority_fee_per_gas &&
        U256::from(max_fee_per_gas) >= threshold(old.max_fee_per_gas) &&
        U256::from(max_priority_fee_per_gas) >= threshold(old.max_priority_fee_per_gas)
}

/// Geth's `SetCodeAuthorities`: recoverable authorities in list order, without duplicates.
fn set_code_authorities(transaction: &TransactionSigned) -> Vec<Address> {
    let mut authorities = Vec::new();
    for authorization in transaction.authorization_list().unwrap_or_default() {
        if let Ok(authority) = authorization.recover_authority() &&
            !authorities.contains(&authority)
        {
            authorities.push(authority);
        }
    }
    authorities
}

/// The legacy pool's maximum-cost rule: the gas ceiling at the fee cap plus the transferred value.
/// Blob transactions never reach it because the pool refuses their type first.
fn static_pool_max_cost(transaction: &TransactionSigned) -> U256 {
    U256::from(transaction.gas_limit())
        .checked_mul(U256::from(transaction.max_fee_per_gas()))
        .and_then(|cost| cost.checked_add(transaction.value()))
        .unwrap_or(U256::MAX)
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
        admission: &mut StaticPoolAdmission,
        execute: &mut impl FnMut(&TransactionSigned, Address) -> Result<(), String>,
    ) {
        if let Err(rejection) = admission.add(sender, outer) {
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
    admission: &mut StaticPoolAdmission,
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
                if let Err(rejection) = admission.add(sender, &transaction) {
                    sequence.include_fallback(
                        transaction_index,
                        outer,
                        sender,
                        AntiMevReplacementFallback::PoolRejection(rejection),
                        admission,
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
                            admission,
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
                    admission,
                    &mut execute,
                );
            }
            None => {
                if let Err(rejection) = admission.add(sender, outer) {
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

    use alloy_consensus::{Signed, Transaction, TxEip4844, TxEip7702, TxLegacy};
    use alloy_eips::eip4844::BlobTransactionSidecar;
    use alloy_primitives::{keccak256, Bytes, Signature, TxKind};
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
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_revm::{db::states::BundleState, primitives::StorageKeyMap};

    /// Parent header used by the sequencing tests: a gas limit above every transaction they build,
    /// under Prague rules so set-code transactions are admissible.
    const TEST_HEAD: StaticPoolHead =
        StaticPoolHead { gas_limit: 30_000_000, spec: SpecId::PRAGUE };

    /// Intrinsic gas of a plain transfer; test transactions add a small identifying offset.
    const TRANSFER_GAS: u64 = 21_000;

    /// Parent state funding every sender far beyond any cost the tests build, at nonce zero.
    fn funded(senders: &[Address]) -> MockEthProvider {
        let state = MockEthProvider::<EthPrimitives>::new();
        for sender in senders {
            state.add_account(*sender, ExtendedAccount::new(0, U256::from(u128::MAX)));
        }
        state
    }

    /// A legacy transfer at `gas_price` whose gas limit is `TRANSFER_GAS + id`.
    fn priced(nonce: u64, id: u64, gas_price: u128) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                nonce,
                gas_limit: TRANSFER_GAS + id,
                gas_price,
                to: TxKind::Call(Address::repeat_byte(id as u8)),
                ..Default::default()
            }),
            Signature::test_signature(),
        )
    }

    /// A 1 wei legacy transfer identified by `id`.
    fn transaction(nonce: u64, id: u64) -> TransactionSigned {
        priced(nonce, id, 1)
    }

    fn id(transaction: &TransactionSigned) -> u64 {
        transaction.gas_limit() - TRANSFER_GAS
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
        let outer = [transaction(0, 1), transaction(1, 2), transaction(0, 3), transaction(2, 4)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(0, 100)),
            },
        );
        resolutions.insert(
            2,
            AntiMevEnvelopeResolution::Fallback {
                transaction_index: 2,
                reason: AntiMevFallbackReason::TransactionDecoding,
            },
        );

        let senders = [sender_a, sender_b];
        let state = funded(&senders);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &senders).unwrap();
        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b, sender_a],
            &[0, 2],
            &mut admission,
            resolutions,
            |transaction, _| match id(transaction) {
                100 => Err("rejected 100".to_string()),
                _ => Ok(()),
            },
        );

        // The failed replacement stays queued at nonce zero, so the same-priced Envelope cannot
        // replace it and the sender is dropped.
        assert_eq!(sequence.transactions.iter().map(id).collect::<Vec<_>>(), [3]);
        assert_eq!(sequence.senders, [sender_b]);
        assert_eq!(
            sequence.decisions,
            [
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 0,
                    reason: AntiMevDropReason::PoolRejection(
                        StaticPoolRejection::ReplaceUnderpriced { nonce: 0 }
                    ),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 1,
                    reason: AntiMevDropReason::PriorSenderFailure,
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
    fn failed_outer_execution_drops_later_transactions_from_the_sender() {
        let sender = Address::repeat_byte(0xaa);
        let outer = [transaction(0, 1), transaction(1, 2)];
        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let sequence = execute_sequence(
            &outer,
            &[sender, sender],
            &[],
            &mut admission,
            HashMap::new(),
            |_, _| Err("rejected".to_string()),
        );
        assert!(sequence.transactions.is_empty());
        assert_eq!(
            sequence.decisions,
            [
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 0,
                    reason: AntiMevDropReason::OuterExecution("rejected".to_string()),
                },
                AntiMevTransactionDecision::Dropped {
                    transaction_index: 1,
                    reason: AntiMevDropReason::PriorSenderFailure,
                },
            ]
        );
    }

    #[test]
    fn includes_successful_decrypted_replacements() {
        let sender = Address::repeat_byte(0xaa);
        let outer = [transaction(0, 10)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(0, 50)),
            },
        );

        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let sequence =
            execute_sequence(&outer, &[sender], &[0], &mut admission, resolutions, |_, _| Ok(()));
        assert_eq!(id(&sequence.transactions[0]), 50);
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::IncludedDecrypted { transaction_index: 0 }]
        );
    }

    #[test]
    fn reconstruction_pool_drops_blob_transactions_and_later_transactions_from_their_sender() {
        let sender_a = Address::repeat_byte(0xaa);
        let sender_b = Address::repeat_byte(0xbb);
        let outer =
            [blob_transaction(B256::repeat_byte(1)), transaction(0, 20), transaction(0, 30)];

        let senders = [sender_a, sender_b];
        let state = funded(&senders);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &senders).unwrap();
        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b],
            &[],
            &mut admission,
            HashMap::new(),
            |_, _| Ok(()),
        );

        assert_eq!(sequence.transactions.iter().map(id).collect::<Vec<_>>(), [30]);
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
        let outer = [transaction(0, 10)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(priced(0, 50, 0)),
            },
        );

        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let sequence =
            execute_sequence(&outer, &[sender], &[0], &mut admission, resolutions, |_, _| Ok(()));

        // A refused replacement never reaches the queue, so the Envelope is admitted fresh.
        assert_eq!(id(&sequence.transactions[0]), 10);
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
    fn pool_admission_checks_parent_nonce_and_admits_gaps() {
        let sender = Address::repeat_byte(0xaa);
        let state = MockEthProvider::<EthPrimitives>::new();
        state.add_account(sender, ExtendedAccount::new(5, U256::from(1_000_000_u64)));
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();

        assert_eq!(
            admission.add(sender, &transaction(4, 1)),
            Err(StaticPoolRejection::NonceTooLow { nonce: 4, next: 5 })
        );
        admission.add(sender, &transaction(5, 2)).unwrap();
        // Nothing is promoted, so the parent nonce stays the floor and gaps are queued.
        admission.add(sender, &transaction(7, 3)).unwrap();
        admission.add(sender, &transaction(6, 4)).unwrap();
    }

    #[test]
    fn pool_admission_checks_each_cost_against_the_parent_balance_alone() {
        let sender = Address::repeat_byte(0xaa);
        let state = MockEthProvider::<EthPrimitives>::new();
        state.add_account(sender, ExtendedAccount::new(0, U256::from(TRANSFER_GAS + 25)));
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();

        // Pending is always empty in the reference pool, so queued costs are never summed.
        admission.add(sender, &transaction(0, 10)).unwrap();
        admission.add(sender, &transaction(1, 20)).unwrap();
        assert_eq!(
            admission.add(sender, &transaction(2, 30)),
            Err(StaticPoolRejection::InsufficientFunds {
                cost: U256::from(TRANSFER_GAS + 30),
                balance: U256::from(TRANSFER_GAS + 25),
            })
        );
    }

    #[test]
    fn pool_admission_requires_the_price_bump_and_refuses_known_hashes() {
        let sender = Address::repeat_byte(0xaa);
        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();

        admission.add(sender, &priced(0, 1, 100)).unwrap();
        assert_eq!(
            admission.add(sender, &priced(0, 1, 100)),
            Err(StaticPoolRejection::AlreadyKnown)
        );
        assert_eq!(
            admission.add(sender, &priced(0, 2, 109)),
            Err(StaticPoolRejection::ReplaceUnderpriced { nonce: 0 })
        );
        admission.add(sender, &priced(0, 3, 110)).unwrap();
        // The replaced hash leaves the pool and may be added again only by outbidding.
        assert_eq!(
            admission.add(sender, &priced(0, 1, 100)),
            Err(StaticPoolRejection::ReplaceUnderpriced { nonce: 0 })
        );
        // At wei-level prices both fields must still strictly increase.
        admission.add(sender, &priced(1, 4, 1)).unwrap();
        assert_eq!(
            admission.add(sender, &priced(1, 5, 1)),
            Err(StaticPoolRejection::ReplaceUnderpriced { nonce: 1 })
        );
        admission.add(sender, &priced(1, 6, 2)).unwrap();
    }

    #[test]
    fn pool_admission_applies_parent_policy() {
        let sender = Address::repeat_byte(0xaa);
        let blocked = Address::repeat_byte(0xbb);
        let state = funded(&[sender, blocked]);
        state.add_account(
            POLICY_PROXY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT).into(), U256::from(5)),
                (policy_storage_key(POLICY_BASE_FEE_SLOT).into(), U256::from(10)),
                (policy_blacklist_storage_key(blocked).into(), U256::from(1)),
            ]),
        );
        let mut admission =
            StaticPoolAdmission::new(&state, TEST_HEAD, &[sender, blocked]).unwrap();

        let tip_below = StaticPoolRejection::TipBelowPolicy {
            minimum_tip: U256::from(5),
            base_fee: U256::from(10),
        };
        // A legacy price below the Policy base fee is a negative tip.
        assert_eq!(admission.add(sender, &priced(0, 1, 9)), Err(tip_below));
        assert_eq!(admission.add(sender, &priced(0, 2, 14)), Err(tip_below));
        admission.add(sender, &priced(0, 3, 15)).unwrap();
        assert_eq!(
            admission.add(blocked, &priced(0, 4, 15)),
            Err(StaticPoolRejection::BlockedSender)
        );
    }

    #[test]
    fn pool_admission_applies_intrinsic_gas_at_the_parent_rules() {
        let sender = Address::repeat_byte(0xaa);
        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let short = TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                gas_limit: TRANSFER_GAS - 1,
                gas_price: 1,
                to: TxKind::Call(Address::ZERO),
                ..Default::default()
            }),
            Signature::test_signature(),
        );
        assert_eq!(
            admission.add(sender, &short),
            Err(StaticPoolRejection::IntrinsicGas {
                gas_limit: TRANSFER_GAS - 1,
                required: TRANSFER_GAS
            })
        );
    }

    #[test]
    fn pool_admission_limits_delegated_senders_to_their_parent_nonce() {
        let delegated = Address::repeat_byte(0xaa);
        let state = MockEthProvider::<EthPrimitives>::new();
        state.add_account(
            delegated,
            ExtendedAccount::new(3, U256::from(u128::MAX))
                .with_bytecode(Bytes::from_static(&[0x00])),
        );
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[delegated]).unwrap();
        assert_eq!(
            admission.add(delegated, &transaction(4, 1)),
            Err(StaticPoolRejection::DelegatedNonceGap { nonce: 4, next: 3 })
        );
        admission.add(delegated, &transaction(3, 2)).unwrap();
    }

    #[test]
    fn queued_authorizations_reserve_and_delegate_their_authorities() {
        use alloy_eips::eip7702::Authorization;
        use reth_primitives_traits::crypto::secp256k1::sign_message;

        let secret = B256::repeat_byte(0x42);
        let authorization =
            Authorization { chain_id: U256::ZERO, address: Address::repeat_byte(0x77), nonce: 0 };
        let signature = sign_message(secret, authorization.signature_hash()).unwrap();
        let signed = authorization.into_signed(signature);
        let authority = signed.recover_authority().unwrap();
        let set_code = |nonce, id: u64| {
            TransactionSigned::new_unhashed(
                EthereumTransaction::Eip7702(TxEip7702 {
                    nonce,
                    gas_limit: 100_000 + id,
                    max_fee_per_gas: 1,
                    max_priority_fee_per_gas: 1,
                    to: Address::repeat_byte(0x55),
                    authorization_list: vec![signed.clone()],
                    ..Default::default()
                }),
                Signature::test_signature(),
            )
        };

        let sponsor = Address::repeat_byte(0xcc);
        let state = funded(&[sponsor, authority]);
        let mut admission =
            StaticPoolAdmission::new(&state, TEST_HEAD, &[sponsor, authority]).unwrap();
        admission.add(sponsor, &set_code(0, 1)).unwrap();
        // A queued authorization subjects its authority to the delegation limit.
        assert_eq!(
            admission.add(authority, &transaction(1, 2)),
            Err(StaticPoolRejection::DelegatedNonceGap { nonce: 1, next: 0 })
        );
        admission.add(authority, &transaction(0, 3)).unwrap();
        admission.add(authority, &priced(0, 4, 2)).unwrap();
        // One queued transaction from the authority still leaves it authorizable.
        admission.add(sponsor, &set_code(1, 5)).unwrap();
    }

    #[test]
    fn decrypted_replacement_above_parent_balance_falls_back_to_the_envelope() {
        let sender = Address::repeat_byte(0xaa);
        // The replacement costs more than the parent balance while the Envelope fits it; execution
        // would fund the sender earlier in the block, but the pool never sees that effect.
        let outer = [transaction(0, 10)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(0, 20)),
            },
        );

        let state = MockEthProvider::<EthPrimitives>::new();
        state.add_account(sender, ExtendedAccount::new(0, U256::from(TRANSFER_GAS + 15)));
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let sequence =
            execute_sequence(&outer, &[sender], &[0], &mut admission, resolutions, |_, _| Ok(()));

        assert_eq!(id(&sequence.transactions[0]), 10);
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::IncludedFallback {
                transaction_index: 0,
                reason: AntiMevReplacementFallback::PoolRejection(
                    StaticPoolRejection::InsufficientFunds {
                        cost: U256::from(TRANSFER_GAS + 20),
                        balance: U256::from(TRANSFER_GAS + 15),
                    }
                ),
            }]
        );
    }

    #[test]
    fn failed_decrypted_execution_stays_queued_and_blocks_its_envelope() {
        let sender = Address::repeat_byte(0xaa);
        let outer = [transaction(0, 10)];
        let mut resolutions = HashMap::new();
        resolutions.insert(
            0,
            AntiMevEnvelopeResolution::Decrypted {
                transaction_index: 0,
                transaction: Box::new(transaction(0, 20)),
            },
        );

        let state = funded(&[sender]);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &[sender]).unwrap();
        let mut executed = Vec::new();
        let sequence =
            execute_sequence(&outer, &[sender], &[0], &mut admission, resolutions, |tx, _| {
                executed.push(id(tx));
                Err("rejected".to_string())
            });

        // The Envelope is never executed: the pool refuses it as an underpriced replacement.
        assert_eq!(executed, [20]);
        assert!(sequence.transactions.is_empty());
        assert_eq!(
            sequence.decisions,
            [AntiMevTransactionDecision::Dropped {
                transaction_index: 0,
                reason: AntiMevDropReason::PoolRejection(StaticPoolRejection::ReplaceUnderpriced {
                    nonce: 0
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
        let outer =
            [transaction(0, 10), transaction(1, 20), transaction(0, 30), transaction(0, 40)];
        let mut resolutions = HashMap::new();
        for (index, id) in [(1, 200), (2, 300), (3, 400)] {
            resolutions.insert(
                index,
                AntiMevEnvelopeResolution::Decrypted {
                    transaction_index: index,
                    transaction: Box::new(transaction(0, id)),
                },
            );
        }

        let senders = [sender_a, sender_b, sender_c];
        let state = funded(&senders);
        let mut admission = StaticPoolAdmission::new(&state, TEST_HEAD, &senders).unwrap();
        let sequence = execute_sequence(
            &outer,
            &[sender_a, sender_a, sender_b, sender_c],
            &[1, 2, 3],
            &mut admission,
            resolutions,
            |transaction, _| match id(transaction) {
                10 => Err("rejected 10".to_string()),
                _ => Ok(()),
            },
        );

        // A's Envelope is dropped for the prior failure without consuming the cursor, so the
        // Envelopes from B and C are no longer recognized and their outer transactions stand.
        assert_eq!(sequence.transactions.iter().map(id).collect::<Vec<_>>(), [30, 40]);
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
        let ordinary = transaction(0, 21_000);
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
