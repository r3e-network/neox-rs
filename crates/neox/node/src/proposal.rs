//! Deterministic execution and post-state validation for dBFT proposals.

use crate::{
    dkg::read_dkg_state_from_storage, validator::read_governance_validator_set_from_storage,
    DbftStateError, DkgState, DkgStateError, GovernanceValidatorSet,
};
use alloy_primitives::{keccak256, Address, B256, U256};
use reth_chainspec::EthereumHardforks;
use reth_consensus::{Consensus, FullConsensus};
use reth_ethereum_primitives::{Block, BlockBody, EthPrimitives, Receipt, TransactionSigned};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus::{next_consensus_hash, DbftExtraPrefix, ExtraVersion, SignatureScheme};
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::{NeoXEvmConfig, GOVERNANCE_PROXY_ADDRESS, KEY_MANAGEMENT_PROXY_ADDRESS};
use reth_neox_network::DbftPrepareRequest;
use reth_primitives_traits::{Block as _, RecoveredBlock};
use reth_provider::{StateProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use thiserror::Error;

/// A proposal whose transactions, EVM result, state root, and next-consensus commitments match.
#[derive(Debug)]
pub struct VerifiedProposal {
    /// Recovered executable block in the exact primary-proposed transaction order.
    pub block: RecoveredBlock<Block>,
    /// Receipts and post-state changes produced from the canonical parent state.
    pub execution: BlockExecutionOutput<Receipt>,
    /// Governance validator set read from the post-execution state.
    pub next_validators: GovernanceValidatorSet,
    /// Post-execution DKG state when the next height uses Anti-MEV consensus.
    pub next_dkg: Option<DkgState>,
}

/// Executes and validates a complete dBFT `PrepareRequest` without trusting the primary.
pub fn verify_proposal<Provider>(
    request: &DbftPrepareRequest,
    transactions: Vec<TransactionSigned>,
    provider: &Provider,
    evm_config: &NeoXEvmConfig,
    consensus: &NeoXConsensus,
    chain_spec: &NeoXChainSpec,
) -> Result<VerifiedProposal, DbftProposalError>
where
    Provider: StateProviderFactory,
{
    validate_transaction_hashes(request, &transactions)?;
    let header = request.sealing_proposal.clone();
    let prefix = DbftExtraPrefix::decode(&header.extra_data)
        .map_err(|error| DbftProposalError::InvalidExtra(error.to_string()))?;
    let expected_version = chain_spec.extra_version_at_block(header.number);
    if prefix.version() != expected_version {
        return Err(DbftProposalError::UnexpectedExtraVersion {
            expected: expected_version,
            actual: prefix.version(),
        })
    }
    if !chain_spec.is_anti_mev_active_at_block(header.number) &&
        matches!(prefix.signature_scheme(), SignatureScheme::Threshold)
    {
        return Err(DbftProposalError::ThresholdBeforeAntiMev)
    }

    let body = BlockBody {
        transactions,
        ommers: Vec::new(),
        withdrawals: chain_spec
            .is_shanghai_active_at_timestamp(header.timestamp)
            .then(Default::default),
    };
    let block = Block { header, body };
    let sealed = block.clone().seal_slow();
    consensus
        .validate_block_pre_execution(&sealed)
        .map_err(|error| DbftProposalError::PreExecution(error.to_string()))?;
    let recovered = block.try_into_recovered().map_err(|_| DbftProposalError::SenderRecovery)?;
    let state_provider = provider
        .state_by_block_hash(recovered.parent_hash)
        .map_err(|error| DbftProposalError::Provider(error.to_string()))?;
    let executor = evm_config.batch_executor(StateProviderDatabase::new(state_provider.as_ref()));
    let execution = executor
        .execute(&recovered)
        .map_err(|error| DbftProposalError::Execution(error.to_string()))?;
    <NeoXConsensus as FullConsensus<EthPrimitives>>::validate_block_post_execution(
        consensus,
        &recovered,
        &execution.result,
        None,
        None,
    )
    .map_err(|error| DbftProposalError::PostExecution(error.to_string()))?;
    let state_root = state_provider
        .state_root(state_provider.hashed_post_state(&execution.state))
        .map_err(|error| DbftProposalError::Provider(error.to_string()))?;
    if state_root != recovered.state_root {
        return Err(DbftProposalError::StateRoot {
            expected: recovered.state_root,
            actual: state_root,
        })
    }

    let next_validators = read_governance_validator_set_from_storage(|key| {
        post_storage(&execution, state_provider.as_ref(), GOVERNANCE_PROXY_ADDRESS, key)
            .map_err(DbftStateError::Provider)
    })?;
    let fallback_next_consensus = next_consensus_hash(&next_validators.sorted);
    if !matches!(prefix.version(), ExtraVersion::V0) &&
        prefix.fallback_next_consensus() != Some(fallback_next_consensus)
    {
        return Err(DbftProposalError::FallbackNextConsensus {
            expected: fallback_next_consensus,
            actual: prefix.fallback_next_consensus(),
        })
    }

    let next_height = recovered.number.checked_add(1).ok_or(DbftProposalError::HeightOverflow)?;
    let next_dkg = if chain_spec.is_anti_mev_active_at_block(next_height) {
        Some(read_dkg_state_from_storage(|key| {
            post_storage(&execution, state_provider.as_ref(), KEY_MANAGEMENT_PROXY_ADDRESS, key)
                .map_err(DkgStateError::Provider)
        })?)
    } else {
        None
    };
    let expected_next_consensus = next_dkg
        .as_ref()
        .map_or(fallback_next_consensus, |dkg| keccak256(dkg.current.global_public_key));
    if recovered.mix_hash != expected_next_consensus {
        return Err(DbftProposalError::NextConsensus {
            expected: expected_next_consensus,
            actual: recovered.mix_hash,
        })
    }

    Ok(VerifiedProposal { block: recovered, execution, next_validators, next_dkg })
}

fn validate_transaction_hashes(
    request: &DbftPrepareRequest,
    transactions: &[TransactionSigned],
) -> Result<(), DbftProposalError> {
    if request.transaction_hashes.len() != transactions.len() {
        return Err(DbftProposalError::TransactionCount {
            expected: request.transaction_hashes.len(),
            actual: transactions.len(),
        })
    }
    for (index, (expected, transaction)) in
        request.transaction_hashes.iter().zip(transactions).enumerate()
    {
        let actual = *transaction.tx_hash();
        if *expected != actual {
            return Err(DbftProposalError::TransactionHash { index, expected: *expected, actual })
        }
    }
    Ok(())
}

fn post_storage(
    execution: &BlockExecutionOutput<Receipt>,
    state: &dyn StateProvider,
    address: Address,
    key: B256,
) -> Result<Option<U256>, String> {
    let key = U256::from_be_bytes(key.0);
    if let Some(value) = execution.storage(&address, key) {
        return Ok(Some(value))
    }
    state.storage(address, key.into()).map_err(|error| error.to_string())
}

/// Deterministic proposal assembly or execution failure.
#[derive(Debug, Error)]
pub enum DbftProposalError {
    /// Proposal hash list and supplied transaction list differ in length.
    #[error("dBFT proposal transaction count mismatch: expected {expected}, got {actual}")]
    TransactionCount {
        /// Signed hash count.
        expected: usize,
        /// Supplied transaction count.
        actual: usize,
    },
    /// A supplied transaction does not occupy its signed proposal position.
    #[error("dBFT proposal transaction {index} hash mismatch: expected {expected}, got {actual}")]
    TransactionHash {
        /// Transaction position.
        index: usize,
        /// Hash signed by the primary.
        expected: B256,
        /// Supplied transaction hash.
        actual: B256,
    },
    /// Proposal extra prefix is malformed.
    #[error("invalid dBFT proposal extra data: {0}")]
    InvalidExtra(String),
    /// Proposal selected a fork-incompatible extra version.
    #[error("unexpected dBFT proposal extra version: expected {expected:?}, got {actual:?}")]
    UnexpectedExtraVersion {
        /// Version selected by the chain specification.
        expected: ExtraVersion,
        /// Proposal version.
        actual: ExtraVersion,
    },
    /// Threshold signing is not legal before Anti-MEV activation.
    #[error("threshold dBFT proposal received before Anti-MEV activation")]
    ThresholdBeforeAntiMev,
    /// Static body/header checks failed.
    #[error("invalid dBFT proposal before execution: {0}")]
    PreExecution(String),
    /// One or more transaction senders could not be recovered.
    #[error("failed to recover dBFT proposal transaction senders")]
    SenderRecovery,
    /// Canonical parent state could not be loaded or hashed.
    #[error("failed to access dBFT proposal state: {0}")]
    Provider(String),
    /// Neo X EVM execution failed.
    #[error("dBFT proposal execution failed: {0}")]
    Execution(String),
    /// Receipts, gas, logs bloom, or requests differ from the proposal.
    #[error("invalid dBFT proposal execution result: {0}")]
    PostExecution(String),
    /// Computed post-state root differs from the signed proposal.
    #[error("dBFT proposal state root mismatch: expected {expected}, got {actual}")]
    StateRoot {
        /// Root signed in the proposal.
        expected: B256,
        /// Root computed from execution.
        actual: B256,
    },
    /// Governance post-state could not be decoded.
    #[error(transparent)]
    Governance(#[from] DbftStateError),
    /// `KeyManagement` post-state could not be decoded.
    #[error(transparent)]
    Dkg(#[from] DkgStateError),
    /// V1/V2 fallback consensus commitment differs from Governance post-state.
    #[error("dBFT fallback next consensus mismatch: expected {expected}, got {actual:?}")]
    FallbackNextConsensus {
        /// Governance-derived commitment.
        expected: B256,
        /// Proposal commitment.
        actual: Option<B256>,
    },
    /// Header mix hash differs from the post-state-selected next consensus identifier.
    #[error("dBFT next consensus mismatch: expected {expected}, got {actual}")]
    NextConsensus {
        /// Governance or DKG-derived commitment.
        expected: B256,
        /// Proposal mix hash.
        actual: B256,
    },
    /// No height follows `u64::MAX`.
    #[error("dBFT proposal height overflow")]
    HeightOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;

    #[test]
    fn rejects_missing_transactions_before_state_access() {
        let request = DbftPrepareRequest {
            sealing_proposal: Header::default(),
            transaction_hashes: vec![B256::repeat_byte(0x11)],
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        assert!(matches!(
            validate_transaction_hashes(&request, &[]),
            Err(DbftProposalError::TransactionCount { expected: 1, actual: 0 })
        ));
    }

    #[test]
    fn accepts_empty_transaction_commitment() {
        let request = DbftPrepareRequest {
            sealing_proposal: Header::default(),
            transaction_hashes: Vec::new(),
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        validate_transaction_hashes(&request, &[]).unwrap();
    }
}
