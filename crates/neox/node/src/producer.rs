//! Deterministic dBFT primary proposal construction from the canonical state and transaction pool.

use crate::{
    dkg::read_dkg_state_from_storage, validator::read_governance_validator_set_from_storage,
    DbftRoundState, DbftStateError, DkgStateError, GovernanceValidatorSet,
};
use alloy_consensus::{constants::EMPTY_ROOT_HASH, Header};
use alloy_eips::{eip1559::calculate_block_gas_limit, eip4895::Withdrawals};
use alloy_primitives::{keccak256, B256, B64, U256};
use reth_chainspec::EthereumHardforks;
use reth_ethereum_primitives::{PooledTransactionVariant, TransactionSigned};
use reth_evm::{
    execute::{BlockBuilder, BlockExecutionError, BlockValidationError},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus::{
    next_consensus_hash, DbftExtraPrefix, ExtraVersion, SignatureScheme, DIFFICULTY_IN_TURN,
    DIFFICULTY_OUT_OF_TURN,
};
use reth_neox_evm::{
    policy_storage_key, NeoXEvmConfig, GOVERNANCE_REWARD_PROXY_ADDRESS,
    KEY_MANAGEMENT_PROXY_ADDRESS, POLICY_BASE_FEE_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_network::DbftPrepareRequest;
use reth_provider::{HeaderProvider, StateProvider, StateProviderFactory};
use reth_revm::{database::StateProviderDatabase, db::State, Database};
use reth_transaction_pool::{
    error::InvalidPoolTransactionError, BestTransactions, BestTransactionsAttributes,
    PoolTransaction, TransactionPool,
};
use std::fmt;
use thiserror::Error;
use tracing::{debug, trace};

/// Neo X Geth's default target block gas limit.
pub const DEFAULT_PRIMARY_GAS_LIMIT: u64 = 60_000_000;

/// Inputs controlled by the active dBFT view and local validator configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryProposalAttributes {
    /// Active dBFT view.
    pub view: u8,
    /// Unix timestamp captured when construction starts.
    pub timestamp: u64,
    /// Block-signature scheme selected for this round.
    pub signature_scheme: SignatureScheme,
    /// Gas-limit target approached with Ethereum's bounded adjustment rule.
    pub desired_gas_limit: u64,
}

impl PrimaryProposalAttributes {
    /// Creates attributes using Neo X Geth's canonical gas-limit target.
    pub const fn new(view: u8, timestamp: u64, signature_scheme: SignatureScheme) -> Self {
        Self { view, timestamp, signature_scheme, desired_gas_limit: DEFAULT_PRIMARY_GAS_LIMIT }
    }
}

/// Executed primary proposal ready to be signed as a dBFT `PrepareRequest`.
#[derive(Debug)]
pub struct PrimaryProposal {
    /// Header and ordered transaction-hash commitment sent over `dbft/0`.
    pub request: DbftPrepareRequest,
    /// Exact transactions used to execute the committed header.
    pub transactions: Vec<TransactionSigned>,
}

/// Builds a proposal exactly as a backup will subsequently execute and verify it.
pub fn build_primary_proposal<Pool, Provider>(
    round: &DbftRoundState,
    attributes: PrimaryProposalAttributes,
    pool: &Pool,
    provider: &Provider,
    evm_config: &NeoXEvmConfig,
    chain_spec: &NeoXChainSpec,
) -> Result<PrimaryProposal, PrimaryProposalError>
where
    Pool: TransactionPool<
        Transaction: PoolTransaction<
            Consensus = TransactionSigned,
            Pooled = PooledTransactionVariant,
        >,
    >,
    Provider: HeaderProvider<Header = Header> + StateProviderFactory,
{
    if attributes.view != round.current_view() {
        return Err(PrimaryProposalError::StaleView {
            expected: round.current_view(),
            actual: attributes.view,
        })
    }
    if matches!(attributes.signature_scheme, SignatureScheme::Threshold) && !round.anti_mev() {
        return Err(PrimaryProposalError::ThresholdBeforeAntiMev)
    }
    let parent_number = round.height().checked_sub(1).ok_or(PrimaryProposalError::GenesisHeight)?;
    let parent = provider
        .sealed_header(parent_number)
        .map_err(|error| PrimaryProposalError::Provider(error.to_string()))?
        .ok_or(PrimaryProposalError::MissingParent(parent_number))?;
    let state_provider = provider
        .state_by_block_hash(parent.hash())
        .map_err(|error| PrimaryProposalError::Provider(error.to_string()))?;
    let policy_base_fee = state_provider
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(POLICY_BASE_FEE_SLOT).into())
        .map_err(|error| PrimaryProposalError::Provider(error.to_string()))?
        .unwrap_or_default();
    let policy_base_fee = u64::try_from(policy_base_fee)
        .map_err(|_| PrimaryProposalError::PolicyBaseFeeOverflow(policy_base_fee))?;
    let primary = u8::try_from(round.primary_index(attributes.view))
        .map_err(|_| PrimaryProposalError::PrimaryIndexOverflow)?;
    let difficulty = primary_difficulty(round.height(), primary, round.validators().len());
    let timestamp = attributes.timestamp.max(parent.timestamp);
    let gas_limit = calculate_block_gas_limit(parent.gas_limit, attributes.desired_gas_limit);
    let next_attributes = NextBlockEnvAttributes {
        timestamp,
        suggested_fee_recipient: GOVERNANCE_REWARD_PROXY_ADDRESS,
        prev_randao: B256::ZERO,
        gas_limit,
        parent_beacon_block_root: chain_spec
            .is_cancun_active_at_timestamp(timestamp)
            .then_some(EMPTY_ROOT_HASH),
        withdrawals: chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(Withdrawals::default),
        extra_data: Default::default(),
        slot_number: None,
    };

    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(state_provider.as_ref()))
        .with_bundle_update()
        .build();
    let mut evm_env = evm_config
        .next_evm_env(parent.header(), &next_attributes)
        .unwrap_or_else(|never| match never {});
    evm_env.block_env.basefee = policy_base_fee;
    evm_env.block_env.difficulty = U256::from(difficulty);
    let evm = evm_config.evm_with_env(&mut state, evm_env);
    let context = evm_config
        .context_for_next_block(&parent, next_attributes)
        .unwrap_or_else(|never| match never {});
    let mut builder = evm_config.create_block_builder(evm, &parent, context);
    builder.apply_pre_execution_changes()?;

    let mut best_transactions = pool
        .best_transactions_with_attributes(BestTransactionsAttributes::base_fee(policy_base_fee));
    best_transactions.no_updates();
    // Blob sidecars need to be committed and propagated alongside the proposal. Until that path is
    // active, excluding blob transactions keeps every signed proposal independently executable.
    best_transactions.skip_blobs();
    while let Some(pool_transaction) = best_transactions.next() {
        let transaction_hash = *pool_transaction.hash();
        let transaction_gas_limit = pool_transaction.gas_limit();
        match builder.execute_transaction(pool_transaction.to_consensus()) {
            Ok(_) => {}
            Err(BlockExecutionError::Validation(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    block_available_gas,
                    ..
                },
            )) => {
                best_transactions.mark_invalid(
                    &pool_transaction,
                    InvalidPoolTransactionError::ExceedsGasLimit(
                        transaction_gas_limit,
                        block_available_gas,
                    ),
                );
            }
            Err(BlockExecutionError::Validation(error)) => {
                trace!(target: "neox::producer", %transaction_hash, %error, "Skipped invalid primary candidate transaction");
                best_transactions.mark_invalid(
                    &pool_transaction,
                    InvalidPoolTransactionError::Consensus(
                        reth_primitives_traits::transaction::error::InvalidTransactionError::TxTypeNotSupported,
                    ),
                );
            }
            Err(error) => return Err(PrimaryProposalError::Execution(error.to_string())),
        }
    }

    let next_validators = {
        let state = builder.evm_mut().db_mut();
        read_governance_validator_set_from_storage(|key| {
            post_storage(state, reth_neox_evm::GOVERNANCE_PROXY_ADDRESS, key)
                .map_err(DbftStateError::Provider)
        })
        .map_err(|error| PrimaryProposalError::Governance(error.to_string()))?
    };
    let next_height = round.height().checked_add(1).ok_or(PrimaryProposalError::HeightOverflow)?;
    let next_dkg = if chain_spec.is_anti_mev_active_at_block(next_height) {
        let state = builder.evm_mut().db_mut();
        Some(
            read_dkg_state_from_storage(|key| {
                post_storage(state, KEY_MANAGEMENT_PROXY_ADDRESS, key)
                    .map_err(DkgStateError::Provider)
            })
            .map_err(|error| PrimaryProposalError::Dkg(error.to_string()))?,
        )
    } else {
        None
    };
    let outcome = builder
        .finish(state_provider.as_ref(), None)
        .map_err(|error| PrimaryProposalError::Execution(error.to_string()))?;
    let mut block = outcome.block.into_block();
    finalize_primary_header(
        &mut block.header,
        round.height(),
        primary,
        difficulty,
        attributes.signature_scheme,
        &next_validators,
        next_dkg.as_ref().map(|state| state.current.global_public_key),
        chain_spec,
    )?;
    let transactions = block.body.transactions;
    let transaction_hashes =
        transactions.iter().map(|transaction| *transaction.tx_hash()).collect::<Vec<_>>();
    debug!(
        target: "neox::producer",
        block_number = round.height(),
        view = attributes.view,
        primary,
        transactions = transactions.len(),
        gas_used = block.header.gas_used,
        state_root = %block.header.state_root,
        "Built Neo X dBFT primary proposal"
    );
    Ok(PrimaryProposal {
        request: DbftPrepareRequest {
            sealing_proposal: block.header,
            transaction_hashes,
            parent_seal_hash_v0: None,
            parent_extra: None,
        },
        transactions,
    })
}

#[allow(clippy::too_many_arguments)]
fn finalize_primary_header(
    header: &mut Header,
    height: u64,
    primary: u8,
    difficulty: u64,
    signature_scheme: SignatureScheme,
    next_validators: &GovernanceValidatorSet,
    next_dkg_public_key: Option<[u8; 48]>,
    chain_spec: &NeoXChainSpec,
) -> Result<(), PrimaryProposalError> {
    let fallback_next_consensus = next_consensus_hash(&next_validators.sorted);
    let version = chain_spec.extra_version_at_block(height);
    let fallback = (!matches!(version, ExtraVersion::V0)).then_some(fallback_next_consensus);
    header.extra_data = DbftExtraPrefix::new(version, signature_scheme, fallback)
        .map_err(|error| PrimaryProposalError::Extra(error.to_string()))?
        .encode();
    header.mix_hash = match next_dkg_public_key {
        Some(public_key) => keccak256(public_key),
        None => fallback_next_consensus,
    };
    header.nonce = B64::from(u64::from(primary).to_be_bytes());
    header.difficulty = U256::from(difficulty);
    Ok(())
}

fn primary_difficulty(height: u64, primary: u8, validator_count: usize) -> u64 {
    if validator_count > 0 && height % validator_count as u64 == u64::from(primary) {
        DIFFICULTY_IN_TURN
    } else {
        DIFFICULTY_OUT_OF_TURN
    }
}

fn post_storage<DB>(
    state: &mut State<DB>,
    address: alloy_primitives::Address,
    key: B256,
) -> Result<Option<U256>, String>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    state.storage(address, U256::from_be_bytes(key.0)).map(Some).map_err(|error| error.to_string())
}

/// Fatal failure while constructing a local primary proposal.
#[derive(Debug, Error)]
pub enum PrimaryProposalError {
    /// The build completed or started after the round changed view.
    #[error("stale dBFT primary build view: expected {expected}, got {actual}")]
    StaleView {
        /// Currently active view.
        expected: u8,
        /// View requested by the build.
        actual: u8,
    },
    /// Threshold signatures are not enabled before the Anti-MEV fork.
    #[error("threshold primary proposal requested before Anti-MEV activation")]
    ThresholdBeforeAntiMev,
    /// Block zero cannot be produced by an active dBFT round.
    #[error("cannot produce a dBFT genesis block")]
    GenesisHeight,
    /// The next block height overflowed.
    #[error("Neo X primary proposal height overflow")]
    HeightOverflow,
    /// The active primary index does not fit the wire representation.
    #[error("Neo X primary validator index exceeds u8")]
    PrimaryIndexOverflow,
    /// Canonical parent header is absent.
    #[error("missing canonical parent header {0}")]
    MissingParent(u64),
    /// Canonical state access failed.
    #[error("failed to access canonical Neo X state: {0}")]
    Provider(String),
    /// Policy's base fee does not fit the EVM header field.
    #[error("PolicyProxy base fee exceeds u64: {0}")]
    PolicyBaseFeeOverflow(U256),
    /// Block execution or state-root assembly failed.
    #[error("failed to execute Neo X primary proposal: {0}")]
    Execution(String),
    /// Governance post-state could not be decoded.
    #[error("failed to resolve next Governance validators: {0}")]
    Governance(String),
    /// DKG post-state could not be decoded.
    #[error("failed to resolve next DKG key: {0}")]
    Dkg(String),
    /// dBFT extra prefix could not be constructed.
    #[error("failed to construct dBFT proposal extra: {0}")]
    Extra(String),
}

impl From<BlockExecutionError> for PrimaryProposalError {
    fn from(error: BlockExecutionError) -> Self {
        Self::Execution(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use reth_neox_consensus::DbftExtraPrefix;

    fn validator_set() -> GovernanceValidatorSet {
        let sorted = (1..=7).map(Address::repeat_byte).collect::<Vec<_>>();
        GovernanceValidatorSet { original: sorted.clone(), sorted, dkg_indices: (1..=7).collect() }
    }

    #[test]
    fn primary_header_uses_view_primary_and_next_consensus() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let height = 42;
        let primary = (height % 7) as u8;
        let difficulty = primary_difficulty(height, primary, validators.sorted.len());
        let mut header = Header { number: height, ..Default::default() };

        finalize_primary_header(
            &mut header,
            height,
            primary,
            difficulty,
            SignatureScheme::Ecdsa,
            &validators,
            None,
            chain_spec.as_ref(),
        )
        .unwrap();

        assert_eq!(header.nonce.0, u64::from(primary).to_be_bytes());
        assert_eq!(header.difficulty, U256::from(DIFFICULTY_IN_TURN));
        assert_eq!(header.mix_hash, next_consensus_hash(&validators.sorted));
        let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
        assert_eq!(prefix.version(), ExtraVersion::V0);
        assert_eq!(prefix.signature_scheme(), SignatureScheme::Ecdsa);
    }

    #[test]
    fn anti_mev_header_commits_fallback_and_dkg_key() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let height = chain_spec.neox.anti_mev_block;
        let primary = ((height + 7 - 1) % 7) as u8;
        let difficulty = primary_difficulty(height, primary, validators.sorted.len());
        let public_key = [0x23; 48];
        let mut header = Header { number: height, ..Default::default() };

        finalize_primary_header(
            &mut header,
            height,
            primary,
            difficulty,
            SignatureScheme::Threshold,
            &validators,
            Some(public_key),
            chain_spec.as_ref(),
        )
        .unwrap();

        let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
        assert_eq!(prefix.signature_scheme(), SignatureScheme::Threshold);
        assert_eq!(prefix.fallback_next_consensus(), Some(next_consensus_hash(&validators.sorted)));
        assert_eq!(header.mix_hash, keccak256(public_key));
        assert_eq!(header.difficulty, U256::from(DIFFICULTY_OUT_OF_TURN));
    }
}
