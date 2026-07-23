//! Deterministic dBFT primary proposal construction from the canonical state and transaction pool.

use crate::{
    dkg::read_dkg_state_from_storage, pool::validate_envelope_ciphertext,
    validator::read_governance_validator_set_from_storage, DbftRoundState, DbftStateError,
    DkgState, DkgStateError, GovernanceValidatorSet,
};
use alloy_consensus::{constants::EMPTY_ROOT_HASH, Header, Transaction as _, Typed2718 as _};
use alloy_eips::{eip1559::calculate_block_gas_limit, eip4895::Withdrawals};
use alloy_primitives::{keccak256, Bytes, B256, B64, U256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_primitives::{PooledTransactionVariant, TransactionSigned};
use reth_evm::{
    execute::{BlockBuilder, BlockExecutionError, BlockValidationError},
    ConfigureEvm, Evm, NextBlockEnvAttributes,
};
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus::{
    ecdsa_seal_hash, next_consensus_hash, DbftExtraError, DbftExtraPrefix, ExtraVersion,
    SignatureScheme, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN,
};
use reth_neox_evm::{
    policy_storage_key, NeoXEvmConfig, GOVERNANCE_REWARD_PROXY_ADDRESS,
    KEY_MANAGEMENT_PROXY_ADDRESS, POLICY_BASE_FEE_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_network::{BeaconBlobSidecar, DbftPrepareRequest};
use reth_provider::{HeaderProvider, StateProvider, StateProviderFactory};
use reth_revm::{
    context_interface::Block as _, database::StateProviderDatabase, db::State, Database,
};
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use std::{fmt, sync::Arc};
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
    /// Validated pool sidecars in blob-transaction order.
    pub sidecars: Vec<BeaconBlobSidecar>,
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
        });
    }
    if matches!(attributes.signature_scheme, SignatureScheme::Threshold) && !round.anti_mev() {
        return Err(PrimaryProposalError::ThresholdBeforeAntiMev);
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

    let blob_fee = builder.evm_mut().block().blob_gasprice().map(|gasprice| gasprice as u64);
    let mut best_transactions = pool.best_transactions_with_attributes(
        BestTransactionsAttributes::new(policy_base_fee, blob_fee),
    );
    best_transactions.no_updates();
    let maximum_blob_count = chain_spec
        .blob_params_at_timestamp(timestamp)
        .map(|params| params.max_blob_count)
        .unwrap_or_default();
    let is_osaka = chain_spec.is_osaka_active_at_timestamp(timestamp);
    let mut block_blob_count = 0;
    let mut sidecars = Vec::new();
    while let Some(pool_transaction) = best_transactions.next() {
        let transaction_hash = *pool_transaction.hash();
        if reject_invalid_envelope_candidate(pool, &mut best_transactions, &pool_transaction) {
            continue;
        }
        let transaction_gas_limit = pool_transaction.gas_limit();
        let transaction_blob_count = pool_transaction.to_consensus().blob_count();
        let blob_sidecar = if let Some(transaction_blob_count) = transaction_blob_count {
            if block_blob_count + transaction_blob_count > maximum_blob_count {
                best_transactions.mark_invalid(
                    &pool_transaction,
                    InvalidPoolTransactionError::Eip4844(
                        Eip4844PoolTransactionError::TooManyEip4844Blobs {
                            have: block_blob_count + transaction_blob_count,
                            permitted: maximum_blob_count,
                        },
                    ),
                );
                continue;
            }
            let sidecar = match pool
                .get_blob(transaction_hash)
                .map_err(|error| PrimaryProposalError::BlobStore(error.to_string()))?
            {
                Some(sidecar) => sidecar,
                None => {
                    best_transactions.mark_invalid(
                        &pool_transaction,
                        InvalidPoolTransactionError::Eip4844(
                            Eip4844PoolTransactionError::MissingEip4844BlobSidecar,
                        ),
                    );
                    continue;
                }
            };
            let version_error = if is_osaka && !sidecar.is_eip7594() {
                Some(Eip4844PoolTransactionError::UnexpectedEip4844SidecarAfterOsaka)
            } else if !is_osaka && !sidecar.is_eip4844() {
                Some(Eip4844PoolTransactionError::UnexpectedEip7594SidecarBeforeOsaka)
            } else {
                None
            };
            if let Some(error) = version_error {
                best_transactions
                    .mark_invalid(&pool_transaction, InvalidPoolTransactionError::Eip4844(error));
                continue;
            }
            Some(sidecar)
        } else {
            None
        };
        match builder.execute_transaction(pool_transaction.to_consensus()) {
            Ok(_) => {
                if let Some(transaction_blob_count) = transaction_blob_count {
                    block_blob_count += transaction_blob_count;
                    if block_blob_count == maximum_blob_count {
                        best_transactions.skip_blobs();
                    }
                }
                if let Some(sidecar) = blob_sidecar {
                    sidecars.push(BeaconBlobSidecar::from(sidecar.as_ref().clone()));
                }
            }
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
        read_next_dkg_or_fallback(true, |key| {
            post_storage(state, KEY_MANAGEMENT_PROXY_ADDRESS, key).map_err(DkgStateError::Provider)
        })
    } else {
        None
    };
    let outcome = builder
        .finish(state_provider.as_ref(), None)
        .map_err(|error| PrimaryProposalError::Execution(error.to_string()))?;
    let mut block = outcome.block.into_block();
    PrimaryHeaderFinalization {
        primary,
        difficulty,
        signature_scheme: attributes.signature_scheme,
        next_validators: &next_validators,
        next_dkg_public_key: next_dkg.as_ref().map(|state| state.current.global_public_key),
        chain_spec,
    }
    .apply(&mut block.header)?;
    let transactions = block.body.transactions;
    let transaction_hashes =
        transactions.iter().map(|transaction| *transaction.tx_hash()).collect::<Vec<_>>();
    debug!(
        target: "neox::producer",
        block_number = round.height(),
        view = attributes.view,
        primary,
        transactions = transactions.len(),
        blobs = block_blob_count,
        gas_used = block.header.gas_used,
        state_root = %block.header.state_root,
        "Built Neo X dBFT primary proposal"
    );
    let (parent_seal_hash_v0, parent_extra) = parent_reseal_witness(parent.header())
        .map_err(|error| PrimaryProposalError::Extra(error.to_string()))?;
    Ok(PrimaryProposal {
        request: DbftPrepareRequest {
            sealing_proposal: block.header,
            transaction_hashes,
            parent_seal_hash_v0,
            parent_extra,
        },
        transactions,
        sidecars,
    })
}

fn reject_invalid_envelope_candidate<Pool, Best>(
    pool: &Pool,
    best_transactions: &mut Best,
    pool_transaction: &Arc<ValidPoolTransaction<Pool::Transaction>>,
) -> bool
where
    Pool: TransactionPool,
    Best: BestTransactions<Item = Arc<ValidPoolTransaction<Pool::Transaction>>>,
{
    let Err(error) = validate_envelope_ciphertext(
        pool_transaction.transaction.ty(),
        pool_transaction.transaction.kind().to().copied(),
        pool_transaction.transaction.input(),
    ) else {
        return false
    };

    let transaction_hash = *pool_transaction.hash();
    trace!(target: "neox::producer", %transaction_hash, %error, "Evicting invalid Anti-MEV Envelope from primary candidates");
    best_transactions.mark_invalid(pool_transaction, error);
    let removed = pool.remove_transaction(transaction_hash).is_some();
    debug!(target: "neox::producer", %transaction_hash, removed, "Discarded invalid Anti-MEV Envelope from transaction pool");
    true
}

struct PrimaryHeaderFinalization<'a> {
    primary: u8,
    difficulty: u64,
    signature_scheme: SignatureScheme,
    next_validators: &'a GovernanceValidatorSet,
    next_dkg_public_key: Option<[u8; 48]>,
    chain_spec: &'a NeoXChainSpec,
}

impl PrimaryHeaderFinalization<'_> {
    fn apply(self, header: &mut Header) -> Result<(), PrimaryProposalError> {
        apply_next_consensus_commitments(
            header,
            self.signature_scheme,
            self.next_validators,
            self.next_dkg_public_key,
            self.chain_spec,
        )
        .map_err(|error| PrimaryProposalError::Extra(error.to_string()))?;
        header.nonce = B64::from(u64::from(self.primary).to_be_bytes());
        header.difficulty = U256::from(self.difficulty);
        Ok(())
    }
}

pub(crate) fn apply_next_consensus_commitments(
    header: &mut Header,
    signature_scheme: SignatureScheme,
    next_validators: &GovernanceValidatorSet,
    next_dkg_public_key: Option<[u8; 48]>,
    chain_spec: &NeoXChainSpec,
) -> Result<(), DbftExtraError> {
    let fallback_next_consensus = next_consensus_hash(&next_validators.sorted);
    let version = chain_spec.extra_version_at_block(header.number);
    let fallback = (!matches!(version, ExtraVersion::V0)).then_some(fallback_next_consensus);
    header.extra_data = DbftExtraPrefix::new(version, signature_scheme, fallback)?.encode();
    header.mix_hash = match next_dkg_public_key {
        Some(public_key) => keccak256(public_key),
        None if chain_spec.is_anti_mev_active_at_block(header.number.saturating_add(1)) => {
            B256::ZERO
        }
        None => fallback_next_consensus,
    };
    Ok(())
}

pub(crate) fn read_next_dkg_or_fallback(
    anti_mev_active: bool,
    storage: impl FnMut(B256) -> Result<Option<U256>, DkgStateError>,
) -> Option<DkgState> {
    if !anti_mev_active {
        return None
    }
    match read_dkg_state_from_storage(storage) {
        Ok(state) => Some(state),
        Err(error) => {
            debug!(target: "neox::dkg", %error, "Using ECDSA fallback for unavailable next DKG state");
            None
        }
    }
}

fn primary_difficulty(height: u64, primary: u8, validator_count: usize) -> u64 {
    if validator_count > 0 && height % validator_count as u64 == u64::from(primary) {
        DIFFICULTY_IN_TURN
    } else {
        DIFFICULTY_OUT_OF_TURN
    }
}

/// Returns the parent seal hash and witness a proposal must carry so a backup holding a different
/// honest quorum subset of the same parent can reseal it to this proposal's parent hash.
///
/// An ECDSA parent can be sealed with different honest quorum subsets, giving the same dBFT seal
/// hash but different block hashes, so the primary must publish the exact witness it built on.
/// Threshold parents hash deterministically and never need a reseal witness.
fn parent_reseal_witness(parent: &Header) -> Result<(Option<B256>, Option<Bytes>), DbftExtraError> {
    match DbftExtraPrefix::decode(&parent.extra_data) {
        Ok(prefix) if matches!(prefix.signature_scheme(), SignatureScheme::Ecdsa) => {
            Ok((Some(ecdsa_seal_hash(parent)?), Some(parent.extra_data.clone())))
        }
        _ => Ok((None, None)),
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
    /// The transaction pool blob store could not be read.
    #[error("failed to read Neo X blob sidecar store: {0}")]
    BlobStore(String),
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
    use alloy_consensus::{TxLegacy, TxType};
    use alloy_primitives::{hex, Address, Signature, TxKind};
    use reth_ethereum_primitives::Transaction as EthereumTransaction;
    use reth_neox_antimev::{
        ENCRYPTED_DATA_PREFIX, ENVELOPE_TARGET, MIN_ENCRYPTED_MESSAGE_LEN, TPKE_SERIALIZED_LEN,
    };
    use reth_neox_consensus::DbftExtraPrefix;
    use reth_neox_evm::{
        uint_mapping_storage_key, KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT,
        KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
    };
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, test_utils::OkValidator, CoinbaseTipOrdering,
        EthPooledTransaction, Pool, TransactionOrigin,
    };
    use std::collections::HashMap;

    const VALID_CIPHERTEXT: [u8; TPKE_SERIALIZED_LEN] = hex!(
        "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
         966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
         8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
         8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
         cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
         17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
    );

    fn malformed_envelope_pool_transaction() -> EthPooledTransaction {
        let mut ciphertext = VALID_CIPHERTEXT;
        ciphertext[reth_neox_antimev::G1_COMPRESSED_LEN * 2] ^= 0x20;
        let mut input = Vec::new();
        input.extend_from_slice(&ENCRYPTED_DATA_PREFIX);
        input.extend_from_slice(&8_u32.to_be_bytes());
        input.extend_from_slice(&35_000_u32.to_be_bytes());
        input.extend_from_slice(B256::repeat_byte(0x42).as_slice());
        input.extend_from_slice(&ciphertext);
        input.resize(input.len() + MIN_ENCRYPTED_MESSAGE_LEN, 0x42);
        let transaction = TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                gas_limit: 100_000,
                gas_price: 1_000_000_000,
                to: TxKind::Call(ENVELOPE_TARGET),
                input: input.into(),
                ..Default::default()
            }),
            Signature::test_signature(),
        );
        assert_eq!(transaction.ty(), TxType::Legacy as u8);
        EthPooledTransaction::try_from_consensus(Recovered::new_unchecked(
            transaction,
            Address::repeat_byte(0x11),
        ))
        .unwrap()
    }

    fn validator_set() -> GovernanceValidatorSet {
        let sorted = (1..=7).map(Address::repeat_byte).collect::<Vec<_>>();
        GovernanceValidatorSet { original: sorted.clone(), sorted, dkg_indices: (1..=7).collect() }
    }

    #[tokio::test]
    async fn invalid_envelope_is_evicted_before_repeated_primary_selection() {
        // A permissive validator models an invalid transaction retained from before this admission
        // rule, and ensures the producer's independent defense is what removes it.
        type TestPool = Pool<
            OkValidator<EthPooledTransaction>,
            CoinbaseTipOrdering<EthPooledTransaction>,
            InMemoryBlobStore,
        >;
        let pool: TestPool = Pool::new(
            OkValidator::default(),
            CoinbaseTipOrdering::default(),
            InMemoryBlobStore::default(),
            Default::default(),
        );
        let transaction = malformed_envelope_pool_transaction();
        let transaction_hash = *transaction.hash();
        pool.add_transaction(TransactionOrigin::External, transaction).await.unwrap();
        assert!(pool.contains(&transaction_hash));

        let mut first_selection = pool.best_transactions();
        first_selection.no_updates();
        let candidate = first_selection.next().expect("malformed Envelope is initially pending");
        assert!(reject_invalid_envelope_candidate(&pool, &mut first_selection, &candidate,));
        assert!(first_selection.next().is_none());
        assert!(!pool.contains(&transaction_hash));

        let mut repeated_selection = pool.best_transactions();
        repeated_selection.no_updates();
        assert!(repeated_selection.next().is_none());
    }

    #[test]
    fn primary_header_uses_view_primary_and_next_consensus() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let height = 42;
        let primary = (height % 7) as u8;
        let difficulty = primary_difficulty(height, primary, validators.sorted.len());
        let mut header = Header { number: height, ..Default::default() };

        PrimaryHeaderFinalization {
            primary,
            difficulty,
            signature_scheme: SignatureScheme::Ecdsa,
            next_validators: &validators,
            next_dkg_public_key: None,
            chain_spec: chain_spec.as_ref(),
        }
        .apply(&mut header)
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

        PrimaryHeaderFinalization {
            primary,
            difficulty,
            signature_scheme: SignatureScheme::Threshold,
            next_validators: &validators,
            next_dkg_public_key: Some(public_key),
            chain_spec: chain_spec.as_ref(),
        }
        .apply(&mut header)
        .unwrap();

        let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
        assert_eq!(prefix.signature_scheme(), SignatureScheme::Threshold);
        assert_eq!(prefix.fallback_next_consensus(), Some(next_consensus_hash(&validators.sorted)));
        assert_eq!(header.mix_hash, keccak256(public_key));
        assert_eq!(header.difficulty, U256::from(DIFFICULTY_OUT_OF_TURN));
    }

    #[test]
    fn anti_mev_header_uses_zero_threshold_commitment_when_dkg_state_is_unavailable() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let height = chain_spec.neox.anti_mev_block;
        let missing = HashMap::<B256, U256>::new();
        let mut malformed =
            HashMap::from([(U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into(), U256::from(1))]);
        malformed.insert(
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(1))
                .into(),
            U256::from(4),
        );

        for storage in [&missing, &malformed] {
            let next_dkg = read_next_dkg_or_fallback(true, |key| Ok(storage.get(&key).copied()));
            assert!(next_dkg.is_none());
            let mut header = Header { number: height, ..Default::default() };
            PrimaryHeaderFinalization {
                primary: 0,
                difficulty: DIFFICULTY_OUT_OF_TURN,
                signature_scheme: SignatureScheme::Ecdsa,
                next_validators: &validators,
                next_dkg_public_key: next_dkg.map(|state| state.current.global_public_key),
                chain_spec: chain_spec.as_ref(),
            }
            .apply(&mut header)
            .unwrap();

            let prefix = DbftExtraPrefix::decode(&header.extra_data).unwrap();
            assert_eq!(
                prefix.fallback_next_consensus(),
                Some(next_consensus_hash(&validators.sorted))
            );
            assert_eq!(header.mix_hash, B256::ZERO);
        }

        assert!(read_next_dkg_or_fallback(true, |_| {
            Err(DkgStateError::Provider("unavailable".to_string()))
        })
        .is_none());
    }

    #[test]
    fn ecdsa_parent_proposal_carries_reseal_witness() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let mut parent = Header { number: 41, ..Default::default() };
        PrimaryHeaderFinalization {
            primary: (41 % 7) as u8,
            difficulty: DIFFICULTY_IN_TURN,
            signature_scheme: SignatureScheme::Ecdsa,
            next_validators: &validators,
            next_dkg_public_key: None,
            chain_spec: chain_spec.as_ref(),
        }
        .apply(&mut parent)
        .unwrap();

        // A backup holding a different honest quorum witness of this parent must be able to reseal
        // it, so the proposal has to carry the parent seal hash and the exact parent witness.
        let (seal_hash, extra) = parent_reseal_witness(&parent).unwrap();
        assert_eq!(seal_hash, Some(ecdsa_seal_hash(&parent).unwrap()));
        assert_eq!(extra, Some(parent.extra_data.clone()));
    }

    #[test]
    fn threshold_parent_proposal_omits_reseal_witness() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validators = validator_set();
        let height = chain_spec.neox.anti_mev_block;
        let mut parent = Header { number: height, ..Default::default() };
        PrimaryHeaderFinalization {
            primary: ((height + 7 - 1) % 7) as u8,
            difficulty: DIFFICULTY_OUT_OF_TURN,
            signature_scheme: SignatureScheme::Threshold,
            next_validators: &validators,
            next_dkg_public_key: Some([0x23; 48]),
            chain_spec: chain_spec.as_ref(),
        }
        .apply(&mut parent)
        .unwrap();

        // Threshold blocks hash deterministically, so no reseal witness is needed or attached.
        assert_eq!(parent_reseal_witness(&parent).unwrap(), (None, None));
    }
}
