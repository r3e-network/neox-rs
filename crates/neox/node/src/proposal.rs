//! Deterministic execution and post-state validation for dBFT proposals.

use crate::{
    dkg::{read_dkg_state, read_dkg_state_from_storage},
    validator::read_governance_validator_set_from_storage,
    AntiMevProposal, DbftStateError, DkgState, DkgStateError, GovernanceValidatorSet,
};
use alloy_consensus::Header;
use alloy_eips::eip4844::env_settings::EnvKzgSettings;
use alloy_primitives::{keccak256, Address, B256, B512, U256};
use reth_chainspec::EthereumHardforks;
use reth_consensus::{Consensus, FullConsensus};
use reth_ethereum_primitives::{
    Block, BlockBody, EthPrimitives, PooledTransactionVariant, Receipt, TransactionSigned,
};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus::{next_consensus_hash, DbftExtraPrefix, ExtraVersion, SignatureScheme};
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::{NeoXEvmConfig, GOVERNANCE_PROXY_ADDRESS, KEY_MANAGEMENT_PROXY_ADDRESS};
use reth_neox_network::{
    transactions_request, BeaconBlobSidecar, DbftPrepareRequest, GetTransactions,
    TransactionsPacket,
};
use reth_primitives_traits::{Block as _, RecoveredBlock, SealedHeader};
use reth_provider::{HeaderProvider, StateProvider, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const MAX_PROPOSAL_TRANSACTIONS: usize = 100_000;

/// Next action produced while recovering a proposal's signed transaction list.
#[derive(Debug)]
pub enum ProposalTransactionAction {
    /// Ask the dBFT message's beacon/2 peer for currently missing hashes.
    Request {
        /// Peer that supplied the proposal.
        peer_id: B512,
        /// Correlated beacon/2 request.
        request: GetTransactions,
    },
    /// All transactions are present in the exact order signed by the primary.
    Ready {
        /// dBFT view containing the proposal.
        view: u8,
        /// Signed outer `PrepareRequest` message hash.
        proposal_hash: B256,
        /// Decoded primary request.
        request: Box<DbftPrepareRequest>,
        /// Ordered transactions.
        transactions: Vec<TransactionSigned>,
        /// One authenticated sidecar for each blob transaction, in transaction order.
        sidecars: Vec<BeaconBlobSidecar>,
    },
}

#[derive(Debug)]
struct PendingProposalTransactions {
    peer_id: B512,
    view: u8,
    proposal_hash: B256,
    request: DbftPrepareRequest,
    transactions: Vec<Option<PooledTransactionVariant>>,
}

/// Correlates beacon/2 responses with one or more concurrently observed dBFT proposals.
#[derive(Debug, Default)]
pub struct ProposalTransactionSync {
    next_request_id: u64,
    pending: HashMap<u64, PendingProposalTransactions>,
}

impl ProposalTransactionSync {
    /// Starts transaction recovery, consulting the local pool before requesting missing hashes.
    pub fn begin(
        &mut self,
        peer_id: B512,
        view: u8,
        proposal_hash: B256,
        request: DbftPrepareRequest,
        mut local: impl FnMut(B256) -> Option<PooledTransactionVariant>,
    ) -> Result<ProposalTransactionAction, DbftProposalError> {
        validate_proposal_hash_set(&request.transaction_hashes)?;
        let transactions = request
            .transaction_hashes
            .iter()
            .map(|hash| local(*hash).filter(|transaction| transaction.tx_hash() == hash))
            .collect::<Vec<_>>();
        self.finish_or_request(PendingProposalTransactions {
            peer_id,
            view,
            proposal_hash,
            request,
            transactions,
        })
    }

    /// Applies one correlated beacon/2 response and either completes or requests the remainder.
    pub fn supply(
        &mut self,
        peer_id: B512,
        response: TransactionsPacket,
    ) -> Result<ProposalTransactionAction, DbftProposalError> {
        let request_id = response.request_id;
        let pending = self
            .pending
            .get(&request_id)
            .ok_or(DbftProposalError::UnknownTransactionResponse(request_id))?;
        if pending.peer_id != peer_id {
            return Err(DbftProposalError::WrongTransactionPeer {
                request_id,
                expected: pending.peer_id,
                actual: peer_id,
            })
        }
        let missing = pending
            .request
            .transaction_hashes
            .iter()
            .enumerate()
            .filter_map(|(index, hash)| {
                pending.transactions[index].is_none().then_some((*hash, index))
            })
            .collect::<HashMap<_, _>>();
        let mut supplied = HashSet::new();
        let mut updates = Vec::with_capacity(response.message.0.len());
        for transaction in response.message.0 {
            let hash = *transaction.tx_hash();
            let Some(index) = missing.get(&hash).copied() else {
                return Err(DbftProposalError::UnexpectedTransaction(hash))
            };
            if !supplied.insert(hash) {
                return Err(DbftProposalError::DuplicateTransaction(hash))
            }
            updates.push((index, transaction));
        }

        let mut pending =
            self.pending.remove(&request_id).expect("correlated proposal checked above");
        for (index, transaction) in updates {
            pending.transactions[index] = Some(transaction);
        }
        self.finish_or_request(pending)
    }

    /// Number of transaction requests awaiting beacon/2 responses.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns whether the active proposal is still waiting for one or more transactions.
    pub fn is_waiting_for(&self, view: u8, proposal_hash: B256) -> bool {
        self.pending
            .values()
            .any(|pending| pending.view == view && pending.proposal_hash == proposal_hash)
    }

    /// Discards requests belonging to a completed height or abandoned view.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    fn finish_or_request(
        &mut self,
        pending: PendingProposalTransactions,
    ) -> Result<ProposalTransactionAction, DbftProposalError> {
        let missing = pending
            .request
            .transaction_hashes
            .iter()
            .enumerate()
            .filter_map(|(index, hash)| pending.transactions[index].is_none().then_some(*hash))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            let mut transactions = Vec::with_capacity(pending.transactions.len());
            let mut sidecars = Vec::new();
            for transaction in pending.transactions {
                let transaction = transaction.expect("missing transactions checked above");
                if let PooledTransactionVariant::Eip4844(blob) = &transaction {
                    sidecars.push(BeaconBlobSidecar::from(blob.tx().sidecar.clone()));
                }
                transactions.push(transaction.into());
            }
            return Ok(ProposalTransactionAction::Ready {
                view: pending.view,
                proposal_hash: pending.proposal_hash,
                request: Box::new(pending.request),
                transactions,
                sidecars,
            })
        }
        let request_id = self.allocate_request_id();
        let peer_id = pending.peer_id;
        self.pending.insert(request_id, pending);
        Ok(ProposalTransactionAction::Request {
            peer_id,
            request: transactions_request(request_id, missing),
        })
    }

    fn allocate_request_id(&mut self) -> u64 {
        loop {
            self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
            if !self.pending.contains_key(&self.next_request_id) {
                return self.next_request_id
            }
        }
    }
}

fn validate_proposal_hash_set(hashes: &[B256]) -> Result<(), DbftProposalError> {
    if hashes.len() > MAX_PROPOSAL_TRANSACTIONS {
        return Err(DbftProposalError::TooManyTransactions(hashes.len()))
    }
    let mut unique = HashSet::with_capacity(hashes.len());
    for hash in hashes {
        if !unique.insert(*hash) {
            return Err(DbftProposalError::DuplicateTransaction(*hash))
        }
    }
    Ok(())
}

/// A proposal whose transactions, EVM result, state root, and next-consensus commitments match.
#[derive(Debug, Clone)]
pub struct VerifiedProposal {
    /// Canonical parent hash whose post-state was used for execution.
    pub parent_state_hash: B256,
    /// Canonical parent base fee used for decrypted replacement-tip comparisons.
    pub parent_base_fee: u64,
    /// Authenticated alternative parent witness that must be imported before this child, if any.
    pub parent_reseal: Option<SealedHeader<Header>>,
    /// Recovered executable block in the exact primary-proposed transaction order.
    pub block: RecoveredBlock<Block>,
    /// Validated sidecars in blob-transaction order.
    pub sidecars: Vec<BeaconBlobSidecar>,
    /// Decoded Anti-MEV Envelopes and epoch classification when the fork is active.
    pub anti_mev: Option<AntiMevProposal>,
    /// Receipts and post-state changes produced from the canonical parent state.
    pub execution: BlockExecutionOutput<Receipt>,
    /// Governance validator set read from the post-execution state.
    pub next_validators: GovernanceValidatorSet,
    /// Post-execution DKG state when the next height uses Anti-MEV consensus.
    pub next_dkg: Option<DkgState>,
}

/// Complete data-availability input accompanying a signed dBFT proposal.
#[derive(Debug)]
pub struct ProposalContents {
    /// Ordered consensus transactions committed by the primary.
    pub transactions: Vec<TransactionSigned>,
    /// One validated wire sidecar candidate per blob transaction.
    pub sidecars: Vec<BeaconBlobSidecar>,
}

/// Executes and validates a complete dBFT `PrepareRequest` without trusting the primary.
pub fn verify_proposal<Provider>(
    request: &DbftPrepareRequest,
    contents: ProposalContents,
    expected_primary: u8,
    provider: &Provider,
    evm_config: &NeoXEvmConfig,
    consensus: &NeoXConsensus,
    chain_spec: &NeoXChainSpec,
) -> Result<VerifiedProposal, DbftProposalError>
where
    Provider: StateProviderFactory + HeaderProvider<Header = Header>,
{
    let ProposalContents { transactions, sidecars } = contents;
    validate_transaction_hashes(request, &transactions)?;
    validate_proposal_sidecars(&transactions, &sidecars)?;
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
    let resolved_parent = resolve_proposal_parent(request, provider, consensus)?;
    consensus
        .validate_proposal_header(sealed.sealed_header(), &resolved_parent.header, expected_primary)
        .map_err(|error| DbftProposalError::Header(error.to_string()))?;
    consensus
        .validate_block_pre_execution(&sealed)
        .map_err(|error| DbftProposalError::PreExecution(error.to_string()))?;
    let recovered = block.try_into_recovered().map_err(|_| DbftProposalError::SenderRecovery)?;
    let state_provider = provider
        .state_by_block_hash(resolved_parent.state_hash)
        .map_err(|error| DbftProposalError::Provider(error.to_string()))?;
    let anti_mev = if chain_spec.is_anti_mev_active_at_block(recovered.number) {
        let dkg_state = read_dkg_state(state_provider.as_ref())?;
        Some(AntiMevProposal::from_transactions(
            &recovered.body().transactions,
            dkg_state.current.round,
        ))
    } else {
        None
    };
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

    Ok(VerifiedProposal {
        parent_state_hash: resolved_parent.state_hash,
        parent_base_fee: resolved_parent.header.base_fee_per_gas.unwrap_or_default(),
        parent_reseal: resolved_parent.reseal,
        block: recovered,
        sidecars,
        anti_mev,
        execution,
        next_validators,
        next_dkg,
    })
}

#[derive(Debug)]
struct ResolvedProposalParent {
    header: SealedHeader<Header>,
    state_hash: B256,
    reseal: Option<SealedHeader<Header>>,
}

fn resolve_proposal_parent<Provider>(
    request: &DbftPrepareRequest,
    provider: &Provider,
    consensus: &NeoXConsensus,
) -> Result<ResolvedProposalParent, DbftProposalError>
where
    Provider: HeaderProvider<Header = Header>,
{
    let parent_number =
        request.sealing_proposal.number.checked_sub(1).ok_or(DbftProposalError::GenesisProposal)?;
    let canonical_parent = provider
        .sealed_header(parent_number)
        .map_err(|error| DbftProposalError::Provider(error.to_string()))?
        .ok_or(DbftProposalError::MissingCanonicalParent(parent_number))?;
    let state_hash = canonical_parent.hash();
    if request.sealing_proposal.parent_hash == state_hash {
        return Ok(ResolvedProposalParent { header: canonical_parent, state_hash, reseal: None })
    }
    if parent_number == 0 {
        return Err(DbftProposalError::GenesisParentMismatch {
            expected: state_hash,
            actual: request.sealing_proposal.parent_hash,
        })
    }

    let parent_seal_hash =
        request.parent_seal_hash_v0.ok_or(DbftProposalError::MissingParentSealHash)?;
    let parent_extra = request.parent_extra.clone().ok_or(DbftProposalError::MissingParentExtra)?;
    let grandparent_hash = canonical_parent.parent_hash;
    let grandparent = provider
        .sealed_header_by_hash(grandparent_hash)
        .map_err(|error| DbftProposalError::Provider(error.to_string()))?
        .ok_or(DbftProposalError::MissingGrandparent(grandparent_hash))?;
    let resealed = consensus
        .validate_parent_reseal(
            &canonical_parent,
            &grandparent,
            parent_seal_hash,
            parent_extra,
            request.sealing_proposal.parent_hash,
        )
        .map_err(|error| DbftProposalError::ParentWitness(error.to_string()))?;
    Ok(ResolvedProposalParent { header: resealed.clone(), state_hash, reseal: Some(resealed) })
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

fn validate_proposal_sidecars(
    transactions: &[TransactionSigned],
    sidecars: &[BeaconBlobSidecar],
) -> Result<(), DbftProposalError> {
    let blob_hashes = transactions
        .iter()
        .filter_map(|transaction| {
            let hashes = &transaction.as_eip4844()?.tx().blob_versioned_hashes;
            (!hashes.is_empty()).then_some(hashes.as_slice())
        })
        .collect::<Vec<_>>();
    if blob_hashes.len() != sidecars.len() {
        return Err(DbftProposalError::SidecarCount {
            expected: blob_hashes.len(),
            actual: sidecars.len(),
        })
    }
    for (transaction_index, (hashes, sidecar)) in blob_hashes.into_iter().zip(sidecars).enumerate()
    {
        sidecar.clone().into_variant().validate(hashes, EnvKzgSettings::Default.get()).map_err(
            |error| DbftProposalError::InvalidSidecar {
                transaction_index,
                error: error.to_string(),
            },
        )?;
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
    /// Proposal exceeds the defensive transaction-count ceiling.
    #[error("dBFT proposal contains too many transactions: {0}")]
    TooManyTransactions(usize),
    /// A proposal or response repeated one transaction hash.
    #[error("duplicate dBFT proposal transaction {0}")]
    DuplicateTransaction(B256),
    /// A beacon/2 response did not match an outstanding request.
    #[error("unknown dBFT transaction response request ID {0}")]
    UnknownTransactionResponse(u64),
    /// A response arrived from a peer other than the proposal source.
    #[error("dBFT transaction response {request_id} came from {actual}, expected {expected}")]
    WrongTransactionPeer {
        /// Correlation identifier.
        request_id: u64,
        /// Proposal source.
        expected: B512,
        /// Response source.
        actual: B512,
    },
    /// A response included a transaction not requested for the proposal.
    #[error("unexpected dBFT proposal transaction {0}")]
    UnexpectedTransaction(B256),
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
    /// Sidecar count must match the number of blob transactions in the proposal.
    #[error("dBFT proposal sidecar count mismatch: expected {expected}, got {actual}")]
    SidecarCount {
        /// Number of blob transactions.
        expected: usize,
        /// Number of supplied sidecars.
        actual: usize,
    },
    /// A blob transaction's sidecar failed KZG and versioned-hash validation.
    #[error("invalid dBFT proposal sidecar at blob transaction {transaction_index}: {error}")]
    InvalidSidecar {
        /// Position among blob transactions, not all transactions.
        transaction_index: usize,
        /// Validation failure.
        error: String,
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
    /// dBFT never proposes the genesis block because it has no executable parent state.
    #[error("dBFT proposal cannot target genesis")]
    GenesisProposal,
    /// The local canonical chain does not contain the proposal height's parent.
    #[error("missing canonical dBFT proposal parent at height {0}")]
    MissingCanonicalParent(u64),
    /// The hard-coded genesis parent hash cannot be replaced by a carried witness.
    #[error("dBFT proposal parent does not match genesis: expected {expected}, got {actual}")]
    GenesisParentMismatch {
        /// Local canonical genesis hash.
        expected: B256,
        /// Parent hash signed by the primary.
        actual: B256,
    },
    /// An alternate ECDSA parent hash requires the legacy honest seal hash.
    #[error("dBFT proposal with alternate parent is missing parent seal hash")]
    MissingParentSealHash,
    /// An alternate ECDSA parent hash requires the complete quorum witness.
    #[error("dBFT proposal with alternate parent is missing parent extra data")]
    MissingParentExtra,
    /// The parent referenced by the local canonical parent is unavailable.
    #[error("missing dBFT proposal grandparent {0}")]
    MissingGrandparent(B256),
    /// A carried alternative parent witness failed seal, hash, or cascading validation.
    #[error("invalid dBFT proposal parent witness: {0}")]
    ParentWitness(String),
    /// Static proposal header or parent-field validation failed.
    #[error("invalid unsealed dBFT proposal header: {0}")]
    Header(String),
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
    use alloy_consensus::{Header, TxLegacy};
    use alloy_eips::eip4844::BlobTransactionSidecar;
    use alloy_primitives::Signature;
    use reth_ethereum_primitives::Transaction;
    use reth_neox_network::transactions_response;
    use reth_provider::test_utils::MockEthProvider;
    use std::sync::Arc;

    fn transaction(nonce: u64) -> TransactionSigned {
        TransactionSigned::new_unhashed(
            Transaction::Legacy(TxLegacy { nonce, ..Default::default() }),
            Signature::test_signature(),
        )
    }

    fn pooled(transaction: TransactionSigned) -> PooledTransactionVariant {
        transaction.try_into().unwrap()
    }

    #[test]
    fn resolves_the_canonical_parent_without_a_witness() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let provider = MockEthProvider::<EthPrimitives>::new()
            .with_chain_spec(chain_spec.as_ref().clone())
            .with_genesis_block();
        let request = DbftPrepareRequest {
            sealing_proposal: Header {
                parent_hash: chain_spec.inner.genesis_header.hash(),
                number: 1,
                ..Default::default()
            },
            transaction_hashes: Vec::new(),
            parent_seal_hash_v0: None,
            parent_extra: None,
        };

        let parent = resolve_proposal_parent(&request, &provider, &consensus).unwrap();
        assert_eq!(parent.header.hash(), chain_spec.inner.genesis_header.hash());
        assert_eq!(parent.state_hash, chain_spec.inner.genesis_header.hash());
        assert!(parent.reseal.is_none());
    }

    #[test]
    fn rejects_a_noncanonical_genesis_parent() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let provider = MockEthProvider::<EthPrimitives>::new()
            .with_chain_spec(chain_spec.as_ref().clone())
            .with_genesis_block();
        let request = DbftPrepareRequest {
            sealing_proposal: Header {
                parent_hash: B256::repeat_byte(0x44),
                number: 1,
                ..Default::default()
            },
            transaction_hashes: Vec::new(),
            parent_seal_hash_v0: None,
            parent_extra: None,
        };

        assert!(matches!(
            resolve_proposal_parent(&request, &provider, &consensus),
            Err(DbftProposalError::GenesisParentMismatch { .. })
        ));
    }

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
        validate_proposal_sidecars(&[], &[]).unwrap();
        assert!(matches!(
            validate_proposal_sidecars(
                &[],
                &[BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default())]
            ),
            Err(DbftProposalError::SidecarCount { expected: 0, actual: 1 })
        ));
    }

    #[test]
    fn recovers_missing_transactions_and_restores_primary_order() {
        let first = transaction(1);
        let second = transaction(2);
        let first_hash = *first.tx_hash();
        let second_hash = *second.tx_hash();
        let request = DbftPrepareRequest {
            sealing_proposal: Header::default(),
            transaction_hashes: vec![first_hash, second_hash],
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let peer_id = B512::repeat_byte(0x44);
        let mut sync = ProposalTransactionSync::default();
        let action = sync
            .begin(peer_id, 3, B256::repeat_byte(0x55), request, |hash| {
                (hash == second_hash).then(|| pooled(second.clone()))
            })
            .unwrap();
        let ProposalTransactionAction::Request { request, .. } = action else {
            panic!("expected missing transaction request")
        };
        assert_eq!(request.message.0, vec![first_hash]);
        assert_eq!(sync.pending_count(), 1);
        assert!(sync.is_waiting_for(3, B256::repeat_byte(0x55)));
        assert!(!sync.is_waiting_for(2, B256::repeat_byte(0x55)));

        let action = sync
            .supply(peer_id, transactions_response(request.request_id, vec![pooled(first)]))
            .unwrap();
        let ProposalTransactionAction::Ready { transactions, sidecars, view, .. } = action else {
            panic!("expected complete proposal")
        };
        assert_eq!(view, 3);
        assert!(sidecars.is_empty());
        assert_eq!(
            transactions.iter().map(|tx| *tx.tx_hash()).collect::<Vec<_>>(),
            [first_hash, second_hash]
        );
        assert_eq!(sync.pending_count(), 0);
        assert!(!sync.is_waiting_for(3, B256::repeat_byte(0x55)));
    }

    #[test]
    fn rejects_wrong_peer_and_unrequested_transactions() {
        let first_tx = transaction(1);
        let hash = *first_tx.tx_hash();
        let request = DbftPrepareRequest {
            sealing_proposal: Header::default(),
            transaction_hashes: vec![hash],
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let peer_id = B512::repeat_byte(0x44);
        let mut sync = ProposalTransactionSync::default();
        let ProposalTransactionAction::Request { request, .. } =
            sync.begin(peer_id, 0, B256::ZERO, request, |_| None).unwrap()
        else {
            panic!("expected request")
        };
        assert!(matches!(
            sync.supply(
                B512::repeat_byte(0x45),
                transactions_response(request.request_id, vec![pooled(first_tx)]),
            ),
            Err(DbftProposalError::WrongTransactionPeer { .. })
        ));
        assert!(matches!(
            sync.supply(
                peer_id,
                transactions_response(request.request_id, vec![pooled(transaction(2))]),
            ),
            Err(DbftProposalError::UnexpectedTransaction(_))
        ));
        assert_eq!(sync.pending_count(), 1);
    }
}
