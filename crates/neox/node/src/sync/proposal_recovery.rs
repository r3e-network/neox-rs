//! Proposal transaction recovery and deterministic verification scheduling.

use crate::{
    verify_proposal, DbftProposalError, DbftRoundState, ProposalContents,
    ProposalTransactionAction, ProposalTransactionSync, VerifiedProposal,
};
use alloy_consensus::Header;
use alloy_primitives::{B256, B512};
use reth_ethereum_primitives::{PooledTransactionVariant, TransactionSigned};
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::NeoXEvmConfig;
use reth_neox_network::{
    BeaconBlobSidecar, BeaconCommand, BeaconProtocol, DbftPrepareRequest, TransactionsPacket,
};
use reth_provider::{HeaderProvider, StateProviderFactory};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub(super) struct ProposalVerificationResult {
    pub(super) view: u8,
    pub(super) proposal_hash: B256,
    pub(super) result: Result<VerifiedProposal, DbftProposalError>,
}

/// Owns proposal transaction correlation and the fixed dependencies used for verification.
pub(super) struct ProposalRecovery<Provider> {
    transactions: ProposalTransactionSync,
    provider: Provider,
    beacon: BeaconProtocol,
    results: mpsc::UnboundedSender<ProposalVerificationResult>,
    consensus: NeoXConsensus,
    evm: NeoXEvmConfig,
    chain_spec: Arc<NeoXChainSpec>,
}

impl<Provider> ProposalRecovery<Provider> {
    pub(super) fn channel(
        provider: Provider,
        beacon: BeaconProtocol,
        consensus: NeoXConsensus,
        evm: NeoXEvmConfig,
        chain_spec: Arc<NeoXChainSpec>,
    ) -> (Self, mpsc::UnboundedReceiver<ProposalVerificationResult>) {
        let (results, receiver) = mpsc::unbounded_channel();
        (
            Self {
                transactions: ProposalTransactionSync::default(),
                provider,
                beacon,
                results,
                consensus,
                evm,
                chain_spec,
            },
            receiver,
        )
    }

    pub(super) fn is_waiting_for(&self, view: u8, proposal_hash: B256) -> bool {
        self.transactions.is_waiting_for(view, proposal_hash)
    }

    pub(super) fn clear(&mut self) {
        self.transactions.clear();
    }
}

impl<Provider> ProposalRecovery<Provider>
where
    Provider: HeaderProvider<Header = Header> + StateProviderFactory + Clone + Send + 'static,
{
    pub(super) fn begin<Pool>(
        &mut self,
        peer_id: B512,
        view: u8,
        proposal_hash: B256,
        request: DbftPrepareRequest,
        round: &DbftRoundState,
        pool: &Pool,
    ) -> Result<(), DbftProposalError>
    where
        Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        >,
    {
        let action = self.transactions.begin(peer_id, view, proposal_hash, request, |hash| {
            pool.get_pooled_transaction_element(hash).map(|transaction| transaction.into_inner())
        })?;
        self.dispatch(action, round);
        Ok(())
    }

    pub(super) fn supply(
        &mut self,
        peer_id: B512,
        response: TransactionsPacket,
        round: Option<&DbftRoundState>,
    ) {
        let request_id = response.request_id;
        let count = response.message.0.len();
        let action = self.transactions.supply(peer_id, response);
        match (action, round) {
            (Ok(action), Some(round)) => self.dispatch(action, round),
            (Ok(_), None) => {
                self.clear();
                debug!(target: "neox::validator", %peer_id, request_id, count, "Discarded Neo X proposal transactions without an active round");
            }
            (Err(DbftProposalError::UnknownTransactionResponse(_)), _) => {
                debug!(target: "neox::validator", %peer_id, request_id, count, "Ignored late Neo X proposal transaction response");
            }
            (Err(error), _) => {
                warn!(target: "neox::validator", %peer_id, request_id, count, %error, "Rejected beacon transaction response for Neo X proposal");
            }
        }
    }

    pub(super) fn verify_local(
        &self,
        round: &DbftRoundState,
        view: u8,
        proposal_hash: B256,
        request: DbftPrepareRequest,
        transactions: Vec<TransactionSigned>,
        sidecars: Vec<BeaconBlobSidecar>,
    ) {
        self.dispatch(
            ProposalTransactionAction::Ready {
                view,
                proposal_hash,
                request: Box::new(request),
                transactions,
                sidecars,
            },
            round,
        );
    }

    fn dispatch(&self, action: ProposalTransactionAction, round: &DbftRoundState) {
        match action {
            ProposalTransactionAction::Request { peer_id, request } => {
                let request_id = request.request_id;
                let count = request.message.0.len();
                if self.beacon.send(peer_id, BeaconCommand::GetTransactions(request)) {
                    debug!(target: "neox::validator", %peer_id, request_id, count, "Requested missing Neo X proposal transactions");
                } else {
                    warn!(target: "neox::validator", %peer_id, request_id, count, "Unable to request Neo X proposal transactions from beacon/2 peer");
                }
            }
            ProposalTransactionAction::Ready {
                view,
                proposal_hash,
                request,
                transactions,
                sidecars,
            } => {
                if round.current_view() != view ||
                    round.proposal(view).map(|proposal| proposal.hash()) != Some(proposal_hash)
                {
                    debug!(target: "neox::validator", view, %proposal_hash, "Discarded transactions for an abandoned Neo X proposal");
                    return
                }
                let Ok(expected_primary) = u8::try_from(round.primary_index(view)) else {
                    warn!(target: "neox::validator", view, "Neo X proposal primary index exceeds wire range");
                    return
                };
                let provider = self.provider.clone();
                let proposal_consensus = self.consensus.clone();
                let proposal_evm = self.evm.clone();
                let chain_spec = Arc::clone(&self.chain_spec);
                let proposal_results = self.results.clone();
                tokio::task::spawn_blocking(move || {
                    let result = verify_proposal(
                        request.as_ref(),
                        ProposalContents { transactions, sidecars },
                        expected_primary,
                        &provider,
                        &proposal_evm,
                        &proposal_consensus,
                        chain_spec.as_ref(),
                    );
                    let _ = proposal_results.send(ProposalVerificationResult {
                        view,
                        proposal_hash,
                        result,
                    });
                });
            }
        }
    }
}
