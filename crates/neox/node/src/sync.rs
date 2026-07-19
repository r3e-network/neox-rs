//! Neo X beacon-to-engine synchronization and canonical block propagation.

use crate::{
    build_primary_proposal, metrics::NeoXSyncMetrics, read_dkg_state,
    read_governance_validator_set, reconstruct_antimev_proposal, verify_proposal, AntiMevPreBlock,
    AntiMevReconstruction, AntiMevTransactionDecision, DbftProposalError, DbftRoundProgress,
    DbftRoundState, DbftSigner, DbftStateError, EnvelopeDkgEpoch, PrimaryProposal,
    PrimaryProposalAttributes, PrimaryProposalError, ProposalContents, ProposalTransactionAction,
    ProposalTransactionSync, VerifiedProposal,
};
use alloy_consensus::Header;
use alloy_eips::eip4844::env_settings::EnvKzgSettings;
use alloy_primitives::{B256, B512, U256};
use alloy_rpc_types_engine::ForkchoiceState;
use futures::StreamExt;
use reth_chain_state::{CanonStateNotification, CanonStateNotificationStream};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_engine_primitives::{EthEngineTypes, EthPayloadTypes};
use reth_ethereum_primitives::{Block, EthPrimitives, PooledTransactionVariant, TransactionSigned};
use reth_neox_antimev::encode_decryption_shares;
use reth_neox_chainspec::{NeoXChainSpec, NEOX_VALIDATOR_COUNT};
use reth_neox_consensus::SignatureScheme;
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::NeoXEvmConfig;
use reth_neox_network::{
    block_hash_announcement, transactions_response, BatchBlobs, BeaconBlobSidecar, BeaconCommand,
    BeaconEvent, BeaconLocalStatus, BeaconProtocol, BeaconStatus, Blobs, DbftChangeView,
    DbftChangeViewReason, DbftDecodedPayload, DbftEvent, DbftMessageType, DbftPreCommit,
    DbftPrepareResponse, DbftProtocol, DbftRecoveryRequest, GetBatchBlobs, GetBlobs,
    NeoXSidecarStore, NewBlobsRoot, NewBlockPacket,
};
use reth_node_api::PayloadTypes;
use reth_primitives_traits::{AlloyBlockHeader, Block as _, SealedBlock};
use reth_provider::{BlockReader, HeaderProvider, StateProviderFactory};
use reth_transaction_pool::{GetPooledTransactionLimit, PoolTransaction, TransactionPool};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const TRANSACTION_RESPONSE_SOFT_LIMIT: usize = 5 * 1024 * 1024;
const SIDECAR_RESPONSE_SOFT_LIMIT: usize = 5 * 1024 * 1024;
const SIDECAR_BATCH_BLOCK_LIMIT: usize = 16;
const SIDECAR_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const SIDECAR_RETAINED_BLOCK_WINDOW: u64 = 8_192 * 32;

/// Runs the bridge between Neo X `beacon/1,2`, Reth's Engine Tree, and the canonical chain.
///
/// Neo X Geth announces finalized dBFT blocks over `beacon`, while historical bodies and state are
/// still downloaded through the standard `eth`/`snap` protocols. Unknown beacon heads are sent to
/// the Engine Tree as sync targets; propagated full blocks are first executed and validated before
/// they can become canonical.
#[derive(Debug)]
pub struct BeaconSyncContext<Pool, Provider> {
    /// Validated events emitted by all negotiated beacon connections.
    pub events: mpsc::UnboundedReceiver<BeaconEvent>,
    /// Cryptographically validated events emitted by `dbft/0` connections.
    pub dbft_events: mpsc::UnboundedReceiver<DbftEvent>,
    /// Canonical-chain notifications emitted by the Engine Tree.
    pub canonical: CanonStateNotificationStream<EthPrimitives>,
    /// Shared beacon status and command handle.
    pub beacon: BeaconProtocol,
    /// Shared dBFT cache, height, and peer command handle.
    pub dbft: DbftProtocol,
    /// Engine Tree ingress used for payload import and backfill targets.
    pub engine: ConsensusEngineHandle<EthEngineTypes>,
    /// Policy-aware Neo X transaction pool.
    pub pool: Pool,
    /// Canonical block provider used for sidecar validation.
    pub provider: Provider,
    /// Active Neo X chain specification.
    pub chain_spec: Arc<NeoXChainSpec>,
    /// Optional local Governance validator identity.
    pub signer: Option<DbftSigner>,
    /// Persistent finalized-block sidecar store.
    pub sidecar_store: NeoXSidecarStore,
}

/// Runs the long-lived Neo X beacon synchronization driver.
pub async fn run_beacon_sync<Pool, Provider>(context: BeaconSyncContext<Pool, Provider>)
where
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        > + 'static,
    Provider: BlockReader<Block = Block>
        + HeaderProvider<Header = Header>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    let BeaconSyncContext {
        mut events,
        mut dbft_events,
        mut canonical,
        beacon,
        dbft,
        engine,
        pool,
        provider,
        chain_spec,
        signer,
        sidecar_store,
    } = context;
    let committed_sidecar_store = sidecar_store.clone();
    let mut sidecars = SidecarSync::new(sidecar_store);
    let mut dbft_round = None;
    let proposal_consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
    let proposal_evm = NeoXEvmConfig::new(Arc::clone(&chain_spec));
    let (proposal_results_tx, mut proposal_results_rx) = mpsc::unbounded_channel();
    let (primary_results_tx, mut primary_results_rx) = mpsc::unbounded_channel();
    let (reconstruction_results_tx, mut reconstruction_results_rx) = mpsc::unbounded_channel();
    let (dbft_timeouts_tx, mut dbft_timeouts_rx) = mpsc::unbounded_channel();
    let mut proposal_transactions = ProposalTransactionSync::default();
    let mut verified_proposals = HashMap::new();
    let mut reconstruction_attempts = HashMap::new();
    let mut primary_builds = HashSet::new();
    let mut dbft_timer = DbftTimerState::default();
    let metrics = NeoXSyncMetrics::default();
    metrics.canonical_height.set(beacon.status().head_number as f64);
    metrics.beacon_peers.set(beacon.peer_count() as f64);
    metrics.dbft_peers.set(dbft.peer_count() as f64);
    let block_period = Duration::from_secs(chain_spec.neox.dbft.period);
    activate_dbft_round(
        beacon.status().head_number,
        &provider,
        &dbft,
        &chain_spec,
        signer.as_ref(),
        &mut dbft_round,
    );
    reset_dbft_timer(
        dbft_round.as_ref(),
        signer.as_ref(),
        block_period,
        &mut dbft_timer,
        &dbft_timeouts_tx,
    );
    // Geth's one-time DBFT.Start call asks an initial primary to propose immediately. Later
    // canonical-height resets are timer driven.
    maybe_schedule_primary_proposal(
        dbft_round.as_ref(),
        signer.as_ref(),
        &pool,
        &provider,
        &proposal_evm,
        &chain_spec,
        &primary_results_tx,
        &mut primary_builds,
    );
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    warn!(target: "neox::sync", "Neo X beacon event channel closed");
                    return
                };
                metrics.beacon_events_total.increment(1);
                sidecars.expire_requests();
                handle_beacon_event(event, BeaconEventContext {
                    beacon: &beacon,
                    engine: &engine,
                    pool: &pool,
                    provider: &provider,
                    sidecars: &mut sidecars,
                    dbft: &dbft,
                    chain_spec: &chain_spec,
                    signer: signer.as_ref(),
                    dbft_round: &mut dbft_round,
                    proposal_transactions: &mut proposal_transactions,
                    proposal_results: &proposal_results_tx,
                    proposal_consensus: &proposal_consensus,
                    proposal_evm: &proposal_evm,
                    primary_builds: &mut primary_builds,
                    dbft_timer: &mut dbft_timer,
                    dbft_timeouts: &dbft_timeouts_tx,
                    block_period,
                }).await;
                metrics.beacon_peers.set(beacon.peer_count() as f64);
            }
            event = dbft_events.recv() => {
                let Some(event) = event else {
                    warn!(target: "neox::sync", "Neo X dBFT event channel closed");
                    return
                };
                metrics.dbft_events_total.increment(1);
                handle_dbft_event(event, DbftEventContext {
                    round: dbft_round.as_mut(),
                    pool: &pool,
                    provider: &provider,
                    beacon: &beacon,
                    proposal_transactions: &mut proposal_transactions,
                    proposal_results: &proposal_results_tx,
                    proposal_consensus: &proposal_consensus,
                    proposal_evm: &proposal_evm,
                    chain_spec: &chain_spec,
                    signer: signer.as_ref(),
                    dbft: &dbft,
                    verified_proposals: &mut verified_proposals,
                    engine: &engine,
                    reconstruction_results: &reconstruction_results_tx,
                    reconstruction_attempts: &mut reconstruction_attempts,
                    primary_results: &primary_results_tx,
                    primary_builds: &mut primary_builds,
                    dbft_timer: &mut dbft_timer,
                    dbft_timeouts: &dbft_timeouts_tx,
                    block_period,
                    sidecar_store: &committed_sidecar_store,
                    metrics: &metrics,
                });
                metrics.dbft_peers.set(dbft.peer_count() as f64);
            }
            timeout = dbft_timeouts_rx.recv() => {
                let Some(timeout) = timeout else {
                    warn!(target: "neox::validator", "Neo X dBFT timeout channel closed");
                    return
                };
                if handle_dbft_timeout(
                    timeout,
                    dbft_round.as_mut(),
                    signer.as_ref(),
                    &dbft,
                    &mut proposal_transactions,
                    block_period,
                    &mut dbft_timer,
                    &dbft_timeouts_tx,
                ) {
                    proposal_transactions.clear();
                }
                maybe_schedule_primary_proposal(
                    dbft_round.as_ref(),
                    signer.as_ref(),
                    &pool,
                    &provider,
                    &proposal_evm,
                    &chain_spec,
                    &primary_results_tx,
                    &mut primary_builds,
                );
            }
            result = primary_results_rx.recv() => {
                let Some(result) = result else {
                    warn!(target: "neox::producer", "Neo X primary proposal channel closed");
                    return
                };
                handle_primary_proposal(
                    result,
                    PrimaryProposalContext {
                        round: dbft_round.as_mut(),
                        signer: signer.as_ref(),
                        dbft: &dbft,
                        provider: &provider,
                        beacon: &beacon,
                        proposal_results: &proposal_results_tx,
                        proposal_consensus: &proposal_consensus,
                        proposal_evm: &proposal_evm,
                        chain_spec: &chain_spec,
                        primary_builds: &mut primary_builds,
                        dbft_timer: &mut dbft_timer,
                        dbft_timeouts: &dbft_timeouts_tx,
                        block_period,
                    },
                );
            }
            result = proposal_results_rx.recv() => {
                let Some(result) = result else {
                    warn!(target: "neox::validator", "Neo X proposal verification channel closed");
                    return
                };
                handle_proposal_verification(
                    result,
                    ProposalVerificationContext {
                        round: dbft_round.as_mut(),
                        signer: signer.as_ref(),
                        dbft: &dbft,
                        verified_proposals: &mut verified_proposals,
                        provider: &provider,
                        engine: &engine,
                        proposal_evm: &proposal_evm,
                        reconstruction_results: &reconstruction_results_tx,
                        reconstruction_attempts: &mut reconstruction_attempts,
                        beacon: &beacon,
                        sidecar_store: &committed_sidecar_store,
                        proposal_transactions: &mut proposal_transactions,
                        dbft_timer: &mut dbft_timer,
                        dbft_timeouts: &dbft_timeouts_tx,
                        block_period,
                    },
                );
                maybe_schedule_primary_proposal(
                    dbft_round.as_ref(),
                    signer.as_ref(),
                    &pool,
                    &provider,
                    &proposal_evm,
                    &chain_spec,
                    &primary_results_tx,
                    &mut primary_builds,
                );
            }
            result = reconstruction_results_rx.recv() => {
                let Some(result) = result else {
                    warn!(target: "neox::validator", "Neo X Anti-MEV reconstruction channel closed");
                    return
                };
                handle_antimev_reconstruction(
                    result,
                    dbft_round.as_mut(),
                    signer.as_ref(),
                    &dbft,
                    &mut verified_proposals,
                    &provider,
                    &engine,
                    &beacon,
                    &committed_sidecar_store,
                    &proposal_evm,
                    &reconstruction_results_tx,
                    &mut reconstruction_attempts,
                );
            }
            notification = canonical.next() => {
                let Some(notification) = notification else {
                    warn!(target: "neox::sync", "Neo X canonical notification stream closed");
                    return
                };
                let Some(tip) = notification.tip_checked() else {
                    debug!(target: "neox::sync", "Canonical revert contained no replacement Neo X block");
                    continue
                };

                proposal_transactions.clear();
                verified_proposals.clear();
                reconstruction_attempts.clear();
                primary_builds.clear();

                let number = tip.number();
                metrics.canonical_height.set(number as f64);
                metrics.canonical_updates_total.increment(1);
                dbft.update_height(number);
                let local = beacon.status();
                let total_difficulty = match &notification {
                    CanonStateNotification::Commit { new } => {
                        sidecars.archive_chain(new, &pool, &beacon);
                        if new.first().parent_hash != local.head {
                            warn!(
                                target: "neox::sync",
                                expected_parent = %local.head,
                                actual_parent = %new.first().parent_hash,
                                "Canonical Neo X commit did not extend the advertised head"
                            );
                        }
                        local.total_difficulty + chain_difficulty(new)
                    }
                    CanonStateNotification::Reorg { old, new } => {
                        metrics.canonical_reorgs_total.increment(1);
                        sidecars.archive_chain(new, &pool, &beacon);
                        local
                            .total_difficulty
                            .checked_sub(chain_difficulty(old))
                            .unwrap_or(chain_spec.inner.genesis_header.difficulty) +
                            chain_difficulty(new)
                    }
                };
                beacon.update_status(BeaconLocalStatus {
                    network_id: chain_spec.inner.chain.id(),
                    total_difficulty,
                    head: tip.hash(),
                    head_number: number,
                    head_timestamp: tip.timestamp(),
                    genesis: chain_spec.inner.genesis_hash(),
                    blob_sync: true,
                });
                let updated_local = beacon.status();
                let network_is_ahead = sidecars.peers.values().any(|peer| {
                    peer.head_number().map_or_else(
                        || peer.total_difficulty() > updated_local.total_difficulty,
                        |remote_number| remote_number > number,
                    )
                });
                if network_is_ahead {
                    dbft.deactivate();
                    dbft_round = None;
                    dbft_timer.disarm();
                } else {
                    activate_dbft_round(
                        number,
                        &provider,
                        &dbft,
                        &chain_spec,
                        signer.as_ref(),
                        &mut dbft_round,
                    );
                    reset_dbft_timer(
                        dbft_round.as_ref(),
                        signer.as_ref(),
                        block_period,
                        &mut dbft_timer,
                        &dbft_timeouts_tx,
                    );
                }

                let announcement = block_hash_announcement(tip.hash(), number);
                let announced = beacon.broadcast(BeaconCommand::NewBlockHashes(announcement));
                let packet = NewBlockPacket {
                    block: tip.clone().into_block(),
                    total_difficulty,
                };
                let propagated = beacon.broadcast(BeaconCommand::NewBlock(Box::new(packet)));
                info!(
                    target: "neox::sync",
                    block_number = number,
                    block_hash = %tip.hash(),
                    announced,
                    propagated,
                    "Updated and propagated canonical Neo X head"
                );
            }
        }
    }
}

struct DbftEventContext<'a, Pool, Provider> {
    round: Option<&'a mut DbftRoundState>,
    pool: &'a Pool,
    provider: &'a Provider,
    beacon: &'a BeaconProtocol,
    proposal_transactions: &'a mut ProposalTransactionSync,
    proposal_results: &'a mpsc::UnboundedSender<ProposalVerificationResult>,
    proposal_consensus: &'a NeoXConsensus,
    proposal_evm: &'a NeoXEvmConfig,
    chain_spec: &'a Arc<NeoXChainSpec>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    verified_proposals: &'a mut HashMap<B256, VerifiedProposal>,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    reconstruction_results: &'a mpsc::UnboundedSender<AntiMevReconstructionResult>,
    reconstruction_attempts: &'a mut HashMap<B256, AntiMevReconstructionAttempt>,
    primary_results: &'a mpsc::UnboundedSender<PrimaryProposalResult>,
    primary_builds: &'a mut HashSet<(u64, u8)>,
    dbft_timer: &'a mut DbftTimerState,
    dbft_timeouts: &'a mpsc::UnboundedSender<DbftTimeout>,
    block_period: Duration,
    sidecar_store: &'a NeoXSidecarStore,
    metrics: &'a NeoXSyncMetrics,
}

struct ProposalVerificationResult {
    view: u8,
    proposal_hash: B256,
    result: Result<VerifiedProposal, DbftProposalError>,
}

struct AntiMevReconstructionResult {
    view: u8,
    proposal_hash: B256,
    result: Result<AntiMevReconstruction, String>,
}

#[derive(Debug, Default)]
struct AntiMevReconstructionAttempt {
    attempted_contributions: usize,
    in_flight: bool,
}

impl AntiMevReconstructionAttempt {
    const fn begin(&mut self, contribution_count: usize) -> bool {
        if self.in_flight || contribution_count <= self.attempted_contributions {
            return false
        }
        self.attempted_contributions = contribution_count;
        self.in_flight = true;
        true
    }

    const fn finish(&mut self) {
        self.in_flight = false;
    }
}

struct PrimaryProposalResult {
    height: u64,
    view: u8,
    result: Result<PrimaryProposal, PrimaryProposalError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DbftTimeout {
    height: u64,
    view: u8,
    generation: u64,
}

#[derive(Debug, Default)]
struct DbftTimerState {
    generation: u64,
    armed: Option<DbftTimeout>,
}

impl DbftTimerState {
    fn arm(
        &mut self,
        height: u64,
        view: u8,
        delay: Duration,
        timeouts: &mpsc::UnboundedSender<DbftTimeout>,
    ) {
        self.generation = self.generation.wrapping_add(1);
        let timeout = DbftTimeout { height, view, generation: self.generation };
        self.armed = Some(timeout);
        let timeouts = timeouts.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = timeouts.send(timeout);
        });
        debug!(
            target: "neox::validator",
            block_number = height,
            view,
            ?delay,
            generation = timeout.generation,
            "Armed local Neo X dBFT timer"
        );
    }

    const fn disarm(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.armed = None;
    }

    fn consume(&mut self, timeout: DbftTimeout) -> bool {
        if self.armed != Some(timeout) {
            return false
        }
        self.armed = None;
        true
    }
}

struct ProposalVerificationContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    verified_proposals: &'a mut HashMap<B256, VerifiedProposal>,
    provider: &'a Provider,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    proposal_evm: &'a NeoXEvmConfig,
    reconstruction_results: &'a mpsc::UnboundedSender<AntiMevReconstructionResult>,
    reconstruction_attempts: &'a mut HashMap<B256, AntiMevReconstructionAttempt>,
    beacon: &'a BeaconProtocol,
    sidecar_store: &'a NeoXSidecarStore,
    proposal_transactions: &'a mut ProposalTransactionSync,
    dbft_timer: &'a mut DbftTimerState,
    dbft_timeouts: &'a mpsc::UnboundedSender<DbftTimeout>,
    block_period: Duration,
}

struct PrimaryProposalContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    provider: &'a Provider,
    beacon: &'a BeaconProtocol,
    proposal_results: &'a mpsc::UnboundedSender<ProposalVerificationResult>,
    proposal_consensus: &'a NeoXConsensus,
    proposal_evm: &'a NeoXEvmConfig,
    chain_spec: &'a Arc<NeoXChainSpec>,
    primary_builds: &'a mut HashSet<(u64, u8)>,
    dbft_timer: &'a mut DbftTimerState,
    dbft_timeouts: &'a mpsc::UnboundedSender<DbftTimeout>,
    block_period: Duration,
}

fn handle_dbft_event<Pool, Provider>(
    event: DbftEvent,
    context: DbftEventContext<'_, Pool, Provider>,
) where
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        > + 'static,
    Provider: BlockReader<Block = Block>
        + HeaderProvider<Header = Header>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    let DbftEventContext {
        round,
        pool,
        provider,
        beacon,
        proposal_transactions,
        proposal_results,
        proposal_consensus,
        proposal_evm,
        chain_spec,
        signer,
        dbft,
        verified_proposals,
        engine,
        reconstruction_results,
        reconstruction_attempts,
        primary_results,
        primary_builds,
        dbft_timer,
        dbft_timeouts,
        block_period,
        sidecar_store,
        metrics,
    } = context;
    match event {
        DbftEvent::Established { peer_id, direction } => {
            info!(target: "neox::sync", %peer_id, ?direction, "Neo X dbft/0 peer established");
        }
        DbftEvent::Disconnected { peer_id } => {
            debug!(target: "neox::sync", %peer_id, "Neo X dbft/0 peer disconnected");
        }
        DbftEvent::Message { peer_id, message } => {
            let Some(round) = round else {
                debug!(target: "neox::sync", %peer_id, "Ignoring dBFT payload without an active canonical round");
                return
            };
            let previous_view = round.current_view();
            let previous_proposal = round.proposal(previous_view).map(|proposal| proposal.hash());
            let received = Arc::clone(&message);
            let result = round.process(message);
            match &result {
                Ok(DbftRoundProgress::Duplicate | DbftRoundProgress::Accepted) => {
                    metrics.dbft_transitions_accepted_total.increment(1);
                }
                Ok(progress @ DbftRoundProgress::Prepared { .. }) => {
                    metrics.dbft_transitions_accepted_total.increment(1);
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached preparation quorum");
                }
                Ok(progress @ DbftRoundProgress::PreCommitted { .. }) => {
                    metrics.dbft_transitions_accepted_total.increment(1);
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached Anti-MEV share quorum");
                }
                Ok(progress @ DbftRoundProgress::Committed { .. }) => {
                    metrics.dbft_transitions_accepted_total.increment(1);
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached commit quorum");
                }
                Ok(progress @ DbftRoundProgress::ViewChanged { .. }) => {
                    metrics.dbft_transitions_accepted_total.increment(1);
                    metrics.dbft_view_changes_total.increment(1);
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT round changed view");
                }
                Err(error) if is_stale_dbft_transition(error) => {
                    metrics.dbft_transitions_stale_total.increment(1);
                    debug!(target: "neox::validator", %peer_id, %error, "Ignored stale Neo X dBFT state transition");
                }
                Err(error) => {
                    metrics.dbft_transitions_rejected_total.increment(1);
                    warn!(target: "neox::validator", %peer_id, %error, "Rejected invalid Neo X dBFT state transition");
                }
            }
            if let Ok(progress) = &result {
                maybe_publish_consensus_contribution(
                    round,
                    progress,
                    signer,
                    dbft,
                    verified_proposals,
                );
                let import_view = match progress {
                    DbftRoundProgress::Committed { view, .. } => *view,
                    _ => round.current_view(),
                };
                schedule_antimev_reconstruction(
                    round,
                    import_view,
                    provider,
                    proposal_evm,
                    verified_proposals,
                    reconstruction_attempts,
                    reconstruction_results,
                );
                schedule_committed_proposal(
                    round,
                    import_view,
                    provider,
                    engine,
                    beacon,
                    sidecar_store,
                    verified_proposals,
                );
            }
            if result.is_err() {
                return
            }
            maybe_respond_to_recovery_request(round, &received, signer, dbft);

            let active_view = round.current_view();
            if active_view != previous_view {
                proposal_transactions.clear();
                verified_proposals.clear();
                reconstruction_attempts.clear();
                reset_dbft_timer(Some(round), signer, block_period, dbft_timer, dbft_timeouts);
                maybe_schedule_primary_proposal(
                    Some(round),
                    signer,
                    pool,
                    provider,
                    proposal_evm,
                    chain_spec,
                    primary_results,
                    primary_builds,
                );
            }
            let Some(proposal) = round.proposal(active_view).cloned() else { return };
            let proposal_hash = proposal.hash();
            if active_view == previous_view && previous_proposal == Some(proposal_hash) {
                return
            }
            let request =
                proposal.consensus_data().map_err(|error| error.to_string()).and_then(|data| {
                    data.decoded_payload().map_err(|error| error.to_string()).and_then(|payload| {
                        match payload {
                            DbftDecodedPayload::PrepareRequest(request) => Ok(*request),
                            _ => Err("accepted proposal is not a PrepareRequest".to_string()),
                        }
                    })
                });
            let request = match request {
                Ok(request) => request,
                Err(error) => {
                    warn!(target: "neox::validator", %peer_id, %error, "Failed to decode accepted Neo X proposal");
                    return
                }
            };
            let action =
                proposal_transactions.begin(peer_id, active_view, proposal_hash, request, |hash| {
                    pool.get_pooled_transaction_element(hash)
                        .map(|transaction| transaction.into_inner())
                });
            match action {
                Ok(action) => dispatch_proposal_action(
                    action,
                    round,
                    provider,
                    beacon,
                    proposal_results,
                    proposal_consensus,
                    proposal_evm,
                    chain_spec,
                ),
                Err(error) => {
                    let reason = proposal_rejection_reason(&error);
                    warn!(target: "neox::validator", %peer_id, %error, "Rejected Neo X proposal transaction commitment");
                    proposal_transactions.clear();
                    publish_local_change_view(
                        round,
                        signer,
                        dbft,
                        reason,
                        block_period,
                        dbft_timer,
                        dbft_timeouts,
                    );
                }
            }
        }
        DbftEvent::Violation { peer_id, reason } => {
            metrics.dbft_transitions_rejected_total.increment(1);
            warn!(target: "neox::sync", %peer_id, ?reason, "Rejected invalid Neo X dbft/0 peer message");
        }
    }
}

/// Canonical notifications can advance the active round while an already-authenticated message
/// for the preceding height is still queued. Neo X Geth treats this exact case as a harmless late
/// message; all other height errors remain protocol-significant.
fn is_stale_dbft_transition(error: &DbftStateError) -> bool {
    matches!(
        error,
        DbftStateError::WrongHeight { expected, end, .. } if end < expected
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_proposal_action<Provider>(
    action: ProposalTransactionAction,
    round: &DbftRoundState,
    provider: &Provider,
    beacon: &BeaconProtocol,
    proposal_results: &mpsc::UnboundedSender<ProposalVerificationResult>,
    proposal_consensus: &NeoXConsensus,
    proposal_evm: &NeoXEvmConfig,
    chain_spec: &Arc<NeoXChainSpec>,
) where
    Provider: HeaderProvider<Header = Header> + StateProviderFactory + Clone + Send + 'static,
{
    match action {
        ProposalTransactionAction::Request { peer_id, request } => {
            let request_id = request.request_id;
            let count = request.message.0.len();
            if beacon.send(peer_id, BeaconCommand::GetTransactions(request)) {
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
            let provider = provider.clone();
            let proposal_consensus = proposal_consensus.clone();
            let proposal_evm = proposal_evm.clone();
            let chain_spec = Arc::clone(chain_spec);
            let proposal_results = proposal_results.clone();
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

fn handle_proposal_verification<Provider>(
    verification: ProposalVerificationResult,
    context: ProposalVerificationContext<'_, Provider>,
) where
    Provider: BlockReader<Block = Block> + StateProviderFactory + Clone + Send + Sync + 'static,
{
    let ProposalVerificationContext {
        round,
        signer,
        dbft,
        verified_proposals,
        provider,
        engine,
        proposal_evm,
        reconstruction_results,
        reconstruction_attempts,
        beacon,
        sidecar_store,
        proposal_transactions,
        dbft_timer,
        dbft_timeouts,
        block_period,
    } = context;
    let Some(round) = round else {
        debug!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Discarded verified proposal without an active round");
        return
    };
    if round.current_view() != verification.view ||
        round.proposal(verification.view).map(|proposal| proposal.hash()) !=
            Some(verification.proposal_hash)
    {
        debug!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Discarded stale Neo X proposal verification result");
        return
    }
    let verified = match verification.result {
        Ok(verified) => verified,
        Err(error) => {
            let reason = proposal_rejection_reason(&error);
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, %error, "Rejected Neo X proposal after deterministic execution");
            proposal_transactions.clear();
            publish_local_change_view(
                round,
                signer,
                dbft,
                reason,
                block_period,
                dbft_timer,
                dbft_timeouts,
            );
            return
        }
    };
    let progress = if round.anti_mev() {
        let Some(anti_mev) = verified.anti_mev.as_ref() else {
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Verified Anti-MEV proposal is missing Envelope metadata");
            proposal_transactions.clear();
            publish_local_change_view(
                round,
                signer,
                dbft,
                DbftChangeViewReason::TransactionInvalid,
                block_period,
                dbft_timer,
                dbft_timeouts,
            );
            return
        };
        round.finalize_pre_block(verification.view, verified.block.header(), anti_mev.len())
    } else {
        round.finalize_proposal(verification.view, verified.block.header().clone())
    };
    let progress = match progress {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, %error, "Rejected executed Neo X proposal pre-block");
            proposal_transactions.clear();
            publish_local_change_view(
                round,
                signer,
                dbft,
                DbftChangeViewReason::TransactionInvalid,
                block_period,
                dbft_timer,
                dbft_timeouts,
            );
            return
        }
    };
    info!(
        target: "neox::validator",
        block_number = verified.block.number,
        view = verification.view,
        proposal_hash = %verification.proposal_hash,
        ?progress,
        parent_resealed = verified.parent_reseal.is_some(),
        transactions = verified.block.body().transactions.len(),
        "Verified Neo X proposal execution and post-state commitments"
    );
    verified_proposals.insert(verification.proposal_hash, verified);
    maybe_publish_consensus_contribution(round, &progress, signer, dbft, verified_proposals);
    schedule_antimev_reconstruction(
        round,
        verification.view,
        provider,
        proposal_evm,
        verified_proposals,
        reconstruction_attempts,
        reconstruction_results,
    );
    if schedule_committed_proposal(
        round,
        verification.view,
        provider,
        engine,
        beacon,
        sidecar_store,
        verified_proposals,
    ) {
        return
    }

    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if usize::from(local_index) == round.primary_index(verification.view) {
        return
    }
    let response = DbftPrepareResponse { preparation_hash: verification.proposal_hash };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        verification.view,
        DbftMessageType::PrepareResponse,
        &response,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, %error, "Failed to sign Neo X PrepareResponse");
            return
        }
    };
    match round.process(Arc::new(message.clone())) {
        Ok(DbftRoundProgress::Duplicate) => {}
        Ok(progress) => {
            match dbft.publish(message) {
                Ok(true) => {
                    info!(target: "neox::validator", validator_index = local_index, view = verification.view, ?progress, "Published verified Neo X PrepareResponse")
                }
                Ok(false) => {
                    debug!(target: "neox::validator", validator_index = local_index, view = verification.view, "Neo X PrepareResponse was already cached")
                }
                Err(error) => {
                    warn!(target: "neox::validator", validator_index = local_index, view = verification.view, ?error, "Failed to publish Neo X PrepareResponse")
                }
            }
            maybe_publish_consensus_contribution(
                round,
                &progress,
                Some(signer),
                dbft,
                verified_proposals,
            );
            schedule_antimev_reconstruction(
                round,
                verification.view,
                provider,
                proposal_evm,
                verified_proposals,
                reconstruction_attempts,
                reconstruction_results,
            );
            schedule_committed_proposal(
                round,
                verification.view,
                provider,
                engine,
                beacon,
                sidecar_store,
                verified_proposals,
            );
        }
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view = verification.view, %error, "Rejected local Neo X PrepareResponse state transition")
        }
    }
}

fn schedule_antimev_reconstruction<Provider>(
    round: &DbftRoundState,
    view: u8,
    provider: &Provider,
    proposal_evm: &NeoXEvmConfig,
    verified_proposals: &HashMap<B256, VerifiedProposal>,
    reconstruction_attempts: &mut HashMap<B256, AntiMevReconstructionAttempt>,
    reconstruction_results: &mpsc::UnboundedSender<AntiMevReconstructionResult>,
) where
    Provider: StateProviderFactory + Clone + Send + 'static,
{
    if !round.anti_mev() || round.has_final_header(view) {
        return
    }
    if !matches!(round.progress(view), DbftRoundProgress::PreCommitted { .. }) {
        return
    }
    let Some(proposal_hash) = round.proposal(view).map(|proposal| proposal.hash()) else { return };
    let Some(dkg_state) = round.dkg_state().cloned() else {
        warn!(target: "neox::validator", view, %proposal_hash, "Cannot reconstruct Anti-MEV block without canonical DKG state");
        return
    };
    let contributions = round
        .pre_commits(view)
        .into_iter()
        .map(|(index, pre_commit)| (index, pre_commit.clone()))
        .collect::<Vec<_>>();
    if contributions.len() < round.quorum() {
        warn!(target: "neox::validator", view, %proposal_hash, contributions = contributions.len(), threshold = round.quorum(), "Anti-MEV share quorum has no complete DKG index mapping");
        return
    }
    let Some(verified) = verified_proposals.get(&proposal_hash).cloned() else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for verified Anti-MEV pre-block before reconstruction");
        return
    };
    let contribution_count = contributions.len();
    let attempt = reconstruction_attempts.entry(proposal_hash).or_default();
    if !attempt.begin(contribution_count) {
        return
    }
    let threshold = round.quorum();
    let provider = provider.clone();
    let proposal_evm = proposal_evm.clone();
    let reconstruction_results = reconstruction_results.clone();
    tokio::task::spawn_blocking(move || {
        let result = (|| {
            let anti_mev = verified
                .anti_mev
                .as_ref()
                .ok_or_else(|| "verified proposal is missing Anti-MEV metadata".to_string())?;
            let contribution_refs = contributions
                .iter()
                .map(|(index, pre_commit)| (*index, pre_commit))
                .collect::<Vec<_>>();
            let resolutions = anti_mev
                .decrypt_and_validate(
                    &contribution_refs,
                    &dkg_state,
                    threshold,
                    AntiMevPreBlock {
                        transactions: &verified.block.body().transactions,
                        senders: verified.block.senders(),
                        receipts: &verified.execution.result.receipts,
                        parent_base_fee: verified.parent_base_fee,
                    },
                )
                .map_err(|error| error.to_string())?;
            reconstruct_antimev_proposal(verified, resolutions, &provider, &proposal_evm)
                .map_err(|error| error.to_string())
        })();
        let _ = reconstruction_results.send(AntiMevReconstructionResult {
            view,
            proposal_hash,
            result,
        });
    });
    debug!(target: "neox::validator", view, %proposal_hash, contributions = contribution_count, "Scheduled Neo X Anti-MEV reconstruction attempt");
}

#[expect(clippy::too_many_arguments)]
fn handle_antimev_reconstruction<Provider>(
    reconstruction: AntiMevReconstructionResult,
    round: Option<&mut DbftRoundState>,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    verified_proposals: &mut HashMap<B256, VerifiedProposal>,
    provider: &Provider,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
    beacon: &BeaconProtocol,
    sidecar_store: &NeoXSidecarStore,
    proposal_evm: &NeoXEvmConfig,
    reconstruction_results: &mpsc::UnboundedSender<AntiMevReconstructionResult>,
    reconstruction_attempts: &mut HashMap<B256, AntiMevReconstructionAttempt>,
) where
    Provider: BlockReader<Block = Block> + StateProviderFactory + Clone + Send + Sync + 'static,
{
    if let Some(attempt) = reconstruction_attempts.get_mut(&reconstruction.proposal_hash) {
        attempt.finish();
    }
    let Some(round) = round else {
        reconstruction_attempts.remove(&reconstruction.proposal_hash);
        debug!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, "Discarded Anti-MEV reconstruction without an active round");
        return
    };
    if round.current_view() != reconstruction.view ||
        round.proposal(reconstruction.view).map(|proposal| proposal.hash()) !=
            Some(reconstruction.proposal_hash)
    {
        reconstruction_attempts.remove(&reconstruction.proposal_hash);
        debug!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, "Discarded stale Anti-MEV reconstruction result");
        return
    }
    let reconstructed = match reconstruction.result {
        Ok(reconstructed) => reconstructed,
        Err(error) => {
            let attempted = reconstruction_attempts
                .get(&reconstruction.proposal_hash)
                .map_or(0, |attempt| attempt.attempted_contributions);
            warn!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, contributions = attempted, %error, "Neo X Anti-MEV reconstruction needs more valid shares");
            schedule_antimev_reconstruction(
                round,
                reconstruction.view,
                provider,
                proposal_evm,
                verified_proposals,
                reconstruction_attempts,
                reconstruction_results,
            );
            return
        }
    };
    let decrypted = reconstructed
        .decisions
        .iter()
        .filter(|decision| matches!(decision, AntiMevTransactionDecision::IncludedDecrypted { .. }))
        .count();
    let fallbacks = reconstructed
        .decisions
        .iter()
        .filter(|decision| matches!(decision, AntiMevTransactionDecision::IncludedFallback { .. }))
        .count();
    let dropped = reconstructed
        .decisions
        .iter()
        .filter(|decision| matches!(decision, AntiMevTransactionDecision::Dropped { .. }))
        .count();
    let proposal = reconstructed.proposal;
    let progress = match round
        .finalize_proposal(reconstruction.view, proposal.block.header().clone())
    {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, %error, "Rejected reconstructed Neo X Anti-MEV final header");
            schedule_antimev_reconstruction(
                round,
                reconstruction.view,
                provider,
                proposal_evm,
                verified_proposals,
                reconstruction_attempts,
                reconstruction_results,
            );
            return
        }
    };
    info!(
        target: "neox::validator",
        block_number = proposal.block.number,
        view = reconstruction.view,
        proposal_hash = %reconstruction.proposal_hash,
        transactions = proposal.block.body().transactions.len(),
        decrypted,
        fallbacks,
        dropped,
        ?progress,
        "Reconstructed Neo X Anti-MEV final block"
    );
    reconstruction_attempts.remove(&reconstruction.proposal_hash);
    verified_proposals.insert(reconstruction.proposal_hash, proposal);
    maybe_publish_consensus_contribution(round, &progress, signer, dbft, verified_proposals);
    schedule_committed_proposal(
        round,
        reconstruction.view,
        provider,
        engine,
        beacon,
        sidecar_store,
        verified_proposals,
    );
}

fn maybe_publish_consensus_contribution(
    round: &mut DbftRoundState,
    progress: &DbftRoundProgress,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    verified_proposals: &HashMap<B256, VerifiedProposal>,
) {
    if round.anti_mev() {
        maybe_publish_antimev_precommit(round, progress, signer, dbft, verified_proposals);
        maybe_publish_antimev_commit(round, progress, signer, dbft);
    } else {
        maybe_publish_pre_antimev_commit(round, progress, signer, dbft, verified_proposals);
    }
}

fn maybe_publish_antimev_precommit(
    round: &mut DbftRoundState,
    progress: &DbftRoundProgress,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    verified_proposals: &HashMap<B256, VerifiedProposal>,
) {
    let view = match progress {
        DbftRoundProgress::Prepared { view, .. } | DbftRoundProgress::PreCommitted { view, .. } => {
            *view
        }
        _ => return,
    };
    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if round.has_pre_commit(view, local_index) {
        return
    }
    let Some(proposal_hash) = round.proposal(view).map(|proposal| proposal.hash()) else { return };
    let Some(anti_mev) =
        verified_proposals.get(&proposal_hash).and_then(|proposal| proposal.anti_mev.as_ref())
    else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local Anti-MEV pre-block validation before signing PreCommit");
        return
    };

    let current_ciphertexts = anti_mev.ciphertexts(EnvelopeDkgEpoch::Current);
    let current_shares = if current_ciphertexts.is_empty() {
        Vec::new()
    } else {
        match signer.current_decryption_shares(&current_ciphertexts) {
            Ok(shares) => shares,
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, %error, "Unable to create current-round Neo X decryption shares");
                Vec::new()
            }
        }
    };
    let previous_ciphertexts = anti_mev.ciphertexts(EnvelopeDkgEpoch::Previous);
    let previous_shares = if previous_ciphertexts.is_empty() {
        Vec::new()
    } else {
        match signer.previous_decryption_shares(&previous_ciphertexts) {
            Ok(shares) => shares,
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, %error, "Unable to create previous-round Neo X decryption shares");
                Vec::new()
            }
        }
    };
    let encoded = match encode_decryption_shares(&current_shares, &previous_shares) {
        Ok(encoded) => encoded,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to encode Neo X PreCommit shares");
            return
        }
    };
    let pre_commit = match DbftPreCommit::from_data(encoded.into()) {
        Ok(pre_commit) => pre_commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Generated invalid Neo X PreCommit payload");
            return
        }
    };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        view,
        DbftMessageType::PreCommit,
        &pre_commit,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to authenticate Neo X PreCommit");
            return
        }
    };
    match round.process(Arc::new(message.clone())) {
        Ok(DbftRoundProgress::Duplicate) => {}
        Ok(progress) => match dbft.publish(message) {
            Ok(true) => info!(
                target: "neox::validator",
                validator_index = local_index,
                view,
                current_shares = current_shares.len(),
                previous_shares = previous_shares.len(),
                ?progress,
                "Published verified Neo X Anti-MEV PreCommit"
            ),
            Ok(false) => {
                debug!(target: "neox::validator", validator_index = local_index, view, "Neo X PreCommit was already cached")
            }
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, ?error, "Failed to publish Neo X PreCommit")
            }
        },
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Rejected local Neo X PreCommit state transition")
        }
    }
}

fn maybe_publish_antimev_commit(
    round: &mut DbftRoundState,
    progress: &DbftRoundProgress,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
) {
    let DbftRoundProgress::PreCommitted { view, .. } = progress else { return };
    let view = *view;
    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if round.has_commit(view, local_index) {
        return
    }
    let Some(header) = round.final_header(view) else {
        debug!(target: "neox::validator", validator_index = local_index, view, "Waiting for Anti-MEV final-block reconstruction before signing Commit");
        return
    };
    let commit = match signer.commit_for_header(header) {
        Ok(commit) => commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to sign Neo X Anti-MEV final block commit");
            return
        }
    };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        view,
        DbftMessageType::Commit,
        &commit,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to authenticate Neo X Anti-MEV Commit");
            return
        }
    };
    match round.process(Arc::new(message.clone())) {
        Ok(DbftRoundProgress::Duplicate) => {}
        Ok(progress) => match dbft.publish(message) {
            Ok(true) => info!(
                target: "neox::validator",
                validator_index = local_index,
                view,
                ?progress,
                "Published verified Neo X Anti-MEV final block Commit"
            ),
            Ok(false) => {
                debug!(target: "neox::validator", validator_index = local_index, view, "Neo X Anti-MEV Commit was already cached")
            }
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, ?error, "Failed to publish Neo X Anti-MEV Commit")
            }
        },
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Rejected local Neo X Anti-MEV Commit state transition")
        }
    }
}

fn maybe_publish_pre_antimev_commit(
    round: &mut DbftRoundState,
    progress: &DbftRoundProgress,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    verified_proposals: &HashMap<B256, VerifiedProposal>,
) {
    let DbftRoundProgress::Prepared { view, proposal_hash, .. } = progress else { return };
    let (view, proposal_hash) = (*view, *proposal_hash);
    if round.anti_mev() {
        return
    }
    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    let Some(verified) = verified_proposals.get(&proposal_hash) else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local proposal execution before signing Neo X commit");
        return
    };
    let commit = match signer.commit_for_header(verified.block.header()) {
        Ok(commit) => commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to sign Neo X block commit");
            return
        }
    };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        view,
        DbftMessageType::Commit,
        &commit,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to authenticate Neo X block commit");
            return
        }
    };
    match round.process(Arc::new(message.clone())) {
        Ok(DbftRoundProgress::Duplicate) => {}
        Ok(progress) => match dbft.publish(message) {
            Ok(true) => {
                info!(target: "neox::validator", validator_index = local_index, view, ?progress, "Published verified Neo X block commit")
            }
            Ok(false) => {
                debug!(target: "neox::validator", validator_index = local_index, view, "Neo X block commit was already cached")
            }
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, ?error, "Failed to publish Neo X block commit")
            }
        },
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Rejected local Neo X block commit state transition")
        }
    }
}

fn schedule_committed_proposal<Provider>(
    round: &DbftRoundState,
    view: u8,
    provider: &Provider,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
    beacon: &BeaconProtocol,
    sidecar_store: &NeoXSidecarStore,
    verified_proposals: &mut HashMap<B256, VerifiedProposal>,
) -> bool
where
    Provider: BlockReader<Block = Block> + Clone + Send + Sync + 'static,
{
    let DbftRoundProgress::Committed { .. } = round.progress(view) else { return false };
    let Some(proposal_hash) = round.proposal(view).map(|proposal| proposal.hash()) else {
        warn!(target: "neox::validator", view, "Committed Neo X dBFT view has no proposal");
        return false
    };
    let sealed_header = match round.sealed_header(view) {
        Ok(header) => header,
        Err(error) => {
            warn!(target: "neox::validator", view, %proposal_hash, %error, "Failed to assemble committed Neo X proposal seal");
            return false
        }
    };
    let Some(verified) = verified_proposals.remove(&proposal_hash) else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local proposal execution before importing committed Neo X block");
        return false
    };

    let parent_state_hash = verified.parent_state_hash;
    let parent_reseal = verified.parent_reseal;
    let sidecars = verified.sidecars;
    let mut block = verified.block.into_block();
    block.header = sealed_header;
    let block_number = block.header.number;
    let block_hash = block.header.hash_slow();
    let provider = provider.clone();
    let engine = engine.clone();
    let beacon = beacon.clone();
    let sidecar_store = sidecar_store.clone();
    tokio::spawn(async move {
        let parent = if let Some(parent_reseal) = parent_reseal {
            let result = tokio::task::spawn_blocking(move || {
                provider.block_by_hash(parent_state_hash).map(|block| {
                    block.map(|mut block| {
                        block.header = parent_reseal.into_header();
                        block
                    })
                })
            })
            .await;
            match result {
                Ok(Ok(Some(parent))) => Some(parent),
                Ok(Ok(None)) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %parent_state_hash, "Cannot import committed Neo X block without its canonical parent body");
                    return
                }
                Ok(Err(error)) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %parent_state_hash, %error, "Failed to load canonical parent for Neo X witness reseal");
                    return
                }
                Err(error) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %parent_state_hash, %error, "Neo X parent witness resolution task failed");
                    return
                }
            }
        } else {
            None
        };
        let sidecars_valid = if sidecars.is_empty() {
            false
        } else {
            match validate_block_sidecars(&block.body, &sidecars) {
                Ok(()) => true,
                Err(error) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %error, "Rejected sidecars for committed Neo X block");
                    false
                }
            }
        };
        if import_committed_block(parent, block, &engine).await && sidecars_valid {
            match sidecar_store.insert(block_hash, sidecars) {
                Ok(()) => {
                    beacon.broadcast(BeaconCommand::NewBlobsRoot(NewBlobsRoot { block_hash }));
                    info!(target: "neox::sync", block_number, %block_hash, "Archived and announced committed Neo X sidecars");
                }
                Err(error) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %error, "Failed to archive committed Neo X sidecars")
                }
            }
        }
    });
    true
}

async fn import_committed_block(
    parent_reseal: Option<Block>,
    block: Block,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
) -> bool {
    let block_number = block.header.number;
    let block_hash = block.header.hash_slow();
    let parent_resealed = parent_reseal.is_some();
    if let Some(parent) = parent_reseal {
        let parent_number = parent.header.number;
        let parent_hash = parent.header.hash_slow();
        if block.header.parent_hash != parent_hash {
            warn!(target: "neox::sync", block_number, %block_hash, expected_parent = %block.header.parent_hash, actual_parent = %parent_hash, "Authenticated Neo X parent witness does not match committed child");
            return false
        }
        let parent_payload = EthPayloadTypes::block_to_payload(parent.seal_slow(), None);
        match engine.new_payload(parent_payload).await {
            Ok(status) if status.is_valid() => {
                debug!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, "Imported authenticated Neo X parent witness reseal");
            }
            Ok(status) if status.is_syncing() => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, "Engine Tree is missing ancestry for Neo X parent witness reseal");
                request_sync_target(engine, parent_hash).await;
                return false
            }
            Ok(status) => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, status = %status, "Engine Tree rejected authenticated Neo X parent witness reseal");
                return false
            }
            Err(error) => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, %error, "Neo X parent witness reseal import failed");
                return false
            }
        }
    }

    let block: SealedBlock<_> = block.seal_slow();
    debug_assert_eq!(block_hash, block.hash());
    let payload = EthPayloadTypes::block_to_payload(block, None);
    match engine.new_payload(payload).await {
        Ok(status) if status.is_valid() => {}
        Ok(status) if status.is_syncing() => {
            warn!(target: "neox::sync", block_number, %block_hash, "Engine Tree is missing ancestry for committed Neo X block");
            request_sync_target(engine, block_hash).await;
            return false
        }
        Ok(status) => {
            warn!(target: "neox::sync", block_number, %block_hash, status = %status, "Engine Tree rejected committed Neo X block");
            return false
        }
        Err(error) => {
            warn!(target: "neox::sync", block_number, %block_hash, %error, "Committed Neo X block import failed");
            return false
        }
    }

    match engine.fork_choice_updated(ForkchoiceState::same_hash(block_hash), None).await {
        Ok(updated) if updated.payload_status.is_valid() => {
            info!(
                target: "neox::sync",
                block_number,
                %block_hash,
                parent_resealed,
                "Imported and finalized committed Neo X dBFT block"
            );
            true
        }
        Ok(updated) => {
            warn!(target: "neox::sync", block_number, %block_hash, status = %updated.payload_status, "Neo X forkchoice rejected committed dBFT block");
            false
        }
        Err(error) => {
            warn!(target: "neox::sync", block_number, %block_hash, %error, "Neo X committed block forkchoice update failed");
            false
        }
    }
}

fn reset_dbft_timer(
    round: Option<&DbftRoundState>,
    signer: Option<&DbftSigner>,
    block_period: Duration,
    timer: &mut DbftTimerState,
    timeouts: &mpsc::UnboundedSender<DbftTimeout>,
) {
    let (Some(round), Some(signer)) = (round, signer) else {
        timer.disarm();
        return
    };
    let Some(local_index) = signer.validator_index(round.validators()) else {
        timer.disarm();
        return
    };
    let view = round.current_view();
    let is_primary = usize::from(local_index) == round.primary_index(view);
    timer.arm(round.height(), view, round_timeout(block_period, view, is_primary), timeouts);
}

#[expect(clippy::too_many_arguments)]
fn handle_dbft_timeout(
    timeout: DbftTimeout,
    round: Option<&mut DbftRoundState>,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    proposal_transactions: &mut ProposalTransactionSync,
    block_period: Duration,
    timer: &mut DbftTimerState,
    timeouts: &mpsc::UnboundedSender<DbftTimeout>,
) -> bool {
    if !timer.consume(timeout) {
        return false
    }
    let (Some(round), Some(signer)) = (round, signer) else { return false };
    if round.height() != timeout.height || round.current_view() != timeout.view {
        debug!(
            target: "neox::validator",
            block_number = timeout.height,
            view = timeout.view,
            "Ignored stale local Neo X dBFT timeout"
        );
        return false
    }
    let Some(local_index) = signer.validator_index(round.validators()) else { return false };
    let is_primary = usize::from(local_index) == round.primary_index(timeout.view);
    if is_primary && round.proposal(timeout.view).is_none() {
        timer.arm(
            timeout.height,
            timeout.view,
            post_proposal_timeout(block_period, timeout.view),
            timeouts,
        );
        info!(
            target: "neox::producer",
            block_number = timeout.height,
            view = timeout.view,
            validator_index = local_index,
            "Local Neo X primary proposal timer expired"
        );
        return false
    }
    if round.has_pre_commit(timeout.view, local_index) ||
        round.has_commit(timeout.view, local_index)
    {
        publish_recovery_message(round, signer, dbft);
        timer.arm(timeout.height, timeout.view, scaled_block_period(block_period, 1), timeouts);
        return false
    }
    let Some(next_view) = timeout.view.checked_add(1) else {
        warn!(
            target: "neox::validator",
            block_number = timeout.height,
            "Cannot advance Neo X dBFT past the maximum view"
        );
        return false
    };
    let recovery_delay = change_view_timeout(block_period, next_view);
    if round.more_than_f_committed_or_failed(timeout.view, local_index) {
        publish_recovery_request(round, signer, local_index, dbft);
        timer.arm(timeout.height, timeout.view, recovery_delay, timeouts);
        return false
    }
    let missing_transactions = round.proposal(timeout.view).is_some_and(|proposal| {
        proposal_transactions.is_waiting_for(timeout.view, proposal.hash())
    });
    let reason = if missing_transactions {
        DbftChangeViewReason::TransactionNotFound
    } else {
        DbftChangeViewReason::Timeout
    };
    let outcome =
        publish_local_change_view(round, Some(signer), dbft, reason, block_period, timer, timeouts);
    if outcome.requested {
        proposal_transactions.clear();
    }
    outcome.changed_view
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LocalChangeViewOutcome {
    requested: bool,
    changed_view: bool,
}

fn publish_local_change_view(
    round: &mut DbftRoundState,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    reason: DbftChangeViewReason,
    block_period: Duration,
    timer: &mut DbftTimerState,
    timeouts: &mpsc::UnboundedSender<DbftTimeout>,
) -> LocalChangeViewOutcome {
    let Some(signer) = signer else { return LocalChangeViewOutcome::default() };
    let Some(local_index) = signer.validator_index(round.validators()) else {
        return LocalChangeViewOutcome::default()
    };
    let height = round.height();
    let view = round.current_view();
    let Some(next_view) = view.checked_add(1) else {
        warn!(target: "neox::validator", block_number = height, "Cannot advance Neo X dBFT past the maximum view");
        return LocalChangeViewOutcome::default()
    };
    let retry_delay = change_view_timeout(block_period, next_view);
    if let Some(message) = round.message(view, DbftMessageType::ChangeView, local_index) {
        match dbft.publish(message.as_ref().clone()) {
            Ok(inserted) => debug!(
                target: "neox::validator",
                block_number = height,
                view,
                validator_index = local_index,
                inserted,
                "Re-published local Neo X ChangeView"
            ),
            Err(error) => warn!(
                target: "neox::validator",
                block_number = height,
                view,
                ?error,
                "Failed to re-publish local Neo X ChangeView"
            ),
        }
        timer.arm(height, view, retry_delay, timeouts);
        return LocalChangeViewOutcome { requested: true, changed_view: false }
    }

    let payload = DbftChangeView::new(unix_timestamp_ns(), reason);
    let message = match signer.sign_message(
        height,
        local_index,
        view,
        DbftMessageType::ChangeView,
        &payload,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::validator", block_number = height, view, %error, "Failed to sign local Neo X ChangeView");
            return LocalChangeViewOutcome::default()
        }
    };
    let message_hash = message.hash();
    let progress = match round.process(Arc::new(message.clone())) {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::validator", block_number = height, view, %error, "Rejected local Neo X ChangeView state transition");
            return LocalChangeViewOutcome::default()
        }
    };
    match dbft.publish(message) {
        Ok(inserted) => info!(
            target: "neox::validator",
            block_number = height,
            view,
            new_view = next_view,
            validator_index = local_index,
            ?reason,
            %message_hash,
            inserted,
            ?progress,
            "Published local Neo X ChangeView"
        ),
        Err(error) => warn!(
            target: "neox::validator",
            block_number = height,
            view,
            ?reason,
            ?error,
            "Failed to publish local Neo X ChangeView"
        ),
    }
    let changed_view = round.current_view() != view;
    if changed_view {
        reset_dbft_timer(Some(round), Some(signer), block_period, timer, timeouts);
    } else {
        timer.arm(height, view, retry_delay, timeouts);
    }
    LocalChangeViewOutcome { requested: true, changed_view }
}

const fn proposal_rejection_reason(error: &DbftProposalError) -> DbftChangeViewReason {
    match error {
        DbftProposalError::InvalidExtra(_) |
        DbftProposalError::UnexpectedExtraVersion { .. } |
        DbftProposalError::ThresholdBeforeAntiMev |
        DbftProposalError::GenesisProposal |
        DbftProposalError::MissingCanonicalParent(_) |
        DbftProposalError::GenesisParentMismatch { .. } |
        DbftProposalError::MissingParentSealHash |
        DbftProposalError::MissingParentExtra |
        DbftProposalError::MissingGrandparent(_) |
        DbftProposalError::ParentWitness(_) |
        DbftProposalError::Header(_) |
        DbftProposalError::Provider(_) |
        DbftProposalError::HeightOverflow => DbftChangeViewReason::BlockRejectedByPolicy,
        DbftProposalError::TooManyTransactions(_) |
        DbftProposalError::DuplicateTransaction(_) |
        DbftProposalError::UnknownTransactionResponse(_) |
        DbftProposalError::EmptyTransactionResponse(_) |
        DbftProposalError::WrongTransactionPeer { .. } |
        DbftProposalError::UnexpectedTransaction(_) |
        DbftProposalError::TransactionCount { .. } |
        DbftProposalError::TransactionHash { .. } |
        DbftProposalError::SidecarCount { .. } |
        DbftProposalError::InvalidSidecar { .. } |
        DbftProposalError::PreExecution(_) |
        DbftProposalError::SenderRecovery |
        DbftProposalError::Execution(_) |
        DbftProposalError::PostExecution(_) |
        DbftProposalError::StateRoot { .. } |
        DbftProposalError::Governance(_) |
        DbftProposalError::Dkg(_) |
        DbftProposalError::FallbackNextConsensus { .. } |
        DbftProposalError::NextConsensus { .. } => DbftChangeViewReason::TransactionInvalid,
    }
}

fn maybe_respond_to_recovery_request(
    round: &DbftRoundState,
    request: &reth_neox_network::DbftMessage,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
) {
    let Some(signer) = signer else { return };
    let Ok(data) = request.consensus_data() else { return };
    if data.message_type != DbftMessageType::RecoveryRequest ||
        data.view_number > round.current_view()
    {
        return
    }
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    let committed = round.has_any_pre_commit(local_index) || round.has_any_commit(local_index);
    if !recovery_response_allowed(
        round.validators().len(),
        data.validator_index,
        local_index,
        committed,
    ) {
        return
    }
    publish_recovery_message(round, signer, dbft);
}

fn recovery_response_allowed(
    validator_count: usize,
    requester: u8,
    local_index: u8,
    committed: bool,
) -> bool {
    if committed {
        return true
    }
    let requester = usize::from(requester);
    let local = usize::from(local_index);
    if validator_count == 0 || requester >= validator_count || local >= validator_count {
        return false
    }
    let response_offset =
        (local + validator_count - requester + validator_count - 1) % validator_count;
    response_offset <= validator_count.saturating_sub(1) / 3
}

fn publish_recovery_request(
    round: &DbftRoundState,
    signer: &DbftSigner,
    local_index: u8,
    dbft: &DbftProtocol,
) {
    let request = DbftRecoveryRequest { timestamp_ns: unix_timestamp_ns() };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        round.current_view(),
        DbftMessageType::RecoveryRequest,
        &request,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(
                target: "neox::validator",
                block_number = round.height(),
                view = round.current_view(),
                %error,
                "Failed to sign local Neo X RecoveryRequest"
            );
            return
        }
    };
    match dbft.publish(message) {
        Ok(inserted) => info!(
            target: "neox::validator",
            block_number = round.height(),
            view = round.current_view(),
            validator_index = local_index,
            inserted,
            "Published local Neo X RecoveryRequest"
        ),
        Err(error) => warn!(
            target: "neox::validator",
            block_number = round.height(),
            view = round.current_view(),
            ?error,
            "Failed to publish local Neo X RecoveryRequest"
        ),
    }
}

fn publish_recovery_message(round: &DbftRoundState, signer: &DbftSigner, dbft: &DbftProtocol) {
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    let recovery = match round.recovery_message(local_index) {
        Ok(recovery) => recovery,
        Err(error) => {
            warn!(
                target: "neox::validator",
                block_number = round.height(),
                view = round.current_view(),
                %error,
                "Failed to compact local Neo X recovery state"
            );
            return
        }
    };
    let message = match signer.sign_message(
        round.height(),
        local_index,
        round.current_view(),
        DbftMessageType::RecoveryMessage,
        &recovery,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(
                target: "neox::validator",
                block_number = round.height(),
                view = round.current_view(),
                %error,
                "Failed to sign local Neo X RecoveryMessage"
            );
            return
        }
    };
    match dbft.publish(message) {
        Ok(inserted) => info!(
            target: "neox::validator",
            block_number = round.height(),
            view = round.current_view(),
            validator_index = local_index,
            inserted,
            "Published local Neo X RecoveryMessage"
        ),
        Err(error) => warn!(
            target: "neox::validator",
            block_number = round.height(),
            view = round.current_view(),
            ?error,
            "Failed to publish local Neo X RecoveryMessage"
        ),
    }
}

fn unix_timestamp_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn round_timeout(block_period: Duration, view: u8, is_primary: bool) -> Duration {
    if is_primary {
        if view == 0 {
            block_period
        } else {
            Duration::ZERO
        }
    } else {
        scaled_block_period(block_period, u32::from(view) + 1)
    }
}

fn post_proposal_timeout(block_period: Duration, view: u8) -> Duration {
    let delay = scaled_block_period(block_period, u32::from(view) + 1);
    if view == 0 {
        delay.saturating_sub(block_period)
    } else {
        delay
    }
}

fn change_view_timeout(block_period: Duration, new_view: u8) -> Duration {
    scaled_block_period(block_period, u32::from(new_view) + 1)
}

fn scaled_block_period(block_period: Duration, exponent: u32) -> Duration {
    let Some(multiplier) = 1_u32.checked_shl(exponent) else { return Duration::MAX };
    block_period.checked_mul(multiplier).unwrap_or(Duration::MAX)
}

#[allow(clippy::too_many_arguments)]
fn maybe_schedule_primary_proposal<Pool, Provider>(
    round: Option<&DbftRoundState>,
    signer: Option<&DbftSigner>,
    pool: &Pool,
    provider: &Provider,
    proposal_evm: &NeoXEvmConfig,
    chain_spec: &Arc<NeoXChainSpec>,
    results: &mpsc::UnboundedSender<PrimaryProposalResult>,
    builds: &mut HashSet<(u64, u8)>,
) where
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        > + 'static,
    Provider: HeaderProvider<Header = Header> + StateProviderFactory + Clone + Send + 'static,
{
    let (Some(round), Some(signer)) = (round, signer) else { return };
    let view = round.current_view();
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if usize::from(local_index) != round.primary_index(view) || round.proposal(view).is_some() {
        return
    }
    let key = (round.height(), view);
    if !builds.insert(key) {
        return
    }
    let signature_scheme =
        if round.anti_mev() { SignatureScheme::Threshold } else { SignatureScheme::Ecdsa };
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let attributes = PrimaryProposalAttributes::new(view, timestamp, signature_scheme);
    let round = round.clone();
    let pool = pool.clone();
    let provider = provider.clone();
    let proposal_evm = proposal_evm.clone();
    let chain_spec = Arc::clone(chain_spec);
    let results = results.clone();
    info!(
        target: "neox::producer",
        block_number = key.0,
        view,
        validator_index = local_index,
        ?signature_scheme,
        "Scheduled local Neo X primary proposal"
    );
    tokio::task::spawn_blocking(move || {
        let result = build_primary_proposal(
            &round,
            attributes,
            &pool,
            &provider,
            &proposal_evm,
            chain_spec.as_ref(),
        );
        let _ = results.send(PrimaryProposalResult { height: key.0, view, result });
    });
}

fn handle_primary_proposal<Provider>(
    result: PrimaryProposalResult,
    context: PrimaryProposalContext<'_, Provider>,
) where
    Provider: HeaderProvider<Header = Header> + StateProviderFactory + Clone + Send + 'static,
{
    let PrimaryProposalContext {
        round,
        signer,
        dbft,
        provider,
        beacon,
        proposal_results,
        proposal_consensus,
        proposal_evm,
        chain_spec,
        primary_builds,
        dbft_timer,
        dbft_timeouts,
        block_period,
    } = context;
    primary_builds.remove(&(result.height, result.view));
    let (Some(round), Some(signer)) = (round, signer) else {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded primary proposal without an active local validator");
        return
    };
    if round.height() != result.height || round.current_view() != result.view {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded stale local primary proposal");
        return
    }
    let Some(local_index) = signer.validator_index(round.validators()) else {
        warn!(target: "neox::producer", account = %signer.account(), "Local primary signer left the active Governance set");
        return
    };
    if usize::from(local_index) != round.primary_index(result.view) ||
        round.proposal(result.view).is_some()
    {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded superseded local primary proposal");
        return
    }
    let proposal = match result.result {
        Ok(proposal) => proposal,
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, %error, "Failed to build local Neo X primary proposal");
            return
        }
    };
    let message = match signer.sign_message(
        result.height,
        local_index,
        result.view,
        DbftMessageType::PrepareRequest,
        &proposal.request,
    ) {
        Ok(message) => message,
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, %error, "Failed to sign local Neo X PrepareRequest");
            return
        }
    };
    let proposal_hash = message.hash();
    let progress = match round.process(Arc::new(message.clone())) {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, %error, "Rejected local Neo X PrepareRequest state transition");
            return
        }
    };
    match dbft.publish(message) {
        Ok(inserted) => {
            info!(
                target: "neox::producer",
                block_number = result.height,
                view = result.view,
                validator_index = local_index,
                %proposal_hash,
                transactions = proposal.transactions.len(),
                inserted,
                ?progress,
                "Published local Neo X PrepareRequest"
            );
        }
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, ?error, "Failed to publish local Neo X PrepareRequest");
            return
        }
    }
    dbft_timer.arm(
        result.height,
        result.view,
        post_proposal_timeout(block_period, result.view),
        dbft_timeouts,
    );
    dispatch_proposal_action(
        ProposalTransactionAction::Ready {
            view: result.view,
            proposal_hash,
            request: Box::new(proposal.request),
            transactions: proposal.transactions,
            sidecars: proposal.sidecars,
        },
        round,
        provider,
        beacon,
        proposal_results,
        proposal_consensus,
        proposal_evm,
        chain_spec,
    );
}

fn activate_dbft_round<Provider>(
    canonical_height: u64,
    provider: &Provider,
    dbft: &DbftProtocol,
    chain_spec: &NeoXChainSpec,
    signer: Option<&DbftSigner>,
    round: &mut Option<DbftRoundState>,
) where
    Provider: StateProviderFactory,
{
    let Some(next_height) = canonical_height.checked_add(1) else {
        dbft.deactivate();
        *round = None;
        warn!(target: "neox::validator", "Cannot start dBFT round after maximum block height");
        return
    };
    let result = provider.latest().map_err(|error| error.to_string()).and_then(|state| {
        let validator_set =
            read_governance_validator_set(state.as_ref()).map_err(|error| error.to_string())?;
        let validators = validator_set.sorted.clone();
        let local_validator_index = signer.and_then(|signer| signer.validator_index(&validators));
        dbft.activate(canonical_height, validators.clone())
            .map_err(|error| format!("{error:?}"))?;
        let anti_mev = chain_spec.is_anti_mev_active_at_block(next_height);
        let mut round = DbftRoundState::new(next_height, validators, anti_mev)
            .map_err(|error| error.to_string())?;
        if anti_mev {
            let dkg_state = read_dkg_state(state.as_ref()).map_err(|error| error.to_string())?;
            round
                .install_dkg_state(validator_set.dkg_indices, dkg_state)
                .map_err(|error| error.to_string())?;
        }
        Ok((round, local_validator_index))
    });
    match result {
        Ok((next_round, local_validator_index)) => {
            info!(
                target: "neox::validator",
                canonical_height,
                next_height,
                validators = NEOX_VALIDATOR_COUNT,
                "Activated Neo X dBFT round from Governance state"
            );
            if let Some(signer) = signer {
                match local_validator_index {
                    Some(index) => info!(
                        target: "neox::validator",
                        account = %signer.account(),
                        validator_index = index,
                        "Activated local Neo X validator signer"
                    ),
                    None => warn!(
                        target: "neox::validator",
                        account = %signer.account(),
                        "Configured Neo X validator is not in the active Governance set"
                    ),
                }
            }
            *round = Some(next_round);
        }
        Err(error) => {
            dbft.deactivate();
            *round = None;
            warn!(target: "neox::validator", canonical_height, %error, "Failed to activate Neo X dBFT round");
        }
    }
}

struct BeaconEventContext<'a, Pool, Provider> {
    beacon: &'a BeaconProtocol,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    pool: &'a Pool,
    provider: &'a Provider,
    sidecars: &'a mut SidecarSync,
    dbft: &'a DbftProtocol,
    chain_spec: &'a Arc<NeoXChainSpec>,
    signer: Option<&'a DbftSigner>,
    dbft_round: &'a mut Option<DbftRoundState>,
    proposal_transactions: &'a mut ProposalTransactionSync,
    proposal_results: &'a mpsc::UnboundedSender<ProposalVerificationResult>,
    proposal_consensus: &'a NeoXConsensus,
    proposal_evm: &'a NeoXEvmConfig,
    primary_builds: &'a mut HashSet<(u64, u8)>,
    dbft_timer: &'a mut DbftTimerState,
    dbft_timeouts: &'a mpsc::UnboundedSender<DbftTimeout>,
    block_period: Duration,
}

async fn handle_beacon_event<Pool, Provider>(
    event: BeaconEvent,
    context: BeaconEventContext<'_, Pool, Provider>,
) where
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        > + 'static,
    Provider: BlockReader<Block = Block>
        + HeaderProvider<Header = Header>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    let BeaconEventContext {
        beacon,
        engine,
        pool,
        provider,
        sidecars,
        dbft,
        chain_spec,
        signer,
        dbft_round,
        proposal_transactions,
        proposal_results,
        proposal_consensus,
        proposal_evm,
        primary_builds,
        dbft_timer,
        dbft_timeouts,
        block_period,
    } = context;
    match event {
        BeaconEvent::Established { peer_id, version, status, .. } => {
            sidecars.peers.insert(peer_id, status);
            let local = beacon.status();
            let remote_is_ahead = status.head_number().map_or_else(
                || status.total_difficulty() > local.total_difficulty,
                |number| number > local.head_number,
            );
            let network_is_ahead = sidecars.peers.values().any(|peer| {
                peer.head_number().map_or_else(
                    || peer.total_difficulty() > local.total_difficulty,
                    |number| number > local.head_number,
                )
            });
            info!(
                target: "neox::sync",
                %peer_id,
                ?version,
                remote_head = %status.head(),
                remote_number = ?status.head_number(),
                remote_is_ahead,
                "Neo X beacon peer established"
            );
            if network_is_ahead {
                dbft.deactivate();
                *dbft_round = None;
                proposal_transactions.clear();
                primary_builds.clear();
                dbft_timer.disarm();
                debug!(target: "neox::validator", "Disabled dBFT admission while Neo X backfill is active");
                if remote_is_ahead {
                    request_sync_target(engine, status.head()).await;
                }
            } else {
                if dbft_round.is_none() {
                    activate_dbft_round(
                        local.head_number,
                        provider,
                        dbft,
                        chain_spec,
                        signer,
                        dbft_round,
                    );
                    reset_dbft_timer(
                        dbft_round.as_ref(),
                        signer,
                        block_period,
                        dbft_timer,
                        dbft_timeouts,
                    );
                }
            }
        }
        BeaconEvent::NewBlockHashes { peer_id, announcement } => {
            if let Some(best) = announcement.0.iter().max_by_key(|announced| announced.number) {
                debug!(
                    target: "neox::sync",
                    %peer_id,
                    block_number = best.number,
                    block_hash = %best.hash,
                    "Received Neo X block announcement"
                );
                if best.number > beacon.status().head_number {
                    request_sync_target(engine, best.hash).await;
                }
            }
        }
        BeaconEvent::NewBlock { peer_id, packet } => {
            import_propagated_block(peer_id, *packet, beacon.status().head_number, engine).await;
        }
        BeaconEvent::GetTransactions { peer_id, request } => {
            let request_id = request.request_id;
            let transactions = pool.get_pooled_transaction_elements(
                request.message.0,
                GetPooledTransactionLimit::ResponseSizeSoftLimit(TRANSACTION_RESPONSE_SOFT_LIMIT),
            );
            let response = transactions_response(request_id, transactions);
            if !beacon.send(peer_id, BeaconCommand::Transactions(response)) {
                debug!(target: "neox::sync", %peer_id, request_id, "Beacon peer disconnected before transaction response");
            }
        }
        BeaconEvent::Transactions { peer_id, response } => {
            let request_id = response.request_id;
            let count = response.message.0.len();
            let action = proposal_transactions.supply(peer_id, response);
            match (action, dbft_round.as_ref()) {
                (Ok(action), Some(round)) => dispatch_proposal_action(
                    action,
                    round,
                    provider,
                    beacon,
                    proposal_results,
                    proposal_consensus,
                    proposal_evm,
                    chain_spec,
                ),
                (Ok(_), None) => {
                    proposal_transactions.clear();
                    debug!(target: "neox::validator", %peer_id, request_id, count, "Discarded Neo X proposal transactions without an active round");
                }
                (Err(DbftProposalError::UnknownTransactionResponse(_)), _) => {
                    debug!(target: "neox::validator", %peer_id, request_id, count, "Ignored late Neo X proposal transaction response");
                }
                (Err(error), _) => {
                    warn!(target: "neox::validator", %peer_id, request_id, count, %error, "Rejected beacon transaction response for Neo X proposal")
                }
            }
        }
        BeaconEvent::NewBlobsRoot { peer_id, announcement } => {
            sidecars.request_announced(peer_id, announcement.block_hash, provider, beacon);
        }
        BeaconEvent::GetBlobs { peer_id, request } => {
            sidecars.serve_or_forward(peer_id, request, provider, beacon);
        }
        BeaconEvent::Blobs { peer_id, response } => {
            sidecars.import_single(peer_id, response, provider, beacon);
        }
        BeaconEvent::GetBatchBlobs { peer_id, request } => {
            sidecars.serve_batch(peer_id, request, beacon);
        }
        BeaconEvent::BatchBlobs { peer_id, response } => {
            sidecars.import_batch(peer_id, response, provider, beacon);
        }
        BeaconEvent::Violation { peer_id, reason } => {
            warn!(target: "neox::sync", %peer_id, ?reason, "Rejected invalid Neo X beacon peer message");
        }
        BeaconEvent::Disconnected { peer_id, version } => {
            sidecars.peers.remove(&peer_id);
            sidecars.pending.retain(|_, request| request.peer_id() != peer_id);
            let local = beacon.status();
            let network_is_ahead = sidecars.peers.values().any(|peer| {
                peer.head_number().map_or_else(
                    || peer.total_difficulty() > local.total_difficulty,
                    |number| number > local.head_number,
                )
            });
            if !network_is_ahead && dbft_round.is_none() {
                activate_dbft_round(
                    local.head_number,
                    provider,
                    dbft,
                    chain_spec,
                    signer,
                    dbft_round,
                );
                reset_dbft_timer(
                    dbft_round.as_ref(),
                    signer,
                    block_period,
                    dbft_timer,
                    dbft_timeouts,
                );
            }
            debug!(target: "neox::sync", %peer_id, ?version, "Neo X beacon peer disconnected");
        }
    }
}

#[derive(Debug)]
struct SidecarSync {
    store: NeoXSidecarStore,
    peers: HashMap<B512, BeaconStatus>,
    pending: HashMap<u64, PendingSidecarRequest>,
    next_request_id: u64,
}

#[derive(Debug)]
enum PendingSidecarRequest {
    Single {
        peer_id: B512,
        block_hash: B256,
        forwarded_for: Option<(B512, u64)>,
        requested_at: Instant,
    },
    Batch {
        peer_id: B512,
        block_hashes: Vec<B256>,
        requested_at: Instant,
    },
}

impl PendingSidecarRequest {
    const fn peer_id(&self) -> B512 {
        match self {
            Self::Single { peer_id, .. } | Self::Batch { peer_id, .. } => *peer_id,
        }
    }

    const fn requested_at(&self) -> Instant {
        match self {
            Self::Single { requested_at, .. } | Self::Batch { requested_at, .. } => *requested_at,
        }
    }

    fn contains_block(&self, block_hash: B256) -> bool {
        match self {
            Self::Single { block_hash: pending, .. } => *pending == block_hash,
            Self::Batch { block_hashes, .. } => block_hashes.contains(&block_hash),
        }
    }
}

impl SidecarSync {
    fn new(store: NeoXSidecarStore) -> Self {
        info!(target: "neox::sync", path = %store.root().display(), "Neo X finalized sidecar store initialized");
        Self { store, peers: HashMap::new(), pending: HashMap::new(), next_request_id: 1 }
    }

    fn expire_requests(&mut self) {
        self.pending.retain(|request_id, request| {
            let retain = request.requested_at().elapsed() < SIDECAR_REQUEST_TIMEOUT;
            if !retain {
                debug!(target: "neox::sync", request_id, peer_id = %request.peer_id(), "Neo X sidecar request timed out");
            }
            retain
        });
    }

    fn archive_chain<Pool>(
        &mut self,
        chain: &reth_execution_types::Chain<EthPrimitives>,
        pool: &Pool,
        beacon: &BeaconProtocol,
    ) where
        Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        >,
    {
        let retained_floor = chain.tip().number().saturating_sub(SIDECAR_RETAINED_BLOCK_WINDOW);
        let mut missing = Vec::new();

        for recovered in chain.blocks_iter() {
            if recovered.number() < retained_floor {
                continue
            }
            let tx_hashes = blob_transaction_hashes(recovered.body());
            if tx_hashes.is_empty() {
                continue
            }
            let block_hash = recovered.hash();
            match self.store.contains(block_hash) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    warn!(target: "neox::sync", %block_hash, %error, "Failed to inspect Neo X sidecar store");
                    continue
                }
            }

            match pool.get_all_blobs_exact(tx_hashes) {
                Ok(pool_sidecars) => {
                    let sidecars: Vec<_> = pool_sidecars
                        .into_iter()
                        .map(|sidecar| BeaconBlobSidecar::from((*sidecar).clone()))
                        .collect();
                    if let Err(error) = validate_block_sidecars(recovered.body(), &sidecars) {
                        warn!(target: "neox::sync", %block_hash, %error, "Rejected transaction-pool sidecars for canonical Neo X block");
                        missing.push(block_hash);
                        continue
                    }
                    let sidecar_count = sidecars.len();
                    match self.store.insert(block_hash, sidecars) {
                        Ok(()) => {
                            beacon.broadcast(BeaconCommand::NewBlobsRoot(NewBlobsRoot {
                                block_hash,
                            }));
                            info!(target: "neox::sync", %block_hash, sidecar_count, "Archived and announced canonical Neo X sidecars");
                        }
                        Err(error) => {
                            warn!(target: "neox::sync", %block_hash, %error, "Failed to archive canonical Neo X sidecars")
                        }
                    }
                }
                Err(error) => {
                    debug!(target: "neox::sync", %block_hash, %error, "Canonical Neo X sidecars are not available in the transaction pool");
                    missing.push(block_hash);
                }
            }
        }

        let Some(peer_id) = self.choose_peer(None) else {
            if !missing.is_empty() {
                debug!(target: "neox::sync", blocks = missing.len(), "No sidecar-serving Neo X peer is available for canonical backfill");
            }
            return
        };
        for block_hashes in missing.chunks(SIDECAR_BATCH_BLOCK_LIMIT) {
            self.request_batch(peer_id, block_hashes.to_vec(), beacon);
        }
    }

    fn request_announced<Provider>(
        &mut self,
        peer_id: B512,
        block_hash: B256,
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) where
        Provider: BlockReader<Block = Block>,
    {
        debug!(target: "neox::sync", %peer_id, %block_hash, "Received Neo X sidecar announcement");
        match provider.block_by_hash(block_hash) {
            Ok(Some(block)) if !blob_transaction_hashes(&block.body).is_empty() => {
                self.request_single(peer_id, block_hash, 3, None, beacon);
            }
            Ok(Some(_)) => {
                debug!(target: "neox::sync", %peer_id, %block_hash, "Ignored sidecar announcement for block without blob transactions");
            }
            Ok(None) => {
                debug!(target: "neox::sync", %peer_id, %block_hash, "Deferred sidecar announcement until its block is imported");
            }
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to look up announced Neo X blob block");
            }
        }
    }

    fn serve_or_forward<Provider>(
        &mut self,
        peer_id: B512,
        request: GetBlobs,
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) where
        Provider: BlockReader<Block = Block>,
    {
        match self.store.get(request.block_hash) {
            Ok(Some(sidecars)) => {
                let response = Blobs { request_id: request.request_id, sidecars };
                if !beacon.send(peer_id, BeaconCommand::Blobs(response)) {
                    debug!(target: "neox::sync", %peer_id, request_id = request.request_id, "Beacon peer disconnected before blob response");
                }
                return
            }
            Ok(None) => {}
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, request_id = request.request_id, block_hash = %request.block_hash, %error, "Failed to read requested Neo X sidecars");
                return
            }
        }

        let known_blob_block = match provider.block_by_hash(request.block_hash) {
            Ok(Some(block)) => !blob_transaction_hashes(&block.body).is_empty(),
            Ok(None) => false,
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, block_hash = %request.block_hash, %error, "Failed to look up requested Neo X blob block");
                false
            }
        };
        if !known_blob_block || request.ttl <= 1 {
            debug!(target: "neox::sync", %peer_id, request_id = request.request_id, block_hash = %request.block_hash, ttl = request.ttl, "Neo X sidecars unavailable at this node");
            return
        }

        let Some(transfer_peer) = self.choose_peer(Some(peer_id)) else {
            debug!(target: "neox::sync", %peer_id, request_id = request.request_id, "No peer available to forward Neo X blob request");
            return
        };
        self.request_single(
            transfer_peer,
            request.block_hash,
            request.ttl - 1,
            Some((peer_id, request.request_id)),
            beacon,
        );
    }

    fn serve_batch(&self, peer_id: B512, request: GetBatchBlobs, beacon: &BeaconProtocol) {
        let mut blocks = Vec::new();
        let mut estimated_size = 0usize;
        for block_hash in request.block_hashes.into_iter().take(2 * SIDECAR_BATCH_BLOCK_LIMIT) {
            if blocks.len() >= SIDECAR_BATCH_BLOCK_LIMIT ||
                estimated_size >= SIDECAR_RESPONSE_SOFT_LIMIT
            {
                break
            }
            let sidecars = match self.store.get(block_hash) {
                Ok(Some(sidecars)) => sidecars,
                Ok(None) => break,
                Err(error) => {
                    warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to read batched Neo X sidecars");
                    break
                }
            };
            let sidecar_size = sidecars.iter().map(BeaconBlobSidecar::size).sum::<usize>();
            if !blocks.is_empty() &&
                estimated_size.saturating_add(sidecar_size) > SIDECAR_RESPONSE_SOFT_LIMIT
            {
                break
            }
            estimated_size = estimated_size.saturating_add(sidecar_size);
            blocks.push(sidecars);
        }
        let response = BatchBlobs { request_id: request.request_id, blocks };
        if !beacon.send(peer_id, BeaconCommand::BatchBlobs(response)) {
            debug!(target: "neox::sync", %peer_id, request_id = request.request_id, "Beacon peer disconnected before batch blob response");
        }
    }

    fn import_single<Provider>(
        &mut self,
        peer_id: B512,
        response: Blobs,
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) where
        Provider: BlockReader<Block = Block>,
    {
        let Some(pending) = self.pending.get(&response.request_id) else {
            debug!(target: "neox::sync", %peer_id, request_id = response.request_id, "Ignored unsolicited Neo X blob response");
            return
        };
        if pending.peer_id() != peer_id {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected Neo X blob response from the wrong peer");
            return
        }
        let Some(PendingSidecarRequest::Single { block_hash, forwarded_for, .. }) =
            self.pending.remove(&response.request_id)
        else {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected single blob response for a batch request");
            return
        };

        let sidecars = response.sidecars;
        if !self.validate_and_store(peer_id, block_hash, &sidecars, provider, beacon) {
            return
        }
        if let Some((requester, original_request_id)) = forwarded_for {
            let forwarded = Blobs { request_id: original_request_id, sidecars };
            if !beacon.send(requester, BeaconCommand::Blobs(forwarded)) {
                debug!(target: "neox::sync", %requester, request_id = original_request_id, "Forwarding requester disconnected before Neo X blob response");
            }
        }
    }

    fn import_batch<Provider>(
        &mut self,
        peer_id: B512,
        response: BatchBlobs,
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) where
        Provider: BlockReader<Block = Block>,
    {
        let Some(pending) = self.pending.get(&response.request_id) else {
            debug!(target: "neox::sync", %peer_id, request_id = response.request_id, "Ignored unsolicited Neo X batch blob response");
            return
        };
        if pending.peer_id() != peer_id {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected Neo X batch blob response from the wrong peer");
            return
        }
        let Some(PendingSidecarRequest::Batch { block_hashes, .. }) =
            self.pending.remove(&response.request_id)
        else {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected batch blob response for a single request");
            return
        };
        if response.blocks.len() > block_hashes.len() {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, expected = block_hashes.len(), received = response.blocks.len(), "Rejected oversized Neo X batch blob response");
            return
        }

        let received = response.blocks.len();
        for (block_hash, sidecars) in block_hashes.iter().copied().zip(response.blocks) {
            self.validate_and_store(peer_id, block_hash, &sidecars, provider, beacon);
        }
        if received < block_hashes.len() {
            debug!(target: "neox::sync", %peer_id, request_id = response.request_id, received, requested = block_hashes.len(), "Neo X peer returned a partial batch blob response");
        }
    }

    fn validate_and_store<Provider>(
        &self,
        peer_id: B512,
        block_hash: B256,
        sidecars: &[BeaconBlobSidecar],
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) -> bool
    where
        Provider: BlockReader<Block = Block>,
    {
        let block = match provider.block_by_hash(block_hash) {
            Ok(Some(block)) => block,
            Ok(None) => {
                debug!(target: "neox::sync", %peer_id, %block_hash, "Discarded Neo X sidecars for an unknown block");
                return false
            }
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to load block for Neo X sidecar validation");
                return false
            }
        };
        if let Err(error) = validate_block_sidecars(&block.body, sidecars) {
            warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Rejected invalid Neo X sidecars");
            return false
        }
        if let Err(error) = self.store.insert(block_hash, sidecars.to_vec()) {
            warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to persist validated Neo X sidecars");
            return false
        }
        beacon.broadcast(BeaconCommand::NewBlobsRoot(NewBlobsRoot { block_hash }));
        info!(target: "neox::sync", %peer_id, %block_hash, sidecars = sidecars.len(), "Validated, archived, and announced Neo X sidecars");
        true
    }

    fn request_single(
        &mut self,
        peer_id: B512,
        block_hash: B256,
        ttl: u8,
        forwarded_for: Option<(B512, u64)>,
        beacon: &BeaconProtocol,
    ) {
        if self.pending.values().any(|request| request.contains_block(block_hash)) {
            return
        }
        match self.store.contains(block_hash) {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => {
                warn!(target: "neox::sync", %block_hash, %error, "Failed to inspect Neo X sidecar store before requesting blobs");
                return
            }
        }
        let request_id = self.allocate_request_id();
        let request = GetBlobs { request_id, block_hash, ttl };
        if beacon.send(peer_id, BeaconCommand::GetBlobs(request)) {
            self.pending.insert(
                request_id,
                PendingSidecarRequest::Single {
                    peer_id,
                    block_hash,
                    forwarded_for,
                    requested_at: Instant::now(),
                },
            );
            debug!(target: "neox::sync", %peer_id, request_id, %block_hash, ttl, "Requested Neo X sidecars");
        }
    }

    fn request_batch(
        &mut self,
        peer_id: B512,
        mut block_hashes: Vec<B256>,
        beacon: &BeaconProtocol,
    ) {
        block_hashes.retain(|hash| {
            !self.pending.values().any(|request| request.contains_block(*hash)) &&
                !matches!(self.store.contains(*hash), Ok(true))
        });
        if block_hashes.is_empty() {
            return
        }
        block_hashes.truncate(SIDECAR_BATCH_BLOCK_LIMIT);
        let request_id = self.allocate_request_id();
        let request = GetBatchBlobs { request_id, block_hashes: block_hashes.clone() };
        if beacon.send(peer_id, BeaconCommand::GetBatchBlobs(request)) {
            self.pending.insert(
                request_id,
                PendingSidecarRequest::Batch {
                    peer_id,
                    block_hashes,
                    requested_at: Instant::now(),
                },
            );
            debug!(target: "neox::sync", %peer_id, request_id, "Requested batch Neo X sidecars");
        }
    }

    fn choose_peer(&self, exclude: Option<B512>) -> Option<B512> {
        self.peers
            .iter()
            .find(|(peer_id, status)| Some(**peer_id) != exclude && status.blob_sync())
            .map(|(peer_id, _)| *peer_id)
            .or_else(|| self.peers.keys().find(|peer_id| Some(**peer_id) != exclude).copied())
    }

    fn allocate_request_id(&mut self) -> u64 {
        loop {
            let request_id = self.next_request_id;
            self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
            if !self.pending.contains_key(&request_id) {
                return request_id
            }
        }
    }
}

fn blob_transaction_hashes(body: &reth_ethereum_primitives::BlockBody) -> Vec<B256> {
    body.transactions
        .iter()
        .filter(|transaction| transaction_blob_hashes(transaction).is_some())
        .map(|transaction| *transaction.tx_hash())
        .collect()
}

fn transaction_blob_hashes(transaction: &TransactionSigned) -> Option<&[B256]> {
    let hashes = &transaction.as_eip4844()?.tx().blob_versioned_hashes;
    (!hashes.is_empty()).then_some(hashes)
}

fn validate_block_sidecars(
    body: &reth_ethereum_primitives::BlockBody,
    sidecars: &[BeaconBlobSidecar],
) -> Result<(), String> {
    let blob_hashes: Vec<_> =
        body.transactions.iter().filter_map(transaction_blob_hashes).collect();
    if blob_hashes.is_empty() {
        return Err("block has no blob transactions".to_string())
    }
    if blob_hashes.len() != sidecars.len() {
        return Err(format!(
            "sidecar count mismatch: expected {}, received {}",
            blob_hashes.len(),
            sidecars.len()
        ))
    }
    for (transaction_index, (hashes, sidecar)) in blob_hashes.into_iter().zip(sidecars).enumerate()
    {
        sidecar
            .clone()
            .into_variant()
            .validate(hashes, EnvKzgSettings::Default.get())
            .map_err(|error| format!("blob transaction {transaction_index}: {error}"))?;
    }
    Ok(())
}

/// Whether a propagated block should be imported: under dBFT instant finality it must advance the
/// canonical head. Same-or-lower-height blocks are competing witnesses of already finalized
/// heights.
const fn propagated_block_extends_head(number: u64, canonical_head: u64) -> bool {
    number > canonical_head
}

async fn import_propagated_block(
    peer_id: alloy_primitives::B512,
    packet: NewBlockPacket,
    canonical_head: u64,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
) {
    let number = packet.block.header.number;
    // Neo X dBFT finalizes each block on commit, so a propagated block can only extend the chain.
    // A competing block at or below the canonical head is a different honest witness of an already
    // finalized height; adopting it would reorg the finalized tip and, when several validators each
    // propagate their own witness, trap the network in an endless same-height reorg loop that never
    // reaches the next height. Ignore anything that does not advance the head.
    if !propagated_block_extends_head(number, canonical_head) {
        debug!(
            target: "neox::sync",
            %peer_id,
            block_number = number,
            canonical_head,
            "Ignored propagated Neo X block at or below the finalized head"
        );
        return
    }
    let difficulty = packet.block.header.difficulty;
    if (difficulty != U256::from(1) && difficulty != U256::from(2)) ||
        packet.total_difficulty < difficulty
    {
        warn!(
            target: "neox::sync",
            %peer_id,
            block_number = number,
            total_difficulty = %packet.total_difficulty,
            difficulty = %difficulty,
            "Rejected Neo X block with invalid difficulty metadata"
        );
        return
    }

    let block: SealedBlock<_> = packet.block.seal_slow();
    let hash = block.hash();
    let payload = EthPayloadTypes::block_to_payload(block, None);
    match engine.new_payload(payload).await {
        Ok(status) if status.is_valid() => {
            match engine.fork_choice_updated(ForkchoiceState::same_hash(hash), None).await {
                Ok(updated) if updated.payload_status.is_valid() => info!(
                    target: "neox::sync",
                    %peer_id,
                    block_number = number,
                    block_hash = %hash,
                    "Validated and finalized propagated Neo X block"
                ),
                Ok(updated) => {
                    warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, status = %updated.payload_status, "Neo X forkchoice did not accept propagated block")
                }
                Err(error) => {
                    warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, %error, "Neo X forkchoice update failed")
                }
            }
        }
        Ok(status) if status.is_syncing() => {
            debug!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, "Neo X block parent unknown; requesting backfill");
            request_sync_target(engine, hash).await;
        }
        Ok(status) => {
            warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, status = %status, "Rejected propagated Neo X payload")
        }
        Err(error) => {
            warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, %error, "Neo X payload validation failed")
        }
    }
}

async fn request_sync_target(engine: &ConsensusEngineHandle<EthEngineTypes>, head: B256) {
    let state = ForkchoiceState {
        head_block_hash: head,
        safe_block_hash: B256::ZERO,
        finalized_block_hash: B256::ZERO,
    };
    match engine.fork_choice_updated(state, None).await {
        Ok(updated) => {
            debug!(target: "neox::sync", block_hash = %head, status = %updated.payload_status, "Submitted Neo X backfill target")
        }
        Err(error) => {
            warn!(target: "neox::sync", block_hash = %head, %error, "Failed to submit Neo X backfill target")
        }
    }
}

fn chain_difficulty(chain: &reth_execution_types::Chain<EthPrimitives>) -> U256 {
    chain.blocks_iter().fold(U256::ZERO, |total, block| total + block.difficulty)
}

#[cfg(test)]
mod tests {
    use super::{
        change_view_timeout, is_stale_dbft_transition, post_proposal_timeout,
        propagated_block_extends_head, proposal_rejection_reason, publish_local_change_view,
        recovery_response_allowed, round_timeout, AntiMevReconstructionAttempt, DbftTimerState,
    };
    use crate::{DbftProposalError, DbftRoundState, DbftSigner, DbftStateError};
    use alloy_primitives::B256;
    use reth_neox_network::{
        DbftChangeViewReason, DbftDecodedPayload, DbftMessageType, DbftProtocol,
    };
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn only_prior_height_dbft_transitions_are_stale() {
        assert!(is_stale_dbft_transition(&DbftStateError::WrongHeight {
            expected: 43,
            start: 0,
            end: 42,
        }));
        assert!(!is_stale_dbft_transition(&DbftStateError::WrongHeight {
            expected: 43,
            start: 0,
            end: 44,
        }));
        assert!(!is_stale_dbft_transition(&DbftStateError::WrongView { expected: 1, actual: 2 }));
    }

    #[test]
    fn dbft_round_timeouts_match_geth_roles() {
        let period = Duration::from_secs(5);
        assert_eq!(round_timeout(period, 0, true), Duration::from_secs(5));
        assert_eq!(round_timeout(period, 0, false), Duration::from_secs(10));
        assert_eq!(round_timeout(period, 1, true), Duration::ZERO);
        assert_eq!(round_timeout(period, 1, false), Duration::from_secs(20));
    }

    #[test]
    fn dbft_post_proposal_timeout_matches_geth() {
        let period = Duration::from_secs(5);
        assert_eq!(post_proposal_timeout(period, 0), Duration::from_secs(5));
        assert_eq!(post_proposal_timeout(period, 1), Duration::from_secs(20));
        assert_eq!(post_proposal_timeout(period, 2), Duration::from_secs(40));
    }

    #[test]
    fn dbft_change_view_timeout_uses_new_view_exponent() {
        let period = Duration::from_secs(5);
        assert_eq!(change_view_timeout(period, 1), Duration::from_secs(20));
        assert_eq!(change_view_timeout(period, 2), Duration::from_secs(40));
    }

    #[test]
    fn recovery_request_selects_the_next_f_plus_one_validators() {
        let responders = (0..7)
            .filter(|local| recovery_response_allowed(7, 0, *local, false))
            .collect::<Vec<_>>();
        assert_eq!(responders, vec![1, 2, 3]);
        assert!(recovery_response_allowed(7, 0, 6, true));
    }

    #[test]
    fn proposal_failures_match_geth_change_view_reasons() {
        assert_eq!(
            proposal_rejection_reason(&DbftProposalError::Header("invalid parent".to_string())),
            DbftChangeViewReason::BlockRejectedByPolicy
        );
        assert_eq!(
            proposal_rejection_reason(&DbftProposalError::Execution(
                "invalid transaction".to_string()
            )),
            DbftChangeViewReason::TransactionInvalid
        );
    }

    #[test]
    fn retries_antimev_reconstruction_only_after_new_contributions() {
        let mut attempt = AntiMevReconstructionAttempt::default();
        assert!(attempt.begin(5));
        assert!(!attempt.begin(6));
        attempt.finish();
        assert!(!attempt.begin(5));
        assert!(attempt.begin(6));
    }

    #[tokio::test]
    async fn publishes_and_records_explicit_change_view_reason() {
        let mut signers = (1_u8..=7)
            .map(|byte| DbftSigner::from_secret(&B256::repeat_byte(byte).0).unwrap())
            .collect::<Vec<_>>();
        signers.sort_unstable_by_key(DbftSigner::account);
        let accounts = signers.iter().map(DbftSigner::account).collect::<Vec<_>>();
        let mut round = DbftRoundState::new(42, accounts.clone(), false).unwrap();
        let (dbft, _events) = DbftProtocol::new(42);
        dbft.activate(42, accounts).unwrap();
        let (timeouts, _timeout_rx) = mpsc::unbounded_channel();
        let mut timer = DbftTimerState::default();

        let outcome = publish_local_change_view(
            &mut round,
            Some(&signers[0]),
            &dbft,
            DbftChangeViewReason::TransactionInvalid,
            Duration::from_secs(5),
            &mut timer,
            &timeouts,
        );

        assert!(outcome.requested);
        assert!(!outcome.changed_view);
        let message = round.message(0, DbftMessageType::ChangeView, 0).unwrap();
        let DbftDecodedPayload::ChangeView(change_view) =
            message.consensus_data().unwrap().decoded_payload().unwrap()
        else {
            panic!("expected ChangeView")
        };
        assert_eq!(change_view.reason().unwrap(), DbftChangeViewReason::TransactionInvalid);
    }

    #[test]
    fn only_head_extending_propagated_blocks_are_imported() {
        // Under dBFT instant finality a propagated block must advance the head; competing
        // same-or-lower-height witnesses are ignored to avoid an endless finalized-height reorg
        // loop.
        assert!(propagated_block_extends_head(11, 10));
        assert!(!propagated_block_extends_head(10, 10));
        assert!(!propagated_block_extends_head(9, 10));
        assert!(!propagated_block_extends_head(0, 0));
    }
}
