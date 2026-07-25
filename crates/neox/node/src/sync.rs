//! Neo X beacon-to-engine synchronization and canonical block propagation.

mod anti_mev;
mod future_messages;
mod proposal_recovery;
mod sidecar;
mod timer;

use anti_mev::{AntiMevReconstructionResult, AntiMevReconstructor};
use future_messages::{CachedDbftMessage, CachedMessageKind, FutureDbftMessages};
use proposal_recovery::{ProposalRecovery, ProposalVerificationResult};
use sidecar::{validate_block_sidecars, SidecarSync};
use timer::{DbftTimeout, DbftTimer};

use crate::{
    build_primary_proposal, metrics::NeoXSyncMetrics, read_dkg_state,
    read_governance_validator_set, AntiMevTransactionDecision, DbftProposalError,
    DbftRoundProgress, DbftRoundState, DbftSigner, DbftStateError, DkgShareEpoch, EnvelopeDkgEpoch,
    PrimaryProposal, PrimaryProposalAttributes, PrimaryProposalError, VerifiedProposal,
};
use alloy_consensus::Header;
use alloy_primitives::{bytes::BytesMut, B256, B512, U256};
use alloy_rlp::Encodable;
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
    block_hash_announcement, transactions_response, BeaconCommand, BeaconEvent,
    BeaconEventReceiver, BeaconLocalStatus, BeaconMessageId, BeaconProtocol, BeaconStatus,
    DbftChangeView, DbftChangeViewReason, DbftDecodedPayload, DbftEvent, DbftEventReceiver,
    DbftMessage, DbftMessageType, DbftPreCommit, DbftPrepareResponse, DbftProtocol,
    DbftRecoveryRequest, NeoXSidecarStore, NewBlobsRoot, NewBlockPacket,
};
use reth_node_api::PayloadTypes;
use reth_primitives_traits::{AlloyBlockHeader, Block as _, SealedBlock};
use reth_provider::{BlockReader, HeaderProvider, StateProviderBox, StateProviderFactory};
use reth_transaction_pool::{GetPooledTransactionLimit, PoolTransaction, TransactionPool};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const TRANSACTION_RESPONSE_SOFT_LIMIT: usize = 5 * 1024 * 1024;
const PROPAGATED_BLOCK_QUEUE_CAPACITY: usize = 2;
const CANONICAL_HEADER_BATCH_SIZE: u64 = 4_096;
const CANONICAL_SNAPSHOT_ATTEMPTS: usize = 4;
const DESCENDANT_SYNC_TARGET_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const DESCENDANT_SYNC_TARGET_MAX_REQUESTS: u16 = 120;

#[derive(Debug)]
struct PropagatedBlockJob {
    peer_id: alloy_primitives::B512,
    packet: NewBlockPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropagatedBlockDisposition {
    DirectChild,
    Gap,
    CompetingFinalized,
}

fn propagated_block_disposition(
    header: &Header,
    canonical: BeaconLocalStatus,
) -> PropagatedBlockDisposition {
    if header.number <= canonical.head_number {
        return PropagatedBlockDisposition::CompetingFinalized
    }
    if canonical.head_number.checked_add(1) != Some(header.number) {
        return PropagatedBlockDisposition::Gap
    }
    if header.parent_hash == canonical.head {
        PropagatedBlockDisposition::DirectChild
    } else {
        PropagatedBlockDisposition::CompetingFinalized
    }
}

fn spawn_propagated_block_importer(
    engine: ConsensusEngineHandle<EthEngineTypes>,
    beacon: BeaconProtocol,
) -> mpsc::Sender<PropagatedBlockJob> {
    let (sender, mut receiver) =
        mpsc::channel::<PropagatedBlockJob>(PROPAGATED_BLOCK_QUEUE_CAPACITY);
    tokio::spawn(async move {
        while let Some(job) = receiver.recv().await {
            import_propagated_block(job.peer_id, job.packet, beacon.status(), &engine).await;
        }
    });
    sender
}

fn enqueue_propagated_block(
    sender: &mpsc::Sender<PropagatedBlockJob>,
    peer_id: alloy_primitives::B512,
    packet: NewBlockPacket,
) -> bool {
    sender.try_send(PropagatedBlockJob { peer_id, packet }).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescendantSyncTarget {
    hash: B256,
    number: u64,
}

fn propagated_block_backfill_target(
    packet: &NewBlockPacket,
    canonical: BeaconLocalStatus,
) -> Option<DescendantSyncTarget> {
    if propagated_block_disposition(&packet.block.header, canonical) !=
        PropagatedBlockDisposition::Gap
    {
        return None
    }
    let difficulty = packet.block.header.difficulty;
    if (difficulty != U256::from(1) && difficulty != U256::from(2)) ||
        packet.total_difficulty < difficulty
    {
        return None
    }
    Some(DescendantSyncTarget {
        hash: packet.block.header.hash_slow(),
        number: packet.block.header.number,
    })
}

fn peer_status_backfill_target(
    remote: BeaconStatus,
    local: BeaconLocalStatus,
) -> Option<DescendantSyncTarget> {
    let number = remote.head_number()?;
    (number > local.head_number).then_some(DescendantSyncTarget { hash: remote.head(), number })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescendantSyncRequest {
    request_id: u64,
    anchor: DescendantSyncAnchor,
    target: DescendantSyncTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescendantSyncAnchor {
    hash: B256,
    number: u64,
}

impl From<BeaconLocalStatus> for DescendantSyncAnchor {
    fn from(status: BeaconLocalStatus) -> Self {
        Self { hash: status.head, number: status.head_number }
    }
}

#[derive(Debug)]
struct PendingDescendantSyncTarget {
    target: DescendantSyncTarget,
    sources: HashSet<B512>,
    requested: bool,
}

#[derive(Debug, Default)]
struct DescendantSyncTargets {
    anchor: Option<DescendantSyncAnchor>,
    claims: HashMap<B512, DescendantSyncTarget>,
    pending: VecDeque<PendingDescendantSyncTarget>,
    requested_sources: HashSet<B512>,
    terminal_hashes: HashSet<B256>,
    requests: u16,
    retry_at: Option<Instant>,
    next_request_id: u64,
    in_flight: Option<DescendantSyncRequest>,
}

impl DescendantSyncTargets {
    fn observe(
        &mut self,
        source: B512,
        target: DescendantSyncTarget,
        canonical: BeaconLocalStatus,
        now: Instant,
    ) -> Option<DescendantSyncRequest> {
        self.reconcile(canonical);
        if target.number <= canonical.head_number || self.terminal_hashes.contains(&target.hash) {
            self.remove_source_claim(source);
            return None
        }

        self.update_source_claim(source, target);
        self.request_if_due(canonical, now)
    }

    fn retry(
        &mut self,
        canonical: BeaconLocalStatus,
        now: Instant,
    ) -> Option<DescendantSyncRequest> {
        self.reconcile(canonical);
        self.request_if_due(canonical, now)
    }

    fn reconcile(&mut self, canonical: BeaconLocalStatus) {
        let anchor = DescendantSyncAnchor::from(canonical);
        let anchor_changed = self.anchor != Some(anchor);
        self.anchor = Some(anchor);
        self.claims.retain(|_, target| target.number > canonical.head_number);

        if anchor_changed {
            // Only authoritative canonical progress replenishes the shared budget. Peer target
            // rotation under an unchanged anchor cannot reset requests or the cooldown.
            self.requests = 0;
            self.retry_at = None;
            self.requested_sources.clear();
            self.terminal_hashes.clear();
            self.rebuild_pending();
        } else {
            self.pending.retain_mut(|pending| {
                pending.sources.retain(|source| {
                    self.claims.get(source).is_some_and(|target| target.hash == pending.target.hash)
                });
                !pending.sources.is_empty()
            });
        }
    }

    fn invalidate(&mut self, hash: B256) {
        self.terminal_hashes.insert(hash);
        self.claims.retain(|_, claimed| claimed.hash != hash);
        self.pending.retain(|pending| pending.target.hash != hash);
    }

    fn disconnect(&mut self, source: B512) {
        self.remove_source_claim(source);
        self.requested_sources.remove(&source);
    }

    fn complete(
        &mut self,
        request: DescendantSyncRequest,
        submission: DescendantSyncTargetSubmission,
        canonical: BeaconLocalStatus,
        now: Instant,
    ) -> Option<DescendantSyncRequest> {
        if self.in_flight != Some(request) {
            return None
        }
        self.in_flight = None;
        self.reconcile(canonical);
        if self.anchor != Some(request.anchor) {
            return self.request_if_due(canonical, now)
        }
        if matches!(
            submission,
            DescendantSyncTargetSubmission::Valid | DescendantSyncTargetSubmission::Invalid
        ) {
            // FCU identity is the block hash. The announced number is an untrusted scheduling hint
            // and must not let the same terminal target survive under another tuple.
            self.invalidate(request.target.hash);
        }
        self.request_if_due(canonical, now)
    }

    fn cancel_submission(&mut self, request: DescendantSyncRequest) {
        if self.in_flight == Some(request) {
            self.in_flight = None;
        }
    }

    fn request_if_due(
        &mut self,
        canonical: BeaconLocalStatus,
        now: Instant,
    ) -> Option<DescendantSyncRequest> {
        if self.in_flight.is_some() {
            return None
        }
        if self.requests >= DESCENDANT_SYNC_TARGET_MAX_REQUESTS {
            self.pending.clear();
            return None
        }
        if self.retry_at.is_some_and(|retry_at| now < retry_at) || self.pending.is_empty() {
            return None
        }

        // Give every newly observed source one request before retrying an already-attempted hint.
        // Rotating a source to another hash does not restore this priority.
        let index = self
            .pending
            .iter()
            .position(|pending| {
                pending.sources.iter().any(|source| !self.requested_sources.contains(source))
            })
            .unwrap_or_default();
        let mut pending = self.pending.remove(index).expect("nonempty descendant target queue");
        pending.requested = true;
        self.requested_sources.extend(pending.sources.iter().copied());
        let target = pending.target;
        self.pending.push_back(pending);

        self.requests += 1;
        self.retry_at = Some(now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL);
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        let request = DescendantSyncRequest {
            request_id: self.next_request_id,
            anchor: DescendantSyncAnchor::from(canonical),
            target,
        };
        self.in_flight = Some(request);
        if self.requests >= DESCENDANT_SYNC_TARGET_MAX_REQUESTS {
            // Keep bounded connected-source claims so canonical progress can rebuild the queue,
            // but retire every exhausted schedulable hint under this anchor.
            self.pending.clear();
        }
        Some(request)
    }

    fn update_source_claim(&mut self, source: B512, target: DescendantSyncTarget) {
        if self.claims.get(&source) == Some(&target) {
            return
        }
        self.remove_source_from_pending(source);
        self.claims.insert(source, target);
        if self.requests >= DESCENDANT_SYNC_TARGET_MAX_REQUESTS {
            return
        }
        if let Some(pending) =
            self.pending.iter_mut().find(|pending| pending.target.hash == target.hash)
        {
            pending.sources.insert(source);
            if pending.requested {
                self.requested_sources.insert(source);
            }
        } else {
            self.pending.push_back(PendingDescendantSyncTarget {
                target,
                sources: HashSet::from([source]),
                requested: false,
            });
        }
    }

    fn remove_source_claim(&mut self, source: B512) {
        self.claims.remove(&source);
        self.remove_source_from_pending(source);
    }

    fn remove_source_from_pending(&mut self, source: B512) {
        for pending in &mut self.pending {
            pending.sources.remove(&source);
        }
        self.pending.retain(|pending| !pending.sources.is_empty());
    }

    fn rebuild_pending(&mut self) {
        self.pending.clear();
        for (source, target) in &self.claims {
            if let Some(pending) =
                self.pending.iter_mut().find(|pending| pending.target.hash == target.hash)
            {
                pending.sources.insert(*source);
            } else {
                self.pending.push_back(PendingDescendantSyncTarget {
                    target: *target,
                    sources: HashSet::from([*source]),
                    requested: false,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DescendantSyncResult {
    request: DescendantSyncRequest,
    submission: DescendantSyncTargetSubmission,
}

fn spawn_descendant_sync_target_worker(
    engine: ConsensusEngineHandle<EthEngineTypes>,
) -> (mpsc::Sender<DescendantSyncRequest>, mpsc::Receiver<DescendantSyncResult>) {
    let (requests_tx, mut requests_rx) = mpsc::channel::<DescendantSyncRequest>(1);
    let (results_tx, results_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        while let Some(request) = requests_rx.recv().await {
            // Await in the dedicated worker so the central sync select stays responsive while a
            // stalled Engine can retain at most one descendant FCU.
            let submission = request_sync_target(&engine, request.target.hash).await;
            if results_tx.send(DescendantSyncResult { request, submission }).await.is_err() {
                return
            }
        }
    });
    (requests_tx, results_rx)
}

/// Runs the bridge between Neo X `beacon/1,2`, Reth's Engine Tree, and the canonical chain.
///
/// Neo X Geth announces finalized dBFT blocks over `beacon`, while historical bodies and state are
/// still downloaded through the standard `eth`/`snap` protocols. Unknown beacon heads are sent to
/// the Engine Tree as sync targets; direct-child propagated blocks are executed and validated
/// before they can become canonical.
#[derive(Debug)]
pub struct BeaconSyncContext<Pool, Provider> {
    /// Validated events emitted by all negotiated beacon connections.
    pub events: BeaconEventReceiver,
    /// Cryptographically validated events emitted by `dbft/0` connections.
    pub dbft_events: DbftEventReceiver,
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
    let propagated_blocks = spawn_propagated_block_importer(engine.clone(), beacon.clone());
    let (descendant_sync_requests, mut descendant_sync_results) =
        spawn_descendant_sync_target_worker(engine.clone());
    let committed_sidecar_store = sidecar_store.clone();
    let mut sidecars = SidecarSync::new(sidecar_store);
    let mut dbft_round = None;
    let proposal_evm = NeoXEvmConfig::new(Arc::clone(&chain_spec));
    let (mut proposal_recovery, mut proposal_results_rx) = ProposalRecovery::channel(
        provider.clone(),
        beacon.clone(),
        NeoXConsensus::new(Arc::clone(&chain_spec)),
        proposal_evm.clone(),
        Arc::clone(&chain_spec),
    );
    let (primary_results_tx, mut primary_results_rx) = mpsc::unbounded_channel();
    let (mut anti_mev, mut reconstruction_results_rx) =
        AntiMevReconstructor::channel(provider.clone(), proposal_evm.clone());
    let block_period = Duration::from_secs(chain_spec.neox.dbft.period);
    let (mut dbft_timer, mut dbft_timeouts_rx) = DbftTimer::channel(block_period);
    let mut verified_proposals = HashMap::new();
    let mut primary_builds = HashSet::new();
    let mut future_messages = FutureDbftMessages::default();
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let metrics = NeoXSyncMetrics::default();
    let mut descendant_sync_targets = DescendantSyncTargets::default();
    let seeded_head = beacon.status();
    let seeded_total_difficulty_is_trusted =
        seeded_head.head_number == 0 || !seeded_head.total_difficulty.is_zero();
    let initial_head = loop {
        // The standard Neo X network builder establishes a verified non-zero TD checkpoint before
        // starting peers. Retain the zero-TD fallback for direct BeaconSyncContext consumers.
        match authoritative_canonical_status(
            &provider,
            seeded_head,
            &chain_spec,
            seeded_total_difficulty_is_trusted,
        ) {
            Ok(status) => break status,
            Err(error) => {
                warn!(target: "neox::sync", %error, "Failed to resolve authoritative Neo X head at startup; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };
    beacon.update_status(initial_head);
    dbft.update_height(initial_head.head_number);
    metrics.canonical_height.set(initial_head.head_number as f64);
    metrics.beacon_peers.set(beacon.peer_count() as f64);
    metrics.dbft_peers.set(dbft.peer_count() as f64);
    activate_dbft_round(
        initial_head.head_number,
        initial_head.head,
        &provider,
        &dbft,
        &chain_spec,
        signer.as_ref(),
        &mut dbft_round,
    );
    dbft_timer.reset(dbft_round.as_ref(), signer.as_ref());
    // Geth's one-time DBFT.Start call asks an initial primary to propose immediately. Later
    // canonical-height resets are timer driven.
    maybe_schedule_primary_proposal(PrimaryProposalScheduleContext {
        round: dbft_round.as_ref(),
        signer: signer.as_ref(),
        pool: &pool,
        provider: &provider,
        proposal_evm: &proposal_evm,
        chain_spec: &chain_spec,
        results: &primary_results_tx,
        builds: &mut primary_builds,
    });
    loop {
        // A round that advances its height or view can accept messages that were cached while it
        // could not, so the height and view before the iteration decide whether the cache is
        // replayed after it. The reference client replays from inside every round initialization,
        // before it arms that round's timer; here the round advances from several handlers, and
        // comparing the round afterwards covers all of them without threading a replay through
        // each. The timer is therefore already armed when the replay runs, so a replay that
        // commits or changes view re-arms it. That only ever shortens the wait, because the
        // timeout a replay arms is at most the one the round already had.
        let round_epoch = dbft_round.as_ref().map(|round| (round.height(), round.current_view()));
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    warn!(target: "neox::sync", "Neo X beacon event channel closed");
                    return
                };
                metrics.beacon_events_total.increment(1);
                handle_beacon_event(event, BeaconEventContext {
                    beacon: &beacon,
                    pool: &pool,
                    provider: &provider,
                    sidecars: &mut sidecars,
                    dbft: &dbft,
                    chain_spec: &chain_spec,
                    signer: signer.as_ref(),
                    dbft_round: &mut dbft_round,
                    proposal_recovery: &mut proposal_recovery,
                    dbft_timer: &mut dbft_timer,
                    propagated_blocks: &propagated_blocks,
                    descendant_sync_targets: &mut descendant_sync_targets,
                    descendant_sync_requests: &descendant_sync_requests,
                });
                metrics.beacon_peers.set(beacon.peer_count() as f64);
            }
            result = descendant_sync_results.recv() => {
                let Some(result) = result else {
                    warn!(target: "neox::sync", "Neo X descendant sync target worker stopped");
                    return
                };
                if let Some(request) = descendant_sync_targets.complete(
                    result.request,
                    result.submission,
                    beacon.status(),
                    Instant::now(),
                ) {
                    submit_descendant_sync_request(
                        &descendant_sync_requests,
                        &mut descendant_sync_targets,
                        request,
                    );
                }
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
                    proposal_recovery: &mut proposal_recovery,
                    proposal_evm: &proposal_evm,
                    chain_spec: &chain_spec,
                    signer: signer.as_ref(),
                    dbft: &dbft,
                    verified_proposals: &mut verified_proposals,
                    engine: &engine,
                    anti_mev: &mut anti_mev,
                    primary_results: &primary_results_tx,
                    primary_builds: &mut primary_builds,
                    dbft_timer: &mut dbft_timer,
                    sidecar_store: &committed_sidecar_store,
                    future_messages: &mut future_messages,
                    metrics: &metrics,
                });
                metrics.dbft_peers.set(dbft.peer_count() as f64);
            }
            timeout = dbft_timeouts_rx.recv() => {
                let Some(timeout) = timeout else {
                    warn!(target: "neox::validator", "Neo X dBFT timeout channel closed");
                    return
                };
                if handle_dbft_timeout(timeout, DbftTimeoutContext {
                    round: dbft_round.as_mut(),
                    signer: signer.as_ref(),
                    dbft: &dbft,
                    proposal_recovery: &mut proposal_recovery,
                    timer: &mut dbft_timer,
                }) {
                    proposal_recovery.clear();
                }
                maybe_schedule_primary_proposal(PrimaryProposalScheduleContext {
                    round: dbft_round.as_ref(),
                    signer: signer.as_ref(),
                    pool: &pool,
                    provider: &provider,
                    proposal_evm: &proposal_evm,
                    chain_spec: &chain_spec,
                    results: &primary_results_tx,
                    builds: &mut primary_builds,
                });
            }
            _ = maintenance.tick() => {
                sidecars.expire_requests(&beacon);
                proposal_recovery.expire_requests(dbft_round.as_ref());
                let local = beacon.status();
                match canonical_head_matches_status(&provider, local) {
                    Ok(true) => {}
                    Ok(false) => match authoritative_canonical_status(&provider, local, &chain_spec, true) {
                        Ok(status) => {
                            proposal_recovery.clear();
                            verified_proposals.clear();
                            anti_mev.clear();
                            primary_builds.clear();
                            metrics.canonical_height.set(status.head_number as f64);
                            metrics.canonical_updates_total.increment(1);
                            dbft.update_height(status.head_number);
                            beacon.update_status(status);
                            descendant_sync_targets.reconcile(status);
                            activate_dbft_round(
                                status.head_number,
                                status.head,
                                &provider,
                                &dbft,
                                &chain_spec,
                                signer.as_ref(),
                                &mut dbft_round,
                            );
                            dbft_timer.reset(dbft_round.as_ref(), signer.as_ref());
                            let announced = beacon.broadcast(BeaconCommand::NewBlockHashes(
                                block_hash_announcement(status.head, status.head_number),
                            ));
                            warn!(
                                target: "neox::sync",
                                previous_number = local.head_number,
                                previous_hash = %local.head,
                                block_number = status.head_number,
                                block_hash = %status.head,
                                announced,
                                "Reconciled Neo X head after a missed canonical notification"
                            );
                        }
                        Err(error) => {
                            warn!(target: "neox::sync", %error, "Failed to reconcile missed Neo X canonical notification");
                        }
                    },
                    Err(error) => {
                        debug!(target: "neox::sync", %error, "Failed to inspect authoritative Neo X head");
                    }
                }
                if let Some(request) =
                    descendant_sync_targets.retry(beacon.status(), Instant::now())
                {
                    submit_descendant_sync_request(
                        &descendant_sync_requests,
                        &mut descendant_sync_targets,
                        request,
                    );
                }
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
                        proposal_recovery: &mut proposal_recovery,
                        primary_builds: &mut primary_builds,
                        dbft_timer: &mut dbft_timer,
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
                        anti_mev: &mut anti_mev,
                        beacon: &beacon,
                        sidecar_store: &committed_sidecar_store,
                        proposal_recovery: &mut proposal_recovery,
                        dbft_timer: &mut dbft_timer,
                    },
                );
                maybe_schedule_primary_proposal(PrimaryProposalScheduleContext {
                    round: dbft_round.as_ref(),
                    signer: signer.as_ref(),
                    pool: &pool,
                    provider: &provider,
                    proposal_evm: &proposal_evm,
                    chain_spec: &chain_spec,
                    results: &primary_results_tx,
                    builds: &mut primary_builds,
                });
            }
            result = reconstruction_results_rx.recv() => {
                let Some(result) = result else {
                    warn!(target: "neox::validator", "Neo X Anti-MEV reconstruction channel closed");
                    return
                };
                handle_antimev_reconstruction(result, AntiMevReconstructionContext {
                    round: dbft_round.as_mut(),
                    signer: signer.as_ref(),
                    dbft: &dbft,
                    verified_proposals: &mut verified_proposals,
                    provider: &provider,
                    engine: &engine,
                    beacon: &beacon,
                    sidecar_store: &committed_sidecar_store,
                    anti_mev: &mut anti_mev,
                    dbft_timer: Some(&mut dbft_timer),
                });
            }
            notification = canonical.next() => {
                let Some(notification) = notification else {
                    warn!(target: "neox::sync", "Neo X canonical notification stream closed");
                    return
                };
                let local = beacon.status();
                let resolution =
                    match resolve_canonical_notification(&notification, &provider, local, &chain_spec) {
                        Ok(resolution) => resolution,
                        Err(error) => {
                            warn!(target: "neox::sync", %error, "Failed to reconcile canonical Neo X notification");
                            continue
                        }
                    };

                match &notification {
                    CanonStateNotification::Commit { new } => {
                        sidecars.archive_chain(new, &pool, &beacon);
                        if new.first().parent_hash != local.head {
                            warn!(
                                target: "neox::sync",
                                expected_parent = %local.head,
                                actual_parent = %new.first().parent_hash,
                                authoritative_head = %resolution.status.head,
                                "Canonical Neo X commit skipped or did not extend the advertised head; reconciled from provider"
                            );
                        }
                    }
                    CanonStateNotification::Reorg { new, .. } => {
                        metrics.canonical_reorgs_total.increment(1);
                        sidecars.archive_chain(new, &pool, &beacon);
                    }
                }

                if resolution.status == local && resolution.notification_tip != local.head {
                    debug!(
                        target: "neox::sync",
                        notification_tip = %resolution.notification_tip,
                        block_number = local.head_number,
                        block_hash = %local.head,
                        "Ignored stale canonical Neo X notification after archiving its sidecars"
                    );
                    continue
                }

                proposal_recovery.clear();
                verified_proposals.clear();
                anti_mev.clear();
                primary_builds.clear();

                let status = resolution.status;
                let number = status.head_number;
                let tip_hash = status.head;
                let coalesced = resolution.notification_tip != tip_hash;
                metrics.canonical_height.set(number as f64);
                metrics.canonical_updates_total.increment(1);
                dbft.update_height(number);
                beacon.update_status(status);
                descendant_sync_targets.reconcile(status);
                activate_dbft_round(
                    number,
                    tip_hash,
                    &provider,
                    &dbft,
                    &chain_spec,
                    signer.as_ref(),
                    &mut dbft_round,
                );
                dbft_timer.reset(dbft_round.as_ref(), signer.as_ref());

                let announcement = block_hash_announcement(tip_hash, number);
                let announced = beacon.broadcast(BeaconCommand::NewBlockHashes(announcement));
                let propagated = resolution
                    .propagated_block
                    .filter(|_| !coalesced)
                    .map_or(0, |block| {
                    let packet = NewBlockPacket { block, total_difficulty: status.total_difficulty };
                    // Encode the block frame body once and fan it out as a raw frame, so broadcasting
                    // to many peers does not deep-clone and re-RLP-encode the whole block per peer.
                    let mut block_payload = BytesMut::new();
                    packet.encode(&mut block_payload);
                    beacon.broadcast(BeaconCommand::Raw {
                        message_id: BeaconMessageId::NewBlock,
                        payload: block_payload.freeze().into(),
                    })
                });
                info!(
                    target: "neox::sync",
                    block_number = number,
                    block_hash = %tip_hash,
                    notification_tip = %resolution.notification_tip,
                    coalesced,
                    announced,
                    propagated,
                    "Updated and propagated canonical Neo X head"
                );
            }
        }
        if dbft_round.as_ref().map(|round| (round.height(), round.current_view())) != round_epoch {
            replay_cached_dbft_messages(DbftEventContext {
                round: dbft_round.as_mut(),
                pool: &pool,
                provider: &provider,
                beacon: &beacon,
                proposal_recovery: &mut proposal_recovery,
                proposal_evm: &proposal_evm,
                chain_spec: &chain_spec,
                signer: signer.as_ref(),
                dbft: &dbft,
                verified_proposals: &mut verified_proposals,
                engine: &engine,
                anti_mev: &mut anti_mev,
                primary_results: &primary_results_tx,
                primary_builds: &mut primary_builds,
                dbft_timer: &mut dbft_timer,
                sidecar_store: &committed_sidecar_store,
                future_messages: &mut future_messages,
                metrics: &metrics,
            });
        }
    }
}

struct DbftEventContext<'a, Pool, Provider> {
    round: Option<&'a mut DbftRoundState>,
    pool: &'a Pool,
    provider: &'a Provider,
    beacon: &'a BeaconProtocol,
    proposal_recovery: &'a mut ProposalRecovery<Provider>,
    proposal_evm: &'a NeoXEvmConfig,
    chain_spec: &'a Arc<NeoXChainSpec>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    verified_proposals: &'a mut HashMap<B256, VerifiedProposal>,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    anti_mev: &'a mut AntiMevReconstructor<Provider>,
    primary_results: &'a mpsc::UnboundedSender<PrimaryProposalResult>,
    primary_builds: &'a mut HashSet<(u64, u8)>,
    dbft_timer: &'a mut DbftTimer,
    sidecar_store: &'a NeoXSidecarStore,
    future_messages: &'a mut FutureDbftMessages,
    metrics: &'a NeoXSyncMetrics,
}

struct PrimaryProposalResult {
    height: u64,
    view: u8,
    result: Result<PrimaryProposal, PrimaryProposalError>,
}

struct ProposalVerificationContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    verified_proposals: &'a mut HashMap<B256, VerifiedProposal>,
    provider: &'a Provider,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    anti_mev: &'a mut AntiMevReconstructor<Provider>,
    beacon: &'a BeaconProtocol,
    sidecar_store: &'a NeoXSidecarStore,
    proposal_recovery: &'a mut ProposalRecovery<Provider>,
    dbft_timer: &'a mut DbftTimer,
}

struct PrimaryProposalContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    proposal_recovery: &'a mut ProposalRecovery<Provider>,
    primary_builds: &'a mut HashSet<(u64, u8)>,
    dbft_timer: &'a mut DbftTimer,
}

struct AntiMevReconstructionContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    verified_proposals: &'a mut HashMap<B256, VerifiedProposal>,
    provider: &'a Provider,
    engine: &'a ConsensusEngineHandle<EthEngineTypes>,
    beacon: &'a BeaconProtocol,
    sidecar_store: &'a NeoXSidecarStore,
    anti_mev: &'a mut AntiMevReconstructor<Provider>,
    dbft_timer: Option<&'a mut DbftTimer>,
}

struct DbftTimeoutContext<'a, Provider> {
    round: Option<&'a mut DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    dbft: &'a DbftProtocol,
    proposal_recovery: &'a mut ProposalRecovery<Provider>,
    timer: &'a mut DbftTimer,
}

struct PrimaryProposalScheduleContext<'a, Pool, Provider> {
    round: Option<&'a DbftRoundState>,
    signer: Option<&'a DbftSigner>,
    pool: &'a Pool,
    provider: &'a Provider,
    proposal_evm: &'a NeoXEvmConfig,
    chain_spec: &'a Arc<NeoXChainSpec>,
    results: &'a mpsc::UnboundedSender<PrimaryProposalResult>,
    builds: &'a mut HashSet<(u64, u8)>,
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
    match event {
        DbftEvent::Established { peer_id, direction } => {
            info!(target: "neox::sync", %peer_id, ?direction, "Neo X dbft/0 peer established");
        }
        DbftEvent::Disconnected { peer_id } => {
            debug!(target: "neox::sync", %peer_id, "Neo X dbft/0 peer disconnected");
        }
        DbftEvent::Message { peer_id, message } => {
            process_dbft_messages(VecDeque::from([(peer_id, message)]), context);
        }
        DbftEvent::Violation { peer_id, reason } => {
            context.metrics.dbft_transitions_rejected_total.increment(1);
            warn!(target: "neox::sync", %peer_id, ?reason, "Rejected invalid Neo X dbft/0 peer message");
        }
    }
}

/// Feeds authenticated dBFT messages through the active round, replaying anything the round cached
/// along the way.
///
/// A message for a height or view the round has not reached is cached rather than dropped, which is
/// what the reference client's state machine does. Every view change taken here replays the cache
/// for the round's height in the reference client's replay order, because that is where the
/// reference client drains it, and a replayed message that is still ahead of the round goes back
/// into the cache for the next view change.
fn process_dbft_messages<Pool, Provider>(
    mut pending: VecDeque<CachedDbftMessage>,
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
        proposal_recovery,
        proposal_evm,
        chain_spec,
        signer,
        dbft,
        verified_proposals,
        engine,
        anti_mev,
        primary_results,
        primary_builds,
        dbft_timer,
        sidecar_store,
        future_messages,
        metrics,
    } = context;
    let Some(round) = round else {
        for (peer_id, _) in &pending {
            debug!(target: "neox::sync", %peer_id, "Ignoring dBFT payload without an active canonical round");
        }
        return;
    };
    while let Some((peer_id, message)) = pending.pop_front() {
        if is_future_dbft_message(round.height(), message.valid_block_end) {
            let cached = cache_future_dbft_message(future_messages, peer_id, &message, metrics);
            debug!(
                target: "neox::validator",
                %peer_id,
                round_height = round.height(),
                message_height = message.valid_block_end,
                cached,
                "Deferred authenticated future Neo X dBFT message while the canonical chain catches up"
            );
            continue;
        }
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
            Err(error) if is_future_view_dbft_transition(error) => {
                // The reference client caches a message from a view above its own instead of
                // refusing it, and replays it if it reaches that view, so a backup that already
                // moved on does not have to resend everything by recovery.
                let cached =
                    cache_future_dbft_message(future_messages, peer_id, &received, metrics);
                metrics.dbft_transitions_stale_total.increment(1);
                debug!(
                    target: "neox::validator",
                    %peer_id,
                    %error,
                    cached,
                    "Deferred authenticated Neo X dBFT message from a later view"
                );
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
                Some(dbft_timer),
            );
            let import_view = match progress {
                DbftRoundProgress::Committed { view, .. } => *view,
                _ => round.current_view(),
            };
            anti_mev.schedule(round, import_view, verified_proposals);
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
            continue;
        }
        maybe_respond_to_recovery_request(round, &received, signer, dbft);

        let active_view = round.current_view();
        if active_view != previous_view {
            proposal_recovery.clear();
            verified_proposals.clear();
            anti_mev.clear();
            dbft_timer.reset(Some(round), signer);
            maybe_schedule_primary_proposal(PrimaryProposalScheduleContext {
                round: Some(round),
                signer,
                pool,
                provider,
                proposal_evm,
                chain_spec,
                results: primary_results,
                builds: primary_builds,
            });
            // The reference client drains its cache every time it initializes a round, which
            // includes each view change, so a message cached for this view is replayed here.
            pending.extend(drain_cached_dbft_messages(future_messages, round.height(), metrics));
        }
        let Some(proposal) = round.proposal(active_view).cloned() else { continue };
        let proposal_hash = proposal.hash();
        if active_view == previous_view && previous_proposal == Some(proposal_hash) {
            proposal_recovery.observe_source(peer_id, active_view, proposal_hash, round);
            continue;
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
                continue;
            }
        };
        match proposal_recovery.begin(peer_id, active_view, proposal_hash, request, round, pool) {
            Ok(()) => {}
            Err(error) => {
                let reason = proposal_rejection_reason(&error);
                warn!(target: "neox::validator", %peer_id, %error, "Rejected Neo X proposal transaction commitment");
                proposal_recovery.clear();
                let outcome = publish_local_change_view(round, signer, dbft, reason, dbft_timer);
                if outcome.changed_view {
                    pending.extend(drain_cached_dbft_messages(
                        future_messages,
                        round.height(),
                        metrics,
                    ));
                }
            }
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

const fn is_future_dbft_message(round_height: u64, message_height: u64) -> bool {
    message_height > round_height
}

/// Reports whether the round refused a message because its view is above the round's.
///
/// The reference client caches these instead of refusing them, so they are worth keeping. A view
/// below the round's is a genuinely stale message and is not.
const fn is_future_view_dbft_transition(error: &DbftStateError) -> bool {
    matches!(error, DbftStateError::WrongView { expected, actual } if *actual > *expected)
}

/// Caches one message the active round cannot accept yet, reporting whether it was retained.
fn cache_future_dbft_message(
    future_messages: &mut FutureDbftMessages,
    peer_id: B512,
    message: &Arc<DbftMessage>,
    metrics: &NeoXSyncMetrics,
) -> bool {
    let cached = message
        .consensus_data()
        .ok()
        .and_then(|data| CachedMessageKind::from_message_type(data.message_type))
        .is_some_and(|kind| future_messages.insert(peer_id, Arc::clone(message), kind));
    if cached {
        metrics.dbft_messages_deferred_total.increment(1);
    }
    metrics.dbft_messages_cached.set(future_messages.len() as f64);
    cached
}

/// Takes the cached messages for one height, in the order the reference client replays them.
fn drain_cached_dbft_messages(
    future_messages: &mut FutureDbftMessages,
    height: u64,
    metrics: &NeoXSyncMetrics,
) -> Vec<CachedDbftMessage> {
    let replayed = future_messages.take_height(height);
    if !replayed.is_empty() {
        metrics.dbft_messages_replayed_total.increment(replayed.len() as u64);
        debug!(
            target: "neox::validator",
            block_number = height,
            messages = replayed.len(),
            "Replaying deferred Neo X dBFT messages"
        );
    }
    metrics.dbft_messages_cached.set(future_messages.len() as f64);
    replayed
}

/// Replays the messages cached for the active round's height, and forgets heights it passed.
fn replay_cached_dbft_messages<Pool, Provider>(context: DbftEventContext<'_, Pool, Provider>)
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
    let Some(height) = context.round.as_deref().map(DbftRoundState::height) else {
        return;
    };
    context.future_messages.prune_through(height.saturating_sub(1));
    let replayed = drain_cached_dbft_messages(context.future_messages, height, context.metrics);
    if !replayed.is_empty() {
        process_dbft_messages(replayed.into(), context);
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
        anti_mev,
        beacon,
        sidecar_store,
        proposal_recovery,
        dbft_timer,
    } = context;
    let Some(round) = round else {
        debug!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Discarded verified proposal without an active round");
        return;
    };
    if round.current_view() != verification.view ||
        round.proposal(verification.view).map(|proposal| proposal.hash()) !=
            Some(verification.proposal_hash)
    {
        debug!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Discarded stale Neo X proposal verification result");
        return;
    }
    let verified = match verification.result {
        Ok(verified) => verified,
        Err(error) => {
            let reason = proposal_rejection_reason(&error);
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, %error, "Rejected Neo X proposal after deterministic execution");
            proposal_recovery.clear();
            publish_local_change_view(round, signer, dbft, reason, dbft_timer);
            return;
        }
    };
    let progress = if round.anti_mev() {
        let Some(anti_mev) = verified.anti_mev.as_ref() else {
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, "Verified Anti-MEV proposal is missing Envelope metadata");
            proposal_recovery.clear();
            publish_local_change_view(
                round,
                signer,
                dbft,
                DbftChangeViewReason::TransactionInvalid,
                dbft_timer,
            );
            return;
        };
        round.finalize_pre_block(verification.view, verified.block.header(), anti_mev.len())
    } else {
        round.finalize_proposal(verification.view, verified.block.header().clone())
    };
    let progress = match progress {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::validator", view = verification.view, proposal_hash = %verification.proposal_hash, %error, "Rejected executed Neo X proposal pre-block");
            proposal_recovery.clear();
            publish_local_change_view(
                round,
                signer,
                dbft,
                DbftChangeViewReason::TransactionInvalid,
                dbft_timer,
            );
            return;
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
    maybe_publish_consensus_contribution(
        round,
        &progress,
        signer,
        dbft,
        verified_proposals,
        Some(dbft_timer),
    );
    anti_mev.schedule(round, verification.view, verified_proposals);
    if schedule_committed_proposal(
        round,
        verification.view,
        provider,
        engine,
        beacon,
        sidecar_store,
        verified_proposals,
    ) {
        return;
    }

    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if usize::from(local_index) == round.primary_index(verification.view) {
        return;
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
            return;
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
                Some(dbft_timer),
            );
            anti_mev.schedule(round, verification.view, verified_proposals);
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

fn handle_antimev_reconstruction<Provider>(
    reconstruction: AntiMevReconstructionResult,
    context: AntiMevReconstructionContext<'_, Provider>,
) where
    Provider: BlockReader<Block = Block> + StateProviderFactory + Clone + Send + Sync + 'static,
{
    let AntiMevReconstructionContext {
        round,
        signer,
        dbft,
        verified_proposals,
        provider,
        engine,
        beacon,
        sidecar_store,
        anti_mev,
        dbft_timer,
    } = context;
    anti_mev.finish(reconstruction.proposal_hash);
    let Some(round) = round else {
        anti_mev.discard(reconstruction.proposal_hash);
        debug!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, "Discarded Anti-MEV reconstruction without an active round");
        return;
    };
    if round.current_view() != reconstruction.view ||
        round.proposal(reconstruction.view).map(|proposal| proposal.hash()) !=
            Some(reconstruction.proposal_hash)
    {
        anti_mev.discard(reconstruction.proposal_hash);
        debug!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, "Discarded stale Anti-MEV reconstruction result");
        return;
    }
    let reconstructed = match reconstruction.result {
        Ok(reconstructed) => reconstructed,
        Err(error) => {
            let attempted = anti_mev.attempted_contributions(reconstruction.proposal_hash);
            warn!(target: "neox::validator", view = reconstruction.view, proposal_hash = %reconstruction.proposal_hash, contributions = attempted, %error, "Neo X Anti-MEV reconstruction needs more valid shares");
            anti_mev.schedule(round, reconstruction.view, verified_proposals);
            return;
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
            anti_mev.schedule(round, reconstruction.view, verified_proposals);
            return;
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
    anti_mev.discard(reconstruction.proposal_hash);
    verified_proposals.insert(reconstruction.proposal_hash, proposal);
    maybe_publish_consensus_contribution(
        round,
        &progress,
        signer,
        dbft,
        verified_proposals,
        dbft_timer,
    );
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

/// Publishes whatever contribution the round now allows, and re-arms the timer if one was recorded.
///
/// The reference client resets its timer to one block period as soon as it records its own
/// `PreCommit` or `Commit`, replacing the longer view timeout that was running. Without that reset
/// a node that has already committed keeps waiting out the view timeout before it resends its
/// commit by recovery, so a round that lost its quorum recovers slower here than on the reference
/// client.
fn maybe_publish_consensus_contribution(
    round: &mut DbftRoundState,
    progress: &DbftRoundProgress,
    signer: Option<&DbftSigner>,
    dbft: &DbftProtocol,
    verified_proposals: &HashMap<B256, VerifiedProposal>,
    timer: Option<&mut DbftTimer>,
) {
    let local_index = signer.and_then(|signer| signer.validator_index(round.validators()));
    let contributed_before = local_index
        .is_some_and(|index| round.has_any_pre_commit(index) || round.has_any_commit(index));
    if round.anti_mev() {
        maybe_publish_antimev_precommit(round, progress, signer, dbft, verified_proposals);
        maybe_publish_antimev_commit(round, progress, signer, dbft, verified_proposals);
    } else {
        maybe_publish_pre_antimev_commit(round, progress, signer, dbft, verified_proposals);
    }
    if contributed_before {
        return;
    }
    let Some(index) = local_index else { return };
    if !(round.has_any_pre_commit(index) || round.has_any_commit(index)) {
        return;
    }
    if let Some(timer) = timer {
        timer.arm_contribution(round.height(), round.current_view());
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
        return;
    }
    let Some(proposal_hash) = round.proposal(view).map(|proposal| proposal.hash()) else { return };
    let Some(verified) = verified_proposals.get(&proposal_hash) else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local Anti-MEV pre-block validation before signing PreCommit");
        return;
    };
    let Some(anti_mev) = verified.anti_mev.as_ref() else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local Anti-MEV metadata before signing PreCommit");
        return
    };
    let Some(dkg_state) = round.dkg_state() else {
        warn!(target: "neox::validator", validator_index = local_index, view, "Cannot create Neo X PreCommit without canonical DKG state");
        return
    };
    let current_epoch = DkgShareEpoch::new(
        dkg_state.current.round,
        dkg_state.current.global_public_key,
        verified.parent_state_hash,
    );

    let current_ciphertexts = anti_mev.ciphertexts(EnvelopeDkgEpoch::Current);
    let current_shares = if current_ciphertexts.is_empty() {
        Vec::new()
    } else {
        match signer.current_decryption_shares_at(current_epoch, &current_ciphertexts) {
            Ok(shares) => shares,
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, %error, "Deferred Neo X PreCommit until current-round decryption shares are available");
                return
            }
        }
    };
    let previous_ciphertexts = anti_mev.ciphertexts(EnvelopeDkgEpoch::Previous);
    let previous_shares = if previous_ciphertexts.is_empty() {
        Vec::new()
    } else if let Some(previous) = dkg_state.previous.as_ref() {
        let previous_epoch = DkgShareEpoch::new(
            previous.round,
            previous.global_public_key,
            verified.parent_state_hash,
        );
        match signer.previous_decryption_shares_at(previous_epoch, &previous_ciphertexts) {
            Ok(shares) => shares,
            Err(error) => {
                warn!(target: "neox::validator", validator_index = local_index, view, %error, "Deferred Neo X PreCommit until previous-round decryption shares are available");
                return
            }
        }
    } else {
        warn!(target: "neox::validator", validator_index = local_index, view, "Cannot create previous-round shares without canonical DKG metadata");
        return
    };
    let encoded = match encode_decryption_shares(&current_shares, &previous_shares) {
        Ok(encoded) => encoded,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to encode Neo X PreCommit shares");
            return;
        }
    };
    let pre_commit = match DbftPreCommit::from_data(encoded.into()) {
        Ok(pre_commit) => pre_commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Generated invalid Neo X PreCommit payload");
            return;
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
            return;
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
    verified_proposals: &HashMap<B256, VerifiedProposal>,
) {
    let DbftRoundProgress::PreCommitted { view, .. } = progress else { return };
    let view = *view;
    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if round.has_commit(view, local_index) {
        return;
    }
    let Some(header) = round.final_header(view) else {
        debug!(target: "neox::validator", validator_index = local_index, view, "Waiting for Anti-MEV final-block reconstruction before signing Commit");
        return;
    };
    let Some(verified) =
        round.proposal(view).and_then(|proposal| verified_proposals.get(&proposal.hash()))
    else {
        debug!(target: "neox::validator", validator_index = local_index, view, "Waiting for canonical proposal context before signing Anti-MEV Commit");
        return
    };
    let epoch = round.dkg_state().map(|state| {
        DkgShareEpoch::new(
            state.current.round,
            state.current.global_public_key,
            verified.parent_state_hash,
        )
    });
    let commit = match signer.commit_for_header_at(header, epoch) {
        Ok(commit) => commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to sign Neo X Anti-MEV final block commit");
            return;
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
            return;
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
        return;
    }
    let Some(signer) = signer else { return };
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    let Some(verified) = verified_proposals.get(&proposal_hash) else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local proposal execution before signing Neo X commit");
        return;
    };
    let epoch = round.dkg_state().map(|state| {
        DkgShareEpoch::new(
            state.current.round,
            state.current.global_public_key,
            verified.parent_state_hash,
        )
    });
    let commit = match signer.commit_for_header_at(verified.block.header(), epoch) {
        Ok(commit) => commit,
        Err(error) => {
            warn!(target: "neox::validator", validator_index = local_index, view, %error, "Failed to sign Neo X block commit");
            return;
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
            return;
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
        return false;
    };
    let sealed_header = match round.sealed_header(view) {
        Ok(header) => header,
        Err(error) => {
            warn!(target: "neox::validator", view, %proposal_hash, %error, "Failed to assemble committed Neo X proposal seal");
            return false;
        }
    };
    let Some(verified) = verified_proposals.remove(&proposal_hash) else {
        debug!(target: "neox::validator", view, %proposal_hash, "Waiting for local proposal execution before importing committed Neo X block");
        return false;
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
                    return;
                }
                Ok(Err(error)) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %parent_state_hash, %error, "Failed to load canonical parent for Neo X witness reseal");
                    return;
                }
                Err(error) => {
                    warn!(target: "neox::sync", block_number, %block_hash, %parent_state_hash, %error, "Neo X parent witness resolution task failed");
                    return;
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
            return false;
        }
        let parent_payload = EthPayloadTypes::block_to_payload(parent.seal_slow(), None);
        match engine.new_payload(parent_payload).await {
            Ok(status) if status.is_valid() => {
                debug!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, "Imported authenticated Neo X parent witness reseal");
            }
            Ok(status) if status.is_syncing() => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, "Engine Tree is missing ancestry for Neo X parent witness reseal");
                request_sync_target(engine, parent_hash).await;
                return false;
            }
            Ok(status) => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, status = %status, "Engine Tree rejected authenticated Neo X parent witness reseal");
                return false;
            }
            Err(error) => {
                warn!(target: "neox::sync", block_number = parent_number, block_hash = %parent_hash, %error, "Neo X parent witness reseal import failed");
                return false;
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
            return false;
        }
        Ok(status) => {
            warn!(target: "neox::sync", block_number, %block_hash, status = %status, "Engine Tree rejected committed Neo X block");
            return false;
        }
        Err(error) => {
            warn!(target: "neox::sync", block_number, %block_hash, %error, "Committed Neo X block import failed");
            return false;
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

fn handle_dbft_timeout<Provider>(
    timeout: DbftTimeout,
    context: DbftTimeoutContext<'_, Provider>,
) -> bool {
    let DbftTimeoutContext { round, signer, dbft, proposal_recovery, timer } = context;
    if !timer.consume(timeout) {
        return false;
    }
    let (Some(round), Some(signer)) = (round, signer) else { return false };
    if round.height() != timeout.height || round.current_view() != timeout.view {
        debug!(
            target: "neox::validator",
            block_number = timeout.height,
            view = timeout.view,
            "Ignored stale local Neo X dBFT timeout"
        );
        return false;
    }
    let Some(local_index) = signer.validator_index(round.validators()) else { return false };
    let is_primary = usize::from(local_index) == round.primary_index(timeout.view);
    if is_primary && round.proposal(timeout.view).is_none() {
        timer.arm_post_proposal(timeout.height, timeout.view);
        info!(
            target: "neox::producer",
            block_number = timeout.height,
            view = timeout.view,
            validator_index = local_index,
            "Local Neo X primary proposal timer expired"
        );
        return false;
    }
    if round.has_pre_commit(timeout.view, local_index) ||
        round.has_commit(timeout.view, local_index)
    {
        publish_recovery_message(round, signer, dbft);
        timer.arm_recovery(timeout.height, timeout.view);
        return false;
    }
    let Some(next_view) = timeout.view.checked_add(1) else {
        warn!(
            target: "neox::validator",
            block_number = timeout.height,
            "Cannot advance Neo X dBFT past the maximum view"
        );
        return false;
    };
    if round.more_than_f_committed_or_failed(timeout.view, local_index) {
        publish_recovery_request(round, signer, local_index, dbft);
        timer.arm_change_view(timeout.height, timeout.view, next_view);
        return false;
    }
    let missing_transactions = round
        .proposal(timeout.view)
        .is_some_and(|proposal| proposal_recovery.is_waiting_for(timeout.view, proposal.hash()));
    let reason = if missing_transactions {
        DbftChangeViewReason::TransactionNotFound
    } else {
        DbftChangeViewReason::Timeout
    };
    let outcome = publish_local_change_view(round, Some(signer), dbft, reason, timer);
    if outcome.requested {
        proposal_recovery.clear();
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
    timer: &mut DbftTimer,
) -> LocalChangeViewOutcome {
    let Some(signer) = signer else { return LocalChangeViewOutcome::default() };
    let Some(local_index) = signer.validator_index(round.validators()) else {
        return LocalChangeViewOutcome::default();
    };
    let height = round.height();
    let view = round.current_view();
    let Some(next_view) = view.checked_add(1) else {
        warn!(target: "neox::validator", block_number = height, "Cannot advance Neo X dBFT past the maximum view");
        return LocalChangeViewOutcome::default();
    };
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
        timer.arm_change_view(height, view, next_view);
        return LocalChangeViewOutcome { requested: true, changed_view: false };
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
            return LocalChangeViewOutcome::default();
        }
    };
    let message_hash = message.hash();
    let progress = match round.process(Arc::new(message.clone())) {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::validator", block_number = height, view, %error, "Rejected local Neo X ChangeView state transition");
            return LocalChangeViewOutcome::default();
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
        timer.reset(Some(round), Some(signer));
    } else {
        timer.arm_change_view(height, view, next_view);
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
        DbftProposalError::PoolRejection { .. } |
        DbftProposalError::UnknownTransactionResponse(_) |
        DbftProposalError::EmptyTransactionResponse(_) |
        DbftProposalError::WrongTransactionPeer { .. } |
        DbftProposalError::UnexpectedTransaction(_) |
        DbftProposalError::TransactionCount { .. } |
        DbftProposalError::TransactionHash { .. } |
        DbftProposalError::SidecarCount { .. } |
        DbftProposalError::InvalidSidecar { .. } |
        DbftProposalError::AntiMevProposal(_) |
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
        return;
    }
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    let committed = round.has_any_pre_commit(local_index) || round.has_any_commit(local_index);
    if !recovery_response_allowed(
        round.validators().len(),
        data.validator_index,
        local_index,
        committed,
    ) {
        return;
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
        return true;
    }
    let requester = usize::from(requester);
    let local = usize::from(local_index);
    if validator_count == 0 || requester >= validator_count || local >= validator_count {
        return false;
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
            return;
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
            return;
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
            return;
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

fn maybe_schedule_primary_proposal<Pool, Provider>(
    context: PrimaryProposalScheduleContext<'_, Pool, Provider>,
) where
    Pool: TransactionPool<
            Transaction: PoolTransaction<
                Consensus = TransactionSigned,
                Pooled = PooledTransactionVariant,
            >,
        > + 'static,
    Provider: HeaderProvider<Header = Header> + StateProviderFactory + Clone + Send + 'static,
{
    let PrimaryProposalScheduleContext {
        round,
        signer,
        pool,
        provider,
        proposal_evm,
        chain_spec,
        results,
        builds,
    } = context;
    let (Some(round), Some(signer)) = (round, signer) else { return };
    let view = round.current_view();
    let Some(local_index) = signer.validator_index(round.validators()) else { return };
    if usize::from(local_index) != round.primary_index(view) || round.proposal(view).is_some() {
        return;
    }
    let key = (round.height(), view);
    if !builds.insert(key) {
        return;
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
        proposal_recovery,
        primary_builds,
        dbft_timer,
    } = context;
    primary_builds.remove(&(result.height, result.view));
    let (Some(round), Some(signer)) = (round, signer) else {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded primary proposal without an active local validator");
        return;
    };
    if round.height() != result.height || round.current_view() != result.view {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded stale local primary proposal");
        return;
    }
    let Some(local_index) = signer.validator_index(round.validators()) else {
        warn!(target: "neox::producer", account = %signer.account(), "Local primary signer left the active Governance set");
        return;
    };
    if usize::from(local_index) != round.primary_index(result.view) ||
        round.proposal(result.view).is_some()
    {
        debug!(target: "neox::producer", block_number = result.height, view = result.view, "Discarded superseded local primary proposal");
        return;
    }
    let proposal = match result.result {
        Ok(proposal) => proposal,
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, %error, "Failed to build local Neo X primary proposal");
            return;
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
            return;
        }
    };
    let proposal_hash = message.hash();
    let progress = match round.process(Arc::new(message.clone())) {
        Ok(progress) => progress,
        Err(error) => {
            warn!(target: "neox::producer", block_number = result.height, view = result.view, %error, "Rejected local Neo X PrepareRequest state transition");
            return;
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
            return;
        }
    }
    dbft_timer.arm_post_proposal(result.height, result.view);
    proposal_recovery.verify_local(
        round,
        result.view,
        proposal_hash,
        proposal.request,
        proposal.transactions,
        proposal.sidecars,
    );
}

trait DbftActivationStateProvider {
    fn activation_state_by_block_hash(&self, block_hash: B256) -> Result<StateProviderBox, String>;
}

impl<Provider> DbftActivationStateProvider for Provider
where
    Provider: StateProviderFactory,
{
    fn activation_state_by_block_hash(&self, block_hash: B256) -> Result<StateProviderBox, String> {
        self.state_by_block_hash(block_hash).map_err(|error| error.to_string())
    }
}

fn activate_dbft_round<Provider>(
    canonical_height: u64,
    canonical_hash: B256,
    provider: &Provider,
    dbft: &DbftProtocol,
    chain_spec: &NeoXChainSpec,
    signer: Option<&DbftSigner>,
    round: &mut Option<DbftRoundState>,
) where
    Provider: DbftActivationStateProvider,
{
    let Some(next_height) = canonical_height.checked_add(1) else {
        dbft.deactivate();
        *round = None;
        warn!(target: "neox::validator", "Cannot start dBFT round after maximum block height");
        return;
    };
    let result = provider.activation_state_by_block_hash(canonical_hash).and_then(|state| {
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
                canonical_hash = %canonical_hash,
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
            warn!(target: "neox::validator", canonical_height, canonical_hash = %canonical_hash, %error, "Failed to activate Neo X dBFT round");
        }
    }
}

struct BeaconEventContext<'a, Pool, Provider> {
    beacon: &'a BeaconProtocol,
    pool: &'a Pool,
    provider: &'a Provider,
    sidecars: &'a mut SidecarSync,
    dbft: &'a DbftProtocol,
    chain_spec: &'a Arc<NeoXChainSpec>,
    signer: Option<&'a DbftSigner>,
    dbft_round: &'a mut Option<DbftRoundState>,
    proposal_recovery: &'a mut ProposalRecovery<Provider>,
    dbft_timer: &'a mut DbftTimer,
    propagated_blocks: &'a mpsc::Sender<PropagatedBlockJob>,
    descendant_sync_targets: &'a mut DescendantSyncTargets,
    descendant_sync_requests: &'a mpsc::Sender<DescendantSyncRequest>,
}

fn handle_beacon_event<Pool, Provider>(
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
        pool,
        provider,
        sidecars,
        dbft,
        chain_spec,
        signer,
        dbft_round,
        proposal_recovery,
        dbft_timer,
        propagated_blocks,
        descendant_sync_targets,
        descendant_sync_requests,
    } = context;
    match event {
        BeaconEvent::Established { peer_id, version, status, .. } => {
            sidecars.connect_peer(peer_id, status);
            proposal_recovery.connect_peer(peer_id, version, dbft_round.as_ref());
            let local = beacon.status();
            info!(
                target: "neox::sync",
                %peer_id,
                ?version,
                remote_head = %status.head(),
                remote_number = ?status.head_number(),
                "Neo X beacon peer established"
            );
            if let Some(target) = peer_status_backfill_target(status, local) &&
                let Some(request) =
                    descendant_sync_targets.observe(peer_id, target, local, Instant::now())
            {
                submit_descendant_sync_request(
                    descendant_sync_requests,
                    descendant_sync_targets,
                    request,
                );
            }
            if dbft_round.is_none() {
                activate_dbft_round(
                    local.head_number,
                    local.head,
                    provider,
                    dbft,
                    chain_spec,
                    signer,
                    dbft_round,
                );
                dbft_timer.reset(dbft_round.as_ref(), signer);
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
                let local = beacon.status();
                if best.number > local.head_number {
                    let target = DescendantSyncTarget { hash: best.hash, number: best.number };
                    if let Some(request) =
                        descendant_sync_targets.observe(peer_id, target, local, Instant::now())
                    {
                        submit_descendant_sync_request(
                            descendant_sync_requests,
                            descendant_sync_targets,
                            request,
                        );
                    }
                }
            }
        }
        BeaconEvent::NewBlock { peer_id, packet } => {
            let block_number = packet.block.header.number;
            let local = beacon.status();
            if let Some(target) = propagated_block_backfill_target(&packet, local) {
                debug!(
                    target: "neox::sync",
                    %peer_id,
                    block_number = target.number,
                    block_hash = %target.hash,
                    canonical_head = local.head_number,
                    "Queued propagated Neo X gap as a bounded descendant backfill target"
                );
                if let Some(request) =
                    descendant_sync_targets.observe(peer_id, target, local, Instant::now())
                {
                    submit_descendant_sync_request(
                        descendant_sync_requests,
                        descendant_sync_targets,
                        request,
                    );
                }
                return
            }
            if !enqueue_propagated_block(propagated_blocks, peer_id, *packet) {
                warn!(target: "neox::sync", %peer_id, block_number, capacity = PROPAGATED_BLOCK_QUEUE_CAPACITY, "Dropped propagated Neo X block because the import queue is full");
            }
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
            proposal_recovery.supply(peer_id, response, dbft_round.as_ref());
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
            sidecars.disconnect_peer(peer_id, beacon);
            proposal_recovery.disconnect_peer(peer_id, dbft_round.as_ref());
            descendant_sync_targets.disconnect(peer_id);
            debug!(target: "neox::sync", %peer_id, ?version, "Neo X beacon peer disconnected");
        }
    }
}

async fn import_propagated_block(
    peer_id: alloy_primitives::B512,
    packet: NewBlockPacket,
    canonical: BeaconLocalStatus,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
) {
    let number = packet.block.header.number;
    let disposition = propagated_block_disposition(&packet.block.header, canonical);
    match disposition {
        PropagatedBlockDisposition::DirectChild | PropagatedBlockDisposition::Gap => {}
        PropagatedBlockDisposition::CompetingFinalized => {
            warn!(
                target: "neox::sync",
                %peer_id,
                block_number = number,
                parent_hash = %packet.block.header.parent_hash,
                canonical_head = canonical.head_number,
                canonical_hash = %canonical.head,
                "Rejected propagated Neo X block that does not directly extend finalized history"
            );
            return
        }
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
        return;
    }

    if disposition == PropagatedBlockDisposition::Gap {
        let hash = packet.block.header.hash_slow();
        debug!(
            target: "neox::sync",
            %peer_id,
            block_number = number,
            block_hash = %hash,
            canonical_head = canonical.head_number,
            canonical_hash = %canonical.head,
            "Ignored propagated Neo X block whose canonical gap changed while queued"
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
            let _ = request_sync_target(engine, hash).await;
        }
        Ok(status) => {
            warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, status = %status, "Rejected propagated Neo X payload")
        }
        Err(error) => {
            warn!(target: "neox::sync", %peer_id, block_number = number, block_hash = %hash, %error, "Neo X payload validation failed")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescendantSyncTargetSubmission {
    Pending,
    Valid,
    Invalid,
}

fn submit_descendant_sync_request(
    requests: &mpsc::Sender<DescendantSyncRequest>,
    targets: &mut DescendantSyncTargets,
    request: DescendantSyncRequest,
) {
    if let Err(error) = requests.try_send(request) {
        targets.cancel_submission(request);
        warn!(
            target: "neox::sync",
            request_id = request.request_id,
            block_hash = %request.target.hash,
            block_number = request.target.number,
            %error,
            "Failed to queue Neo X descendant backfill target"
        );
    }
}

const fn optimistic_sync_target_state(head: B256) -> ForkchoiceState {
    ForkchoiceState {
        head_block_hash: head,
        safe_block_hash: B256::ZERO,
        finalized_block_hash: B256::ZERO,
    }
}

async fn request_sync_target(
    engine: &ConsensusEngineHandle<EthEngineTypes>,
    head: B256,
) -> DescendantSyncTargetSubmission {
    let state = optimistic_sync_target_state(head);
    match engine.fork_choice_updated(state, None).await {
        Ok(updated) => {
            debug!(target: "neox::sync", block_hash = %head, status = %updated.payload_status, "Submitted Neo X backfill target");
            if updated.payload_status.is_valid() {
                DescendantSyncTargetSubmission::Valid
            } else if updated.payload_status.is_invalid() {
                DescendantSyncTargetSubmission::Invalid
            } else {
                DescendantSyncTargetSubmission::Pending
            }
        }
        Err(error) => {
            warn!(target: "neox::sync", block_hash = %head, %error, "Failed to submit Neo X backfill target");
            DescendantSyncTargetSubmission::Pending
        }
    }
}

fn canonical_head_matches_status<Provider>(
    provider: &Provider,
    status: BeaconLocalStatus,
) -> Result<bool, String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    let head = provider.chain_info().map_err(|error| error.to_string())?;
    Ok(head.best_number == status.head_number && head.best_hash == status.head)
}

pub(super) fn authoritative_canonical_status<Provider>(
    provider: &Provider,
    seed: BeaconLocalStatus,
    chain_spec: &NeoXChainSpec,
    seed_total_difficulty_is_trusted: bool,
) -> Result<BeaconLocalStatus, String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    let mut checkpoint = seed_total_difficulty_is_trusted.then_some(seed);
    for _ in 0..CANONICAL_SNAPSHOT_ATTEMPTS {
        let head = provider.chain_info().map_err(|error| error.to_string())?;
        let header = provider
            .header(head.best_hash)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("missing canonical head {}", head.best_hash))?;
        if header.number != head.best_number {
            return Err(format!(
                "canonical head number mismatch: chain info {}, header {}",
                head.best_number, header.number
            ))
        }
        let total_difficulty = match checkpoint {
            Some(checkpoint) => canonical_total_difficulty(provider, checkpoint, head.best_number)?,
            None => add_canonical_difficulty(provider, U256::ZERO, 0, head.best_number)?,
        };
        let candidate = BeaconLocalStatus {
            network_id: chain_spec.inner.chain.id(),
            total_difficulty,
            head: head.best_hash,
            head_number: head.best_number,
            head_timestamp: header.timestamp,
            genesis: chain_spec.inner.genesis_hash(),
            blob_sync: seed.blob_sync,
        };
        let confirmed = provider.chain_info().map_err(|error| error.to_string())?;
        if confirmed == head {
            return Ok(candidate)
        }
        checkpoint = (provider.block_hash(head.best_number).map_err(|error| error.to_string())? ==
            Some(head.best_hash))
        .then_some(candidate);
    }
    Err(format!(
        "canonical head changed during {CANONICAL_SNAPSHOT_ATTEMPTS} reconciliation attempts"
    ))
}

fn canonical_total_difficulty<Provider>(
    provider: &Provider,
    seed: BeaconLocalStatus,
    target: u64,
) -> Result<U256, String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    if seed.head_number <= target &&
        provider.block_hash(seed.head_number).map_err(|error| error.to_string())? ==
            Some(seed.head)
    {
        if seed.head_number == target {
            return Ok(seed.total_difficulty)
        }
        return add_canonical_difficulty(
            provider,
            seed.total_difficulty,
            seed.head_number + 1,
            target,
        )
    }

    // A shallow reorg can normally reuse the trusted TD checkpoint by walking the old branch back
    // to a hash that is still canonical. If the provider no longer retains that branch, calculate
    // from genesis instead of guessing from incomplete notification deltas.
    let mut hash = seed.head;
    let mut number = seed.head_number;
    let mut total_difficulty = seed.total_difficulty;
    loop {
        if number <= target &&
            provider.block_hash(number).map_err(|error| error.to_string())? == Some(hash)
        {
            if number == target {
                return Ok(total_difficulty)
            }
            return add_canonical_difficulty(provider, total_difficulty, number + 1, target)
        }
        let Some(header) = provider.header(hash).map_err(|error| error.to_string())? else { break };
        if header.number != number {
            break
        }
        let Some(parent_total_difficulty) = total_difficulty.checked_sub(header.difficulty) else {
            break
        };
        if number == 0 {
            break
        }
        hash = header.parent_hash;
        number -= 1;
        total_difficulty = parent_total_difficulty;
    }

    add_canonical_difficulty(provider, U256::ZERO, 0, target)
}

fn add_canonical_difficulty<Provider>(
    provider: &Provider,
    mut total_difficulty: U256,
    start: u64,
    end: u64,
) -> Result<U256, String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    if start > end {
        return Ok(total_difficulty)
    }
    let mut cursor = start;
    loop {
        let batch_end = cursor.saturating_add(CANONICAL_HEADER_BATCH_SIZE - 1).min(end);
        let headers =
            provider.headers_range(cursor..=batch_end).map_err(|error| error.to_string())?;
        let expected = usize::try_from(batch_end - cursor + 1)
            .map_err(|_| "canonical header batch length overflow".to_string())?;
        if headers.len() != expected {
            return Err(format!(
                "missing canonical headers in range {cursor}..={batch_end}: expected {expected}, got {}",
                headers.len()
            ))
        }
        for (offset, header) in headers.into_iter().enumerate() {
            let expected_number = cursor + offset as u64;
            if header.number != expected_number {
                return Err(format!(
                    "out-of-order canonical header: expected {expected_number}, got {}",
                    header.number
                ))
            }
            total_difficulty = total_difficulty
                .checked_add(header.difficulty)
                .ok_or_else(|| format!("total difficulty overflow at block {}", header.number))?;
        }
        if batch_end == end {
            return Ok(total_difficulty)
        }
        cursor = batch_end + 1;
    }
}

#[derive(Debug)]
struct CanonicalNotificationResolution {
    notification_tip: B256,
    propagated_block: Option<Block>,
    status: BeaconLocalStatus,
}

fn resolve_canonical_notification<Provider>(
    notification: &CanonStateNotification<EthPrimitives>,
    provider: &Provider,
    seed: BeaconLocalStatus,
    chain_spec: &NeoXChainSpec,
) -> Result<CanonicalNotificationResolution, String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    let (notification_tip, _, propagated_block) =
        canonical_notification_tip(notification, provider)?;
    let status = authoritative_canonical_status(provider, seed, chain_spec, true)?;
    let propagated_block = (notification_tip == status.head).then_some(propagated_block).flatten();
    Ok(CanonicalNotificationResolution { notification_tip, propagated_block, status })
}

fn canonical_notification_tip<Provider>(
    notification: &CanonStateNotification<EthPrimitives>,
    provider: &Provider,
) -> Result<(B256, Header, Option<Block>), String>
where
    Provider: BlockReader<Block = Block> + HeaderProvider<Header = Header>,
{
    if let Some(tip) = notification.tip_checked() {
        return Ok((tip.hash(), tip.header().clone(), Some(tip.clone().into_block())))
    }

    let CanonStateNotification::Reorg { old, new } = notification else {
        return Err("canonical commit contained no blocks".to_string())
    };
    if !new.is_empty() || old.is_empty() {
        return Err("canonical reorg did not contain a resolvable tip".to_string())
    }
    let first_reverted = old.first();
    let parent_hash = first_reverted.parent_hash();
    let parent = provider
        .header(parent_hash)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("missing canonical parent {parent_hash} after pure revert"))?;
    if parent.number.checked_add(1) != Some(first_reverted.number()) {
        return Err(format!(
            "pure revert parent height mismatch: parent {}, first reverted {}",
            parent.number,
            first_reverted.number()
        ))
    }
    Ok((parent_hash, parent, None))
}

#[cfg(test)]
mod tests {
    use super::{
        activate_dbft_round, authoritative_canonical_status, cache_future_dbft_message,
        canonical_notification_tip, drain_cached_dbft_messages, enqueue_propagated_block,
        future_messages::FutureDbftMessages, is_future_dbft_message,
        is_future_view_dbft_transition, is_stale_dbft_transition, optimistic_sync_target_state,
        peer_status_backfill_target, propagated_block_backfill_target,
        propagated_block_disposition, proposal_rejection_reason, publish_local_change_view,
        recovery_response_allowed, resolve_canonical_notification, timer::DbftTimer,
        DbftActivationStateProvider, DescendantSyncTarget, DescendantSyncTargetSubmission,
        DescendantSyncTargets, PropagatedBlockDisposition, DESCENDANT_SYNC_TARGET_MAX_REQUESTS,
        DESCENDANT_SYNC_TARGET_RETRY_INTERVAL, PROPAGATED_BLOCK_QUEUE_CAPACITY,
    };
    use crate::{
        metrics::NeoXSyncMetrics, DbftProposalError, DbftRoundState, DbftSigner, DbftStateError,
    };
    use alloy_consensus::Header;
    use alloy_eips::eip2124::{ForkHash, ForkId};
    use alloy_primitives::{hex, keccak256, Address, B256, B512, U256};
    use reth_chain_state::CanonStateNotification;
    use reth_ethereum_primitives::{Block, EthPrimitives};
    use reth_execution_types::Chain;
    use reth_neox_chainspec::NeoXChainSpec;
    use reth_neox_evm::{
        dynamic_array_element_storage_key, uint_mapping_storage_key,
        GOVERNANCE_CURRENT_CONSENSUS_SLOT, GOVERNANCE_PROXY_ADDRESS,
        KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, KEY_MANAGEMENT_PROXY_ADDRESS,
        KEY_MANAGEMENT_ROUND_NUMBER_SLOT,
    };
    use reth_neox_network::{
        BeaconLocalStatus, BeaconVersion, DbftChangeViewReason, DbftDecodedPayload,
        DbftMessageType, DbftProtocol, NewBlockPacket,
    };
    use reth_primitives_traits::RecoveredBlock;
    use reth_provider::{
        test_utils::{ExtendedAccount, MockEthProvider},
        StateProviderBox,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    #[derive(Debug)]
    struct HashPinnedActivationProvider {
        states: HashMap<B256, MockEthProvider<EthPrimitives>>,
        requested: Mutex<Vec<B256>>,
    }

    impl DbftActivationStateProvider for HashPinnedActivationProvider {
        fn activation_state_by_block_hash(
            &self,
            block_hash: B256,
        ) -> Result<StateProviderBox, String> {
            self.requested.lock().unwrap().push(block_hash);
            self.states
                .get(&block_hash)
                .cloned()
                .map(|state| Box::new(state) as StateProviderBox)
                .ok_or_else(|| format!("missing test state for {block_hash}"))
        }
    }

    fn governance_state(seed: u8) -> (MockEthProvider<EthPrimitives>, Vec<Address>) {
        let validators = (0..7).map(|index| Address::repeat_byte(seed + index)).collect::<Vec<_>>();
        let mut storage = vec![(
            U256::from(GOVERNANCE_CURRENT_CONSENSUS_SLOT).into(),
            U256::from(validators.len()),
        )];
        storage.extend(validators.iter().enumerate().map(|(index, validator)| {
            (
                dynamic_array_element_storage_key(GOVERNANCE_CURRENT_CONSENSUS_SLOT, index as u64)
                    .into(),
                U256::from_be_slice(validator.as_slice()),
            )
        }));
        let provider = MockEthProvider::<EthPrimitives>::new();
        provider.add_account(
            GOVERNANCE_PROXY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
        );
        (provider, validators)
    }

    fn install_dkg_state(provider: &MockEthProvider<EthPrimitives>, round: u64) {
        let commitment = hex!(
            "0000000000000000000000000000000014c3bd13c1d7fcf70d288e1be25e5fed"
            "75ecd9de009614311862bf53a630de41b688d3dc2dd8ab6418b7ff74d16e1d31"
            "0000000000000000000000000000000011172e2b1d5f21c54ba685ff04703657"
            "f74630886044a3b8884c5a2077fa0776da2cc1a4dbdfa64dd1092bcb0c3fe192"
        );
        let mapping_slot =
            uint_mapping_storage_key(KEY_MANAGEMENT_AGGREGATED_COMMITMENTS_SLOT, U256::from(round));
        let data_base = U256::from_be_bytes(keccak256(mapping_slot.to_be_bytes::<32>()).0);
        let mut storage = vec![
            (U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into(), U256::from(round)),
            (mapping_slot.into(), U256::from(commitment.len() * 2 + 1)),
        ];
        storage.extend(commitment.as_chunks::<32>().0.iter().enumerate().map(|(index, word)| {
            (data_base.wrapping_add(U256::from(index)).into(), U256::from_be_slice(word))
        }));
        provider.add_account(
            KEY_MANAGEMENT_PROXY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
        );
    }

    fn canonical_headers(
        provider: &MockEthProvider<EthPrimitives>,
        difficulties: &[u64],
    ) -> Vec<(B256, Header)> {
        let mut parent_hash = B256::ZERO;
        difficulties
            .iter()
            .enumerate()
            .map(|(number, difficulty)| {
                let header = Header {
                    parent_hash,
                    number: number as u64,
                    timestamp: 1_000 + number as u64,
                    difficulty: U256::from(*difficulty),
                    ..Default::default()
                };
                let hash = header.hash_slow();
                provider.add_header(hash, header.clone());
                parent_hash = hash;
                (hash, header)
            })
            .collect()
    }

    fn beacon_status(head: B256, head_number: u64, total_difficulty: u64) -> BeaconLocalStatus {
        BeaconLocalStatus {
            network_id: 47_763,
            total_difficulty: U256::from(total_difficulty),
            head,
            head_number,
            head_timestamp: 1_000 + head_number,
            genesis: B256::ZERO,
            blob_sync: true,
        }
    }

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
    fn authenticated_future_dbft_messages_wait_for_canonical_backfill() {
        assert!(is_future_dbft_message(1, 7_177_710));
        assert!(!is_future_dbft_message(1, 1));
        assert!(!is_future_dbft_message(1, 0));
    }

    #[test]
    fn only_ahead_v2_peer_status_requests_canonical_descendant_backfill() {
        let local_hash = B256::repeat_byte(0x41);
        let remote_hash = B256::repeat_byte(0x42);
        let local = beacon_status(local_hash, 10, 16);
        let fork_id = ForkId { hash: ForkHash([1, 2, 3, 4]), next: 0 };
        let ahead = beacon_status(remote_hash, 11, 17);

        assert_eq!(
            peer_status_backfill_target(ahead.wire_status(BeaconVersion::V2, fork_id), local),
            Some(DescendantSyncTarget { hash: remote_hash, number: 11 })
        );
        assert_eq!(
            peer_status_backfill_target(
                beacon_status(remote_hash, 10, 17).wire_status(BeaconVersion::V2, fork_id),
                local,
            ),
            None
        );
        assert_eq!(
            peer_status_backfill_target(
                beacon_status(remote_hash, 9, 15).wire_status(BeaconVersion::V2, fork_id),
                local,
            ),
            None
        );
        assert_eq!(
            peer_status_backfill_target(ahead.wire_status(BeaconVersion::V1, fork_id), local),
            None
        );
    }

    #[test]
    fn descendant_backfill_fcu_leaves_safe_and_finalized_unset() {
        let head = B256::repeat_byte(0x51);
        let state = optimistic_sync_target_state(head);

        assert_eq!(state.head_block_hash, head);
        assert_eq!(state.safe_block_hash, B256::ZERO);
        assert_eq!(state.finalized_block_hash, B256::ZERO);
    }

    #[test]
    fn propagated_large_gap_coalesces_through_descendant_scheduler() {
        let now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let source = B512::repeat_byte(0x31);
        let packet = |number| NewBlockPacket {
            block: Block {
                header: Header {
                    parent_hash: B256::repeat_byte((number % 251) as u8),
                    number,
                    difficulty: U256::from(1),
                    ..Default::default()
                },
                body: Default::default(),
            },
            total_difficulty: U256::from(number + 1),
        };
        let mut targets = DescendantSyncTargets::default();

        let first_target = propagated_block_backfill_target(&packet(5_000), local).unwrap();
        let first_request = targets.observe(source, first_target, local, now).unwrap();
        let mut latest_target = first_target;
        for number in [6_000, 7_000, 8_000] {
            latest_target = propagated_block_backfill_target(&packet(number), local).unwrap();
            assert!(targets.observe(source, latest_target, local, now).is_none());
        }

        assert_eq!(targets.requests, 1);
        assert_eq!(targets.in_flight, Some(first_request));
        assert_eq!(targets.claims.get(&source), Some(&latest_target));
        assert_eq!(targets.pending.len(), 1);
        assert_eq!(targets.pending.front().unwrap().target, latest_target);
    }

    #[test]
    fn pending_descendant_target_retries_with_latest_canonical_anchor() {
        let now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let target = DescendantSyncTarget { hash: B256::repeat_byte(0x51), number: 20 };
        let source = B512::repeat_byte(0x31);
        let mut targets = DescendantSyncTargets::default();

        let initial = targets.observe(source, target, local, now).unwrap();
        assert_eq!(initial.target, target);
        assert_eq!(initial.anchor.hash, local.head);
        assert_eq!(initial.anchor.number, local.head_number);
        assert!(targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL).is_none());
        assert!(targets
            .complete(initial, DescendantSyncTargetSubmission::Pending, local, now)
            .is_none());
        assert!(targets
            .retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL - Duration::from_millis(1))
            .is_none());

        let advanced = beacon_status(B256::repeat_byte(0x42), 11, 17);
        let retry = targets.retry(advanced, now + Duration::from_millis(1)).unwrap();
        assert_eq!(retry.target, target);
        assert_eq!(retry.anchor.hash, advanced.head);
        assert_eq!(retry.anchor.number, advanced.head_number);
        assert_eq!(targets.requests, 1, "canonical progress replenishes the anchor budget");

        let reached = beacon_status(B256::repeat_byte(0x43), target.number, 26);
        assert!(targets
            .complete(retry, DescendantSyncTargetSubmission::Pending, reached, now)
            .is_none());
        assert!(targets.pending.is_empty());
        assert!(targets.claims.is_empty());
    }

    #[test]
    fn alternating_source_cannot_race_an_honest_new_target() {
        let now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let attacker = B512::repeat_byte(0x31);
        let honest = B512::repeat_byte(0x32);
        let first = DescendantSyncTarget { hash: B256::repeat_byte(0x51), number: u64::MAX };
        let rotated = DescendantSyncTarget { hash: B256::repeat_byte(0x52), number: u64::MAX };
        let honest_target = DescendantSyncTarget { hash: B256::repeat_byte(0x61), number: 20 };
        let mut targets = DescendantSyncTargets::default();

        let first_request = targets.observe(attacker, first, local, now).unwrap();
        assert!(targets.observe(attacker, rotated, local, now).is_none());
        assert!(targets.observe(honest, honest_target, local, now).is_none());
        assert_eq!(targets.requests, 1);
        assert_eq!(targets.claims.get(&attacker), Some(&rotated));
        assert_eq!(targets.claims.get(&honest), Some(&honest_target));

        assert!(targets
            .complete(first_request, DescendantSyncTargetSubmission::Pending, local, now)
            .is_none());
        let honest_request =
            targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL).unwrap();
        assert_eq!(honest_request.target, honest_target);
        assert_eq!(targets.requests, 2);

        assert!(targets
            .complete(
                honest_request,
                DescendantSyncTargetSubmission::Pending,
                local,
                now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL,
            )
            .is_none());
        let attacker_retry =
            targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL * 2).unwrap();
        assert_eq!(attacker_retry.target, rotated);
    }

    #[test]
    fn alternating_hashes_share_one_anchor_budget_and_cooldown() {
        let mut now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let source = B512::repeat_byte(0x31);
        let mut targets = DescendantSyncTargets::default();

        let mut request = targets
            .observe(
                source,
                DescendantSyncTarget { hash: B256::repeat_byte(1), number: u64::MAX },
                local,
                now,
            )
            .unwrap();
        for _ in 1..DESCENDANT_SYNC_TARGET_MAX_REQUESTS {
            assert!(targets
                .complete(request, DescendantSyncTargetSubmission::Pending, local, now)
                .is_none());
            let rotated = DescendantSyncTarget {
                hash: B256::repeat_byte((targets.requests as u8).wrapping_add(1)),
                number: u64::MAX,
            };
            assert!(targets.observe(source, rotated, local, now).is_none());
            now += DESCENDANT_SYNC_TARGET_RETRY_INTERVAL;
            request = targets.retry(local, now).unwrap();
            assert_eq!(request.target, rotated);
        }
        assert_eq!(targets.requests, DESCENDANT_SYNC_TARGET_MAX_REQUESTS);
        assert!(targets.pending.is_empty(), "exhausted hints must leave no schedulable entry");
        assert!(targets
            .complete(request, DescendantSyncTargetSubmission::Pending, local, now)
            .is_none());

        now += DESCENDANT_SYNC_TARGET_RETRY_INTERVAL;
        assert!(targets.retry(local, now).is_none());
        let final_rotation =
            DescendantSyncTarget { hash: B256::repeat_byte(0xfe), number: u64::MAX };
        assert!(targets.observe(source, final_rotation, local, now).is_none());
        assert!(targets.pending.is_empty());

        let advanced = beacon_status(B256::repeat_byte(0x42), 11, 17);
        let renewed = targets.retry(advanced, now).unwrap();
        assert_eq!(renewed.target, final_rotation);
        assert_eq!(targets.requests, 1);
    }

    #[test]
    fn disconnect_clears_source_and_stale_completion_cannot_clear_honest_target() {
        let now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let disconnected = B512::repeat_byte(0x31);
        let honest = B512::repeat_byte(0x32);
        let stale_target = DescendantSyncTarget { hash: B256::repeat_byte(0x51), number: 20 };
        let honest_target = DescendantSyncTarget { hash: B256::repeat_byte(0x61), number: 21 };
        let mut targets = DescendantSyncTargets::default();

        let stale_request = targets.observe(disconnected, stale_target, local, now).unwrap();
        assert!(targets.observe(honest, honest_target, local, now).is_none());
        targets.disconnect(disconnected);
        assert!(!targets.claims.contains_key(&disconnected));
        assert_eq!(targets.claims.get(&honest), Some(&honest_target));
        assert!(targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL).is_none());

        let honest_request = targets
            .complete(
                stale_request,
                DescendantSyncTargetSubmission::Valid,
                local,
                now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL,
            )
            .unwrap();
        assert_eq!(honest_request.target, honest_target);

        targets.disconnect(honest);
        assert!(targets.claims.is_empty());
        assert!(targets.pending.is_empty());
        assert!(targets
            .complete(
                honest_request,
                DescendantSyncTargetSubmission::Pending,
                local,
                now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL,
            )
            .is_none());
        assert!(targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL * 2).is_none());
    }

    #[test]
    fn terminal_valid_retires_target_and_only_one_submission_can_be_in_flight() {
        let now = Instant::now();
        let local = beacon_status(B256::repeat_byte(0x41), 10, 16);
        let first_source = B512::repeat_byte(0x31);
        let second_source = B512::repeat_byte(0x32);
        let same_hash_source = B512::repeat_byte(0x33);
        let first = DescendantSyncTarget { hash: B256::repeat_byte(0x51), number: 20 };
        let renumbered_first = DescendantSyncTarget { hash: first.hash, number: 99 };
        let second = DescendantSyncTarget { hash: B256::repeat_byte(0x52), number: 21 };
        let mut targets = DescendantSyncTargets::default();

        let request = targets.observe(first_source, first, local, now).unwrap();
        assert!(targets.observe(first_source, renumbered_first, local, now).is_none());
        assert!(targets.observe(same_hash_source, first, local, now).is_none());
        assert!(targets.observe(second_source, second, local, now).is_none());
        assert_eq!(targets.pending.len(), 2, "one hash is one FCU target");
        assert!(targets.retry(local, now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL).is_none());
        assert_eq!(targets.in_flight, Some(request));

        let next = targets
            .complete(
                request,
                DescendantSyncTargetSubmission::Valid,
                local,
                now + DESCENDANT_SYNC_TARGET_RETRY_INTERVAL,
            )
            .unwrap();
        assert_eq!(next.target, second);
        assert!(!targets.claims.values().any(|target| *target == first));
        assert!(!targets.claims.values().any(|target| target.hash == first.hash));
        assert!(targets.terminal_hashes.contains(&first.hash));
        assert_eq!(targets.in_flight, Some(next));

        assert!(targets.observe(first_source, renumbered_first, local, now).is_none());
        assert!(!targets.claims.contains_key(&first_source));

        let advanced = beacon_status(B256::repeat_byte(0x42), 11, 17);
        targets.reconcile(advanced);
        assert!(!targets.terminal_hashes.contains(&first.hash));
        assert!(targets.observe(first_source, renumbered_first, advanced, now).is_none());
        assert_eq!(targets.claims.get(&first_source), Some(&renumbered_first));
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
    fn defers_and_replays_messages_the_round_cannot_accept_yet() {
        // The reference client caches a message from a future height or view and replays it once it
        // reaches that round, so a validator briefly behind on canonical state does not lose the
        // whole quorum for the next height and have to recover it after a view timeout.
        let signer = DbftSigner::from_secret(&B256::repeat_byte(0x11).0).unwrap();
        let peer = B512::repeat_byte(0x31);
        let metrics = NeoXSyncMetrics::default();
        let mut cache = FutureDbftMessages::default();
        let commit = Arc::new(
            signer
                .sign_message(
                    43,
                    0,
                    0,
                    DbftMessageType::Commit,
                    &alloy_primitives::Bytes::from_static(&[0x02; 65]),
                )
                .unwrap(),
        );
        let recovery = Arc::new(
            signer
                .sign_message(
                    43,
                    0,
                    0,
                    DbftMessageType::RecoveryRequest,
                    &alloy_primitives::Bytes::new(),
                )
                .unwrap(),
        );

        assert!(is_future_dbft_message(42, commit.valid_block_end));
        assert!(cache_future_dbft_message(&mut cache, peer, &commit, &metrics));
        // Recovery control messages are not cached, matching the reference client.
        assert!(!cache_future_dbft_message(&mut cache, peer, &recovery, &metrics));

        // The height the round left behind is never asked for again.
        assert!(drain_cached_dbft_messages(&mut cache, 42, &metrics).is_empty());
        let replayed = drain_cached_dbft_messages(&mut cache, 43, &metrics);
        assert_eq!(replayed, vec![(peer, commit)]);
        assert!(drain_cached_dbft_messages(&mut cache, 43, &metrics).is_empty());
    }

    #[test]
    fn only_a_later_view_defers_a_refused_transition() {
        // A view above the round's is cached and replayed; one below it is stale and stays refused.
        assert!(is_future_view_dbft_transition(&DbftStateError::WrongView {
            expected: 1,
            actual: 2
        }));
        assert!(!is_future_view_dbft_transition(&DbftStateError::WrongView {
            expected: 2,
            actual: 1
        }));
        assert!(!is_future_view_dbft_transition(&DbftStateError::WrongHeight {
            expected: 2,
            start: 0,
            end: 1
        }));
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
        let (mut timer, _timeouts) = DbftTimer::channel(Duration::from_secs(5));

        let outcome = publish_local_change_view(
            &mut round,
            Some(&signers[0]),
            &dbft,
            DbftChangeViewReason::TransactionInvalid,
            &mut timer,
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
    fn only_a_direct_canonical_child_can_be_finalized_from_propagation() {
        let canonical_hash = B256::repeat_byte(0x41);
        let canonical = beacon_status(canonical_hash, 10, 16);
        let direct_child = Header { parent_hash: canonical_hash, number: 11, ..Default::default() };
        let adversarial_fork =
            Header { parent_hash: B256::repeat_byte(0x99), number: 11, ..Default::default() };
        let gap =
            Header { parent_hash: direct_child.hash_slow(), number: 12, ..Default::default() };
        let finalized_height = Header { number: 10, ..Default::default() };

        assert_eq!(
            propagated_block_disposition(&direct_child, canonical),
            PropagatedBlockDisposition::DirectChild
        );
        assert_eq!(
            propagated_block_disposition(&adversarial_fork, canonical),
            PropagatedBlockDisposition::CompetingFinalized
        );
        assert_eq!(propagated_block_disposition(&gap, canonical), PropagatedBlockDisposition::Gap);
        assert_eq!(
            propagated_block_disposition(&finalized_height, canonical),
            PropagatedBlockDisposition::CompetingFinalized
        );
    }

    #[test]
    fn propagated_block_queue_is_strictly_bounded() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(PROPAGATED_BLOCK_QUEUE_CAPACITY);
        let packet = |number| NewBlockPacket {
            block: Block {
                header: Header { number, ..Default::default() },
                body: Default::default(),
            },
            total_difficulty: U256::from(number),
        };
        let peer = B512::repeat_byte(0x11);
        assert!(enqueue_propagated_block(&sender, peer, packet(1)));
        assert!(enqueue_propagated_block(&sender, peer, packet(2)));
        assert!(!enqueue_propagated_block(&sender, peer, packet(3)));
    }

    #[test]
    fn dbft_activation_uses_the_notified_head_state_snapshot() {
        let notified_hash = B256::repeat_byte(0x41);
        let newer_hash = B256::repeat_byte(0x42);
        let (notified_state, mut notified_validators) = governance_state(1);
        let (newer_state, newer_validators) = governance_state(21);
        install_dkg_state(&notified_state, 88);
        install_dkg_state(&newer_state, 89);
        let provider = HashPinnedActivationProvider {
            states: HashMap::from([(notified_hash, notified_state), (newer_hash, newer_state)]),
            requested: Mutex::new(Vec::new()),
        };
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let canonical_height = 3_749_760;
        let (dbft, _events) = DbftProtocol::new(canonical_height);
        let mut round = None;

        // Simulate handling a queued notification after state for a newer head already exists.
        activate_dbft_round(
            canonical_height,
            notified_hash,
            &provider,
            &dbft,
            chain_spec.as_ref(),
            None,
            &mut round,
        );

        notified_validators.sort_unstable();
        assert_eq!(provider.requested.lock().unwrap().as_slice(), &[notified_hash]);
        assert_eq!(round.as_ref().unwrap().validators(), notified_validators);
        assert_ne!(round.as_ref().unwrap().validators(), newer_validators);
        assert_eq!(round.as_ref().unwrap().dkg_state().unwrap().current.round, 88);
    }

    #[test]
    fn authoritative_status_repairs_a_stale_startup_seed() {
        let provider = MockEthProvider::<EthPrimitives>::new();
        let headers = canonical_headers(&provider, &[1, 2, 1]);
        let seed = beacon_status(headers[0].0, 0, 0);
        let chain_spec = NeoXChainSpec::mainnet().unwrap();

        let status =
            authoritative_canonical_status(&provider, seed, chain_spec.as_ref(), false).unwrap();

        assert_eq!(status.head, headers[2].0);
        assert_eq!(status.head_number, 2);
        assert_eq!(status.total_difficulty, U256::from(4));
        assert_eq!(status.head_timestamp, headers[2].1.timestamp);
    }

    #[test]
    fn skipped_commit_reconciliation_uses_provider_td_and_latest_head() {
        let provider = MockEthProvider::<EthPrimitives>::new();
        let headers = canonical_headers(&provider, &[1, 2, 1, 2, 1]);
        let skipped = RecoveredBlock::new_unhashed(
            Block { header: headers[3].1.clone(), body: Default::default() },
            Vec::new(),
        );
        let notification = CanonStateNotification::Commit {
            new: Arc::new(Chain::new([skipped], Default::default(), Default::default())),
        };
        let seed = beacon_status(headers[0].0, 0, 1);
        let chain_spec = NeoXChainSpec::mainnet().unwrap();

        let resolution =
            resolve_canonical_notification(&notification, &provider, seed, chain_spec.as_ref())
                .unwrap();

        assert_eq!(resolution.notification_tip, headers[3].0);
        assert_eq!(resolution.status.head, headers[4].0);
        assert_eq!(resolution.status.head_number, 4);
        assert_eq!(resolution.status.total_difficulty, U256::from(7));
        assert!(resolution.propagated_block.is_none());
    }

    #[test]
    fn pure_revert_resolves_the_parent_as_the_new_canonical_tip() {
        let parent_hash = B256::repeat_byte(0x22);
        let parent = Header { number: 41, timestamp: 1234, ..Default::default() };
        let provider = MockEthProvider::<EthPrimitives>::new();
        provider.add_header(parent_hash, parent.clone());
        let reverted = RecoveredBlock::new_unhashed(
            Block {
                header: Header { parent_hash, number: 42, timestamp: 1235, ..Default::default() },
                body: Default::default(),
            },
            Vec::new(),
        );
        let notification = CanonStateNotification::Reorg {
            old: Arc::new(Chain::new([reverted], Default::default(), Default::default())),
            new: Arc::new(Chain::default()),
        };

        let (hash, header, propagated) =
            canonical_notification_tip(&notification, &provider).unwrap();
        assert_eq!(hash, parent_hash);
        assert_eq!(header, parent);
        assert!(propagated.is_none());
    }
}
