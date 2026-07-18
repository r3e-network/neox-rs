//! Neo X beacon-to-engine synchronization and canonical block propagation.

use crate::{read_governance_validators, DbftRoundProgress, DbftRoundState};
use alloy_eips::eip4844::env_settings::EnvKzgSettings;
use alloy_primitives::{B256, B512, U256};
use alloy_rpc_types_engine::ForkchoiceState;
use futures::StreamExt;
use reth_chain_state::{CanonStateNotification, CanonStateNotificationStream};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_engine_primitives::{EthEngineTypes, EthPayloadTypes};
use reth_ethereum_primitives::{Block, EthPrimitives, PooledTransactionVariant, TransactionSigned};
use reth_neox_chainspec::{NeoXChainSpec, NEOX_VALIDATOR_COUNT};
use reth_neox_network::{
    block_hash_announcement, transactions_response, BatchBlobs, BeaconBlobSidecar, BeaconCommand,
    BeaconEvent, BeaconLocalStatus, BeaconProtocol, BeaconStatus, Blobs, DbftEvent, DbftProtocol,
    GetBatchBlobs, GetBlobs, NeoXSidecarStore, NewBlobsRoot, NewBlockPacket,
};
use reth_node_api::PayloadTypes;
use reth_primitives_traits::{AlloyBlockHeader, Block as _, SealedBlock};
use reth_provider::{BlockReader, StateProviderFactory};
use reth_transaction_pool::{GetPooledTransactionLimit, PoolTransaction, TransactionPool};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
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
    Provider: BlockReader<Block = Block> + StateProviderFactory + Clone + Sync + 'static,
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
        sidecar_store,
    } = context;
    let mut sidecars = SidecarSync::new(sidecar_store);
    let mut dbft_round = None;
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    warn!(target: "neox::sync", "Neo X beacon event channel closed");
                    return
                };
                sidecars.expire_requests();
                handle_beacon_event(event, BeaconEventContext {
                    beacon: &beacon,
                    engine: &engine,
                    pool: &pool,
                    provider: &provider,
                    sidecars: &mut sidecars,
                    dbft: &dbft,
                    chain_spec: &chain_spec,
                    dbft_round: &mut dbft_round,
                }).await;
            }
            event = dbft_events.recv() => {
                let Some(event) = event else {
                    warn!(target: "neox::sync", "Neo X dBFT event channel closed");
                    return
                };
                handle_dbft_event(event, dbft_round.as_mut());
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

                let number = tip.number();
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
                } else {
                    activate_dbft_round(
                        number,
                        &provider,
                        &dbft,
                        &chain_spec,
                        &mut dbft_round,
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

fn handle_dbft_event(event: DbftEvent, round: Option<&mut DbftRoundState>) {
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
            match round.process(message) {
                Ok(DbftRoundProgress::Duplicate | DbftRoundProgress::Accepted) => {}
                Ok(progress @ DbftRoundProgress::Prepared { .. }) => {
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached preparation quorum");
                }
                Ok(progress @ DbftRoundProgress::PreCommitted { .. }) => {
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached Anti-MEV share quorum");
                }
                Ok(progress @ DbftRoundProgress::Committed { .. }) => {
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT proposal reached commit quorum");
                }
                Ok(progress @ DbftRoundProgress::ViewChanged { .. }) => {
                    info!(target: "neox::validator", %peer_id, ?progress, "Neo X dBFT round changed view");
                }
                Err(error) => {
                    warn!(target: "neox::validator", %peer_id, %error, "Rejected invalid Neo X dBFT state transition");
                }
            }
        }
        DbftEvent::Violation { peer_id, reason } => {
            warn!(target: "neox::sync", %peer_id, ?reason, "Rejected invalid Neo X dbft/0 peer message");
        }
    }
}

fn activate_dbft_round<Provider>(
    canonical_height: u64,
    provider: &Provider,
    dbft: &DbftProtocol,
    chain_spec: &NeoXChainSpec,
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
    let result = provider
        .latest()
        .map_err(|error| error.to_string())
        .and_then(|state| {
            read_governance_validators(state.as_ref()).map_err(|error| error.to_string())
        })
        .and_then(|validators| {
            dbft.activate(canonical_height, validators.clone())
                .map_err(|error| format!("{error:?}"))?;
            DbftRoundState::new(
                next_height,
                validators,
                chain_spec.is_anti_mev_active_at_block(next_height),
            )
            .map_err(|error| error.to_string())
        });
    match result {
        Ok(next_round) => {
            info!(
                target: "neox::validator",
                canonical_height,
                next_height,
                validators = NEOX_VALIDATOR_COUNT,
                "Activated Neo X dBFT round from Governance state"
            );
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
    chain_spec: &'a NeoXChainSpec,
    dbft_round: &'a mut Option<DbftRoundState>,
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
    >,
    Provider: BlockReader<Block = Block> + StateProviderFactory + Sync,
{
    let BeaconEventContext {
        beacon,
        engine,
        pool,
        provider,
        sidecars,
        dbft,
        chain_spec,
        dbft_round,
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
                debug!(target: "neox::validator", "Disabled dBFT admission while Neo X backfill is active");
                if remote_is_ahead {
                    request_sync_target(engine, status.head()).await;
                }
            } else {
                activate_dbft_round(local.head_number, provider, dbft, chain_spec, dbft_round);
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
            import_propagated_block(peer_id, *packet, engine).await;
        }
        BeaconEvent::GetTransactions { peer_id, request } => {
            let request_id = request.request_id;
            let transactions = pool
                .get_pooled_transaction_elements(
                    request.message.0,
                    GetPooledTransactionLimit::ResponseSizeSoftLimit(
                        TRANSACTION_RESPONSE_SOFT_LIMIT,
                    ),
                )
                .into_iter()
                .map(<Pool::Transaction as PoolTransaction>::pooled_into_consensus)
                .collect();
            let response = transactions_response(request_id, transactions);
            if !beacon.send(peer_id, BeaconCommand::Transactions(response)) {
                debug!(target: "neox::sync", %peer_id, request_id, "Beacon peer disconnected before transaction response");
            }
        }
        BeaconEvent::Transactions { peer_id, response } => {
            debug!(target: "neox::sync", %peer_id, request_id = response.request_id, count = response.message.0.len(), "Received beacon transaction response");
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
            if !network_is_ahead {
                activate_dbft_round(local.head_number, provider, dbft, chain_spec, dbft_round);
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

async fn import_propagated_block(
    peer_id: alloy_primitives::B512,
    packet: NewBlockPacket,
    engine: &ConsensusEngineHandle<EthEngineTypes>,
) {
    let number = packet.block.header.number;
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
