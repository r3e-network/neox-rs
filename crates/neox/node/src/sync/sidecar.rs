//! Finalized Neo X blob-sidecar synchronization state and validation.

use alloy_eips::eip4844::{env_settings::EnvKzgSettings, BlobTransactionValidationError};
use alloy_primitives::{B256, B512};
use reth_ethereum_primitives::{Block, EthPrimitives, PooledTransactionVariant, TransactionSigned};
use reth_neox_network::{
    BatchBlobs, BeaconBlobSidecar, BeaconCommand, BeaconProtocol, BeaconStatus, Blobs,
    GetBatchBlobs, GetBlobs, NeoXSidecarStore, NewBlobsRoot, MAX_BLOB_REQUEST_TTL,
};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::BlockReader;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, info, warn};

const SIDECAR_RESPONSE_SOFT_LIMIT: usize = 5 * 1024 * 1024;
const SIDECAR_BATCH_BLOCK_LIMIT: usize = 16;
const SIDECAR_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const SIDECAR_RETAINED_BLOCK_WINDOW: u64 = 8_192 * 32;
const SIDECAR_RETRY_QUEUE_LIMIT: usize = 256;

#[derive(Debug)]
pub(super) struct SidecarSync {
    store: NeoXSidecarStore,
    peers: HashMap<B512, BeaconStatus>,
    pending: HashMap<u64, PendingSidecarRequest>,
    retries: VecDeque<SidecarRetry>,
    next_request_id: u64,
}

#[derive(Debug)]
enum PendingSidecarRequest {
    Single {
        peer_id: B512,
        block_hash: B256,
        ttl: u8,
        forwarded_for: Option<(B512, u64)>,
        failed_peers: HashSet<B512>,
        requested_at: Instant,
    },
    Batch {
        peer_id: B512,
        block_hashes: Vec<B256>,
        failed_peers: HashSet<B512>,
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

    fn into_retry(self) -> SidecarRetry {
        match self {
            Self::Single { peer_id, block_hash, ttl, forwarded_for, mut failed_peers, .. } => {
                failed_peers.insert(peer_id);
                SidecarRetry::Single {
                    preferred_peer: None,
                    block_hash,
                    ttl,
                    forwarded_for,
                    failed_peers,
                }
            }
            Self::Batch { peer_id, block_hashes, mut failed_peers, .. } => {
                failed_peers.insert(peer_id);
                SidecarRetry::Batch { preferred_peer: None, block_hashes, failed_peers }
            }
        }
    }
}

#[derive(Debug)]
enum SidecarRetry {
    Single {
        preferred_peer: Option<B512>,
        block_hash: B256,
        ttl: u8,
        forwarded_for: Option<(B512, u64)>,
        failed_peers: HashSet<B512>,
    },
    Batch {
        preferred_peer: Option<B512>,
        block_hashes: Vec<B256>,
        failed_peers: HashSet<B512>,
    },
}

impl SidecarRetry {
    fn contains_block(&self, block_hash: B256) -> bool {
        match self {
            Self::Single { block_hash: pending, .. } => *pending == block_hash,
            Self::Batch { block_hashes, .. } => block_hashes.contains(&block_hash),
        }
    }

    fn reopen_exhausted_peer_cycle(&mut self, peers: &HashMap<B512, BeaconStatus>) {
        match self {
            Self::Single { forwarded_for, failed_peers, .. } => {
                if !peers.is_empty() && peers.keys().all(|peer_id| failed_peers.contains(peer_id)) {
                    failed_peers.clear();
                    if let Some((requester, _)) = forwarded_for {
                        failed_peers.insert(*requester);
                    }
                }
            }
            Self::Batch { failed_peers, .. } => {
                if !peers.is_empty() && peers.keys().all(|peer_id| failed_peers.contains(peer_id)) {
                    failed_peers.clear();
                }
            }
        }
    }
}

fn choose_sidecar_peer(
    peers: &HashMap<B512, BeaconStatus>,
    preferred: Option<B512>,
    failed_peers: &HashSet<B512>,
) -> Option<B512> {
    preferred
        .filter(|peer_id| peers.contains_key(peer_id) && !failed_peers.contains(peer_id))
        .or_else(|| {
            peers
                .iter()
                .find(|(peer_id, status)| !failed_peers.contains(*peer_id) && status.blob_sync())
                .map(|(peer_id, _)| *peer_id)
        })
        .or_else(|| peers.keys().find(|peer_id| !failed_peers.contains(*peer_id)).copied())
}

const fn batch_response_penalizes_peer(received: usize, invalid_blocks: usize) -> bool {
    received == 0 || invalid_blocks != 0
}

/// Whether an inbound `GetBlobs` TTL is in the range Neo X Geth accepts.
///
/// The oracle rejects only `Ttl == 0`; every non-zero `uint8` value is accepted by the wire
/// handler.
const fn sidecar_request_ttl_in_range(ttl: u8) -> bool {
    ttl != 0
}

fn retry_missing_batch(
    peer_id: B512,
    requested: &[B256],
    received: usize,
    mut missing: Vec<B256>,
    mut failed_peers: HashSet<B512>,
) -> Option<SidecarRetry> {
    let invalid_blocks = missing.len();
    missing.extend_from_slice(requested.get(received..).unwrap_or_default());
    if missing.is_empty() {
        return None
    }
    if batch_response_penalizes_peer(received, invalid_blocks) {
        failed_peers.insert(peer_id);
    }
    Some(SidecarRetry::Batch { preferred_peer: None, block_hashes: missing, failed_peers })
}

impl SidecarSync {
    pub(super) fn new(store: NeoXSidecarStore) -> Self {
        info!(target: "neox::sync", path = %store.root().display(), "Neo X finalized sidecar store initialized");
        Self {
            store,
            peers: HashMap::new(),
            pending: HashMap::new(),
            retries: VecDeque::new(),
            next_request_id: 1,
        }
    }

    /// Records a connected peer's latest status.
    pub(super) fn connect_peer(&mut self, peer_id: B512, status: BeaconStatus) {
        self.peers.insert(peer_id, status);
    }

    /// Removes a disconnected peer and fails over every sidecar request assigned to it.
    pub(super) fn disconnect_peer(&mut self, peer_id: B512, beacon: &BeaconProtocol) {
        self.peers.remove(&peer_id);
        let failed_ids = self
            .pending
            .iter()
            .filter_map(|(request_id, request)| {
                (request.peer_id() == peer_id).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in failed_ids {
            if let Some(request) = self.pending.remove(&request_id) {
                self.dispatch_retry(request.into_retry(), beacon);
            }
        }
    }

    pub(super) fn expire_requests(&mut self, beacon: &BeaconProtocol) {
        let expired_ids = self
            .pending
            .iter()
            .filter_map(|(request_id, request)| {
                let expired = request.requested_at().elapsed() >= SIDECAR_REQUEST_TIMEOUT;
                if expired {
                    debug!(target: "neox::sync", request_id, peer_id = %request.peer_id(), "Neo X sidecar request timed out");
                }
                expired.then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in expired_ids {
            if let Some(request) = self.pending.remove(&request_id) {
                self.dispatch_retry(request.into_retry(), beacon);
            }
        }
        self.drain_retries(beacon);
    }

    pub(super) fn archive_chain<Pool>(
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
        if chain.is_empty() {
            return
        }
        let retained_floor = chain.tip().number().saturating_sub(SIDECAR_RETAINED_BLOCK_WINDOW);
        let mut missing = Vec::new();

        for recovered in chain.blocks_iter() {
            if recovered.number() < retained_floor {
                continue;
            }
            let tx_hashes = blob_transaction_hashes(recovered.body());
            if tx_hashes.is_empty() {
                continue;
            }
            let block_hash = recovered.hash();
            match self.store.contains(block_hash) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    warn!(target: "neox::sync", %block_hash, %error, "Failed to inspect Neo X sidecar store");
                    continue;
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
                        continue;
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

        for block_hashes in missing.chunks(SIDECAR_BATCH_BLOCK_LIMIT) {
            self.request_batch(None, block_hashes.to_vec(), beacon);
        }
    }

    pub(super) fn request_announced<Provider>(
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
                self.request_single(
                    Some(peer_id),
                    block_hash,
                    MAX_BLOB_REQUEST_TTL,
                    None,
                    HashSet::new(),
                    beacon,
                );
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

    pub(super) fn serve_or_forward<Provider>(
        &mut self,
        peer_id: B512,
        request: GetBlobs,
        provider: &Provider,
        beacon: &BeaconProtocol,
    ) where
        Provider: BlockReader<Block = Block>,
    {
        // Neo X Geth checks the TTL bounds before it looks anything up, and treats a violation as a
        // protocol error that tears the connection down: `handleGetBlobs` rejects `Ttl < 1` and
        // `handleGetBlobsPacket` rejects `Ttl > 3`. Forwarding decrements whatever a peer sent, so
        // without this bound a peer that asks for a blob block with `ttl = 255` makes this node
        // emit `ttl = 254` to its own peers, and every Geth peer among them drops it.
        // Refuse the request instead, and refuse it before consulting the store so the
        // reply set matches the oracle's.
        if !sidecar_request_ttl_in_range(request.ttl) {
            debug!(target: "neox::sync", %peer_id, request_id = request.request_id, block_hash = %request.block_hash, ttl = request.ttl, max_ttl = MAX_BLOB_REQUEST_TTL, "Rejected Neo X sidecar request with an out-of-range TTL");
            return;
        }
        match self.store.get(request.block_hash) {
            Ok(Some(sidecars)) => {
                let response = Blobs { request_id: request.request_id, sidecars };
                if !beacon.send(peer_id, BeaconCommand::Blobs(response)) {
                    debug!(target: "neox::sync", %peer_id, request_id = request.request_id, "Beacon peer disconnected before blob response");
                }
                return;
            }
            Ok(None) => {}
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, request_id = request.request_id, block_hash = %request.block_hash, %error, "Failed to read requested Neo X sidecars");
                return;
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
            return;
        }

        let failed_peers = HashSet::from([peer_id]);
        self.request_single(
            None,
            request.block_hash,
            request.ttl - 1,
            Some((peer_id, request.request_id)),
            failed_peers,
            beacon,
        );
    }

    pub(super) fn serve_batch(
        &self,
        peer_id: B512,
        request: GetBatchBlobs,
        beacon: &BeaconProtocol,
    ) {
        let mut blocks = Vec::new();
        let mut estimated_size = 0usize;
        for block_hash in request.block_hashes.into_iter().take(2 * SIDECAR_BATCH_BLOCK_LIMIT) {
            if blocks.len() >= SIDECAR_BATCH_BLOCK_LIMIT ||
                estimated_size >= SIDECAR_RESPONSE_SOFT_LIMIT
            {
                break;
            }
            let sidecars = match self.store.get(block_hash) {
                Ok(Some(sidecars)) => sidecars,
                Ok(None) => break,
                Err(error) => {
                    warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to read batched Neo X sidecars");
                    break;
                }
            };
            let sidecar_size = sidecars.iter().map(BeaconBlobSidecar::size).sum::<usize>();
            if !blocks.is_empty() &&
                estimated_size.saturating_add(sidecar_size) > SIDECAR_RESPONSE_SOFT_LIMIT
            {
                break;
            }
            estimated_size = estimated_size.saturating_add(sidecar_size);
            blocks.push(sidecars);
        }
        let response = BatchBlobs { request_id: request.request_id, blocks };
        if !beacon.send(peer_id, BeaconCommand::BatchBlobs(response)) {
            debug!(target: "neox::sync", %peer_id, request_id = request.request_id, "Beacon peer disconnected before batch blob response");
        }
    }

    pub(super) fn import_single<Provider>(
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
            return;
        };
        if pending.peer_id() != peer_id {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected Neo X blob response from the wrong peer");
            return;
        }
        let pending = self.pending.remove(&response.request_id).expect("pending request checked");
        let (block_hash, ttl, forwarded_for, mut failed_peers) = match pending {
            PendingSidecarRequest::Single {
                block_hash, ttl, forwarded_for, failed_peers, ..
            } => (block_hash, ttl, forwarded_for, failed_peers),
            pending => {
                warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected single blob response for a batch request");
                self.dispatch_retry(pending.into_retry(), beacon);
                return
            }
        };

        let sidecars = response.sidecars;
        if !self.validate_and_store(peer_id, block_hash, &sidecars, provider, beacon) {
            failed_peers.insert(peer_id);
            self.dispatch_retry(
                SidecarRetry::Single {
                    preferred_peer: None,
                    block_hash,
                    ttl,
                    forwarded_for,
                    failed_peers,
                },
                beacon,
            );
            return
        }
        if let Some((requester, original_request_id)) = forwarded_for {
            let forwarded = Blobs { request_id: original_request_id, sidecars };
            if !beacon.send(requester, BeaconCommand::Blobs(forwarded)) {
                debug!(target: "neox::sync", %requester, request_id = original_request_id, "Forwarding requester disconnected before Neo X blob response");
            }
        }
    }

    pub(super) fn import_batch<Provider>(
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
            return;
        };
        if pending.peer_id() != peer_id {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected Neo X batch blob response from the wrong peer");
            return;
        }
        let pending = self.pending.remove(&response.request_id).expect("pending request checked");
        let (block_hashes, mut failed_peers) = match pending {
            PendingSidecarRequest::Batch { block_hashes, failed_peers, .. } => {
                (block_hashes, failed_peers)
            }
            pending => {
                warn!(target: "neox::sync", %peer_id, request_id = response.request_id, "Rejected batch blob response for a single request");
                self.dispatch_retry(pending.into_retry(), beacon);
                return
            }
        };
        if response.blocks.len() > block_hashes.len() {
            warn!(target: "neox::sync", %peer_id, request_id = response.request_id, expected = block_hashes.len(), received = response.blocks.len(), "Rejected oversized Neo X batch blob response");
            failed_peers.insert(peer_id);
            self.dispatch_retry(
                SidecarRetry::Batch { preferred_peer: None, block_hashes, failed_peers },
                beacon,
            );
            return
        }

        let received = response.blocks.len();
        let mut missing = Vec::new();
        for (block_hash, sidecars) in block_hashes.iter().copied().zip(response.blocks) {
            if !self.validate_and_store(peer_id, block_hash, &sidecars, provider, beacon) {
                missing.push(block_hash);
            }
        }
        if received < block_hashes.len() {
            debug!(target: "neox::sync", %peer_id, request_id = response.request_id, received, requested = block_hashes.len(), "Neo X peer returned a partial batch blob response");
        }
        if let Some(retry) =
            retry_missing_batch(peer_id, &block_hashes, received, missing, failed_peers)
        {
            self.dispatch_retry(retry, beacon);
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
                return false;
            }
            Err(error) => {
                warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to load block for Neo X sidecar validation");
                return false;
            }
        };
        if let Err(error) = validate_block_sidecars(&block.body, sidecars) {
            warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Rejected invalid Neo X sidecars");
            return false;
        }
        if let Err(error) = self.store.insert(block_hash, sidecars.to_vec()) {
            warn!(target: "neox::sync", %peer_id, %block_hash, %error, "Failed to persist validated Neo X sidecars");
            return false;
        }
        beacon.broadcast(BeaconCommand::NewBlobsRoot(NewBlobsRoot { block_hash }));
        info!(target: "neox::sync", %peer_id, %block_hash, sidecars = sidecars.len(), "Validated, archived, and announced Neo X sidecars");
        true
    }

    fn request_single(
        &mut self,
        preferred_peer: Option<B512>,
        block_hash: B256,
        ttl: u8,
        forwarded_for: Option<(B512, u64)>,
        failed_peers: HashSet<B512>,
        beacon: &BeaconProtocol,
    ) {
        if self.pending.values().any(|request| request.contains_block(block_hash)) ||
            self.retries.iter().any(|request| request.contains_block(block_hash))
        {
            return;
        }
        match self.store.contains(block_hash) {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => {
                warn!(target: "neox::sync", %block_hash, %error, "Failed to inspect Neo X sidecar store before requesting blobs");
                return;
            }
        }
        self.dispatch_retry(
            SidecarRetry::Single { preferred_peer, block_hash, ttl, forwarded_for, failed_peers },
            beacon,
        );
    }

    fn request_batch(
        &mut self,
        preferred_peer: Option<B512>,
        mut block_hashes: Vec<B256>,
        beacon: &BeaconProtocol,
    ) {
        block_hashes.retain(|hash| {
            !self.pending.values().any(|request| request.contains_block(*hash)) &&
                !self.retries.iter().any(|request| request.contains_block(*hash)) &&
                !matches!(self.store.contains(*hash), Ok(true))
        });
        if block_hashes.is_empty() {
            return;
        }
        block_hashes.truncate(SIDECAR_BATCH_BLOCK_LIMIT);
        self.dispatch_retry(
            SidecarRetry::Batch { preferred_peer, block_hashes, failed_peers: HashSet::new() },
            beacon,
        );
    }

    fn dispatch_retry(&mut self, retry: SidecarRetry, beacon: &BeaconProtocol) {
        match retry {
            SidecarRetry::Single {
                mut preferred_peer,
                block_hash,
                ttl,
                forwarded_for,
                mut failed_peers,
            } => {
                if matches!(self.store.contains(block_hash), Ok(true)) {
                    return
                }
                loop {
                    let Some(peer_id) = self.choose_peer(preferred_peer, &failed_peers) else {
                        self.queue_retry(SidecarRetry::Single {
                            preferred_peer,
                            block_hash,
                            ttl,
                            forwarded_for,
                            failed_peers,
                        });
                        return
                    };
                    let request_id = self.allocate_request_id();
                    let request = GetBlobs { request_id, block_hash, ttl };
                    if beacon.send(peer_id, BeaconCommand::GetBlobs(request)) {
                        self.pending.insert(
                            request_id,
                            PendingSidecarRequest::Single {
                                peer_id,
                                block_hash,
                                ttl,
                                forwarded_for,
                                failed_peers,
                                requested_at: Instant::now(),
                            },
                        );
                        debug!(target: "neox::sync", %peer_id, request_id, %block_hash, ttl, "Requested Neo X sidecars");
                        return
                    }
                    failed_peers.insert(peer_id);
                    preferred_peer = None;
                }
            }
            SidecarRetry::Batch { mut preferred_peer, mut block_hashes, mut failed_peers } => {
                block_hashes.retain(|hash| {
                    !self.pending.values().any(|request| request.contains_block(*hash)) &&
                        !matches!(self.store.contains(*hash), Ok(true))
                });
                if block_hashes.is_empty() {
                    return
                }
                block_hashes.truncate(SIDECAR_BATCH_BLOCK_LIMIT);
                loop {
                    let Some(peer_id) = self.choose_peer(preferred_peer, &failed_peers) else {
                        self.queue_retry(SidecarRetry::Batch {
                            preferred_peer,
                            block_hashes,
                            failed_peers,
                        });
                        return
                    };
                    let request_id = self.allocate_request_id();
                    let request = GetBatchBlobs { request_id, block_hashes: block_hashes.clone() };
                    if beacon.send(peer_id, BeaconCommand::GetBatchBlobs(request)) {
                        self.pending.insert(
                            request_id,
                            PendingSidecarRequest::Batch {
                                peer_id,
                                block_hashes,
                                failed_peers,
                                requested_at: Instant::now(),
                            },
                        );
                        debug!(target: "neox::sync", %peer_id, request_id, "Requested batch Neo X sidecars");
                        return
                    }
                    failed_peers.insert(peer_id);
                    preferred_peer = None;
                }
            }
        }
    }

    fn queue_retry(&mut self, retry: SidecarRetry) {
        if self.retries.len() >= SIDECAR_RETRY_QUEUE_LIMIT {
            warn!(target: "neox::sync", limit = SIDECAR_RETRY_QUEUE_LIMIT, "Dropped Neo X sidecar retry because the retry queue is full");
            return
        }
        self.retries.push_back(retry);
    }

    fn drain_retries(&mut self, beacon: &BeaconProtocol) {
        let queued = self.retries.len();
        for _ in 0..queued {
            let Some(mut retry) = self.retries.pop_front() else { break };
            retry.reopen_exhausted_peer_cycle(&self.peers);
            self.dispatch_retry(retry, beacon);
        }
    }

    fn choose_peer(&self, preferred: Option<B512>, failed_peers: &HashSet<B512>) -> Option<B512> {
        choose_sidecar_peer(&self.peers, preferred, failed_peers)
    }

    fn allocate_request_id(&mut self) -> u64 {
        loop {
            let request_id = self.next_request_id;
            self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
            if !self.pending.contains_key(&request_id) {
                return request_id;
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

pub(super) fn validate_block_sidecars(
    body: &reth_ethereum_primitives::BlockBody,
    sidecars: &[BeaconBlobSidecar],
) -> Result<(), SidecarValidationError> {
    let blob_hashes: Vec<_> =
        body.transactions.iter().filter_map(transaction_blob_hashes).collect();
    if blob_hashes.is_empty() {
        return Err(SidecarValidationError::NoBlobTransactions);
    }
    if blob_hashes.len() != sidecars.len() {
        return Err(SidecarValidationError::Count {
            expected: blob_hashes.len(),
            actual: sidecars.len(),
        });
    }
    for (transaction_index, (hashes, sidecar)) in blob_hashes.into_iter().zip(sidecars).enumerate()
    {
        sidecar
            .clone()
            .into_variant()
            .validate(hashes, EnvKzgSettings::Default.get())
            .map_err(|source| SidecarValidationError::Invalid { transaction_index, source })?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(super) enum SidecarValidationError {
    #[error("block has no blob transactions")]
    NoBlobTransactions,
    #[error("sidecar count mismatch: expected {expected}, received {actual}")]
    Count { expected: usize, actual: usize },
    #[error("blob transaction {transaction_index}: {source}")]
    Invalid {
        transaction_index: usize,
        #[source]
        source: BlobTransactionValidationError,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        batch_response_penalizes_peer, choose_sidecar_peer, retry_missing_batch,
        sidecar_request_ttl_in_range, validate_block_sidecars, SidecarRetry,
        SidecarValidationError, MAX_BLOB_REQUEST_TTL,
    };
    use alloy_eips::eip2124::{ForkHash, ForkId};
    use alloy_primitives::{B256, B512, U256};
    use reth_ethereum_primitives::BlockBody;
    use reth_neox_network::{BeaconStatus, BeaconStatusV2};
    use std::collections::{HashMap, HashSet};

    /// Geth rejects only `Ttl == 0` in its blob request handler. Pin the accepted range directly
    /// against the oracle's wire behavior.
    #[test]
    fn accepts_only_the_ttl_range_neox_geth_accepts() {
        assert_eq!(MAX_BLOB_REQUEST_TTL, u8::MAX, "wire TTL is a uint8");

        assert!(!sidecar_request_ttl_in_range(0), "oracle rejects Ttl == 0");
        for ttl in [1, 3, 4, 16, 128, u8::MAX] {
            assert!(sidecar_request_ttl_in_range(ttl), "ttl {ttl} is accepted by the oracle");
        }
    }

    /// Forwarding stops at one, so no forwarded request emits the oracle-invalid zero TTL.
    #[test]
    fn forwarded_ttl_stays_nonzero() {
        for ttl in 2..=MAX_BLOB_REQUEST_TTL {
            assert!(
                sidecar_request_ttl_in_range(ttl - 1),
                "forwarding ttl {ttl} must emit nonzero"
            );
        }
    }

    #[test]
    fn retry_work_preserves_failed_peers_and_missing_blocks() {
        let failed_peer = B512::repeat_byte(0x11);
        let first = B256::repeat_byte(0x22);
        let second = B256::repeat_byte(0x33);
        let retry = SidecarRetry::Batch {
            preferred_peer: None,
            block_hashes: vec![first, second],
            failed_peers: HashSet::from([failed_peer]),
        };
        assert!(retry.contains_block(first));
        assert!(retry.contains_block(second));
        assert!(!retry.contains_block(B256::ZERO));
    }

    #[test]
    fn failed_sidecar_peer_is_skipped_for_a_connected_alternative() {
        let failed = B512::repeat_byte(0x11);
        let alternate = B512::repeat_byte(0x22);
        let status = BeaconStatus::V2(BeaconStatusV2 {
            protocol_version: 2,
            network_id: 47_763,
            total_difficulty: U256::from(10),
            head: B256::ZERO,
            head_number: 10,
            genesis: B256::ZERO,
            fork_id: ForkId { hash: ForkHash([1, 2, 3, 4]), next: 0 },
            blob_sync: true,
        });
        let peers = HashMap::from([(failed, status), (alternate, status)]);

        assert_eq!(
            choose_sidecar_peer(&peers, Some(failed), &HashSet::from([failed])),
            Some(alternate)
        );
    }

    #[test]
    fn reconnected_sidecar_peer_reopens_on_the_next_retry_cycle() {
        let peer = B512::repeat_byte(0x11);
        let status = BeaconStatus::V2(BeaconStatusV2 {
            protocol_version: 2,
            network_id: 47_763,
            total_difficulty: U256::from(10),
            head: B256::ZERO,
            head_number: 10,
            genesis: B256::ZERO,
            fork_id: ForkId { hash: ForkHash([1, 2, 3, 4]), next: 0 },
            blob_sync: true,
        });
        let mut retry = SidecarRetry::Batch {
            preferred_peer: None,
            block_hashes: vec![B256::repeat_byte(0x22)],
            failed_peers: HashSet::from([peer]),
        };

        retry.reopen_exhausted_peer_cycle(&HashMap::new());
        let SidecarRetry::Batch { failed_peers, .. } = &retry else { unreachable!() };
        assert!(failed_peers.contains(&peer));

        let peers = HashMap::from([(peer, status)]);
        retry.reopen_exhausted_peer_cycle(&peers);
        let SidecarRetry::Batch { failed_peers, .. } = retry else { unreachable!() };
        assert_eq!(choose_sidecar_peer(&peers, None, &failed_peers), Some(peer));
    }

    #[test]
    fn forwarded_sidecar_request_never_retries_its_origin() {
        let requester = B512::repeat_byte(0x11);
        let failed_relay = B512::repeat_byte(0x22);
        let status = BeaconStatus::V2(BeaconStatusV2 {
            protocol_version: 2,
            network_id: 47_763,
            total_difficulty: U256::from(10),
            head: B256::ZERO,
            head_number: 10,
            genesis: B256::ZERO,
            fork_id: ForkId { hash: ForkHash([1, 2, 3, 4]), next: 0 },
            blob_sync: true,
        });
        let peers = HashMap::from([(requester, status), (failed_relay, status)]);
        let mut retry = SidecarRetry::Single {
            preferred_peer: None,
            block_hash: B256::repeat_byte(0x33),
            ttl: 2,
            forwarded_for: Some((requester, 7)),
            failed_peers: HashSet::from([requester, failed_relay]),
        };

        retry.reopen_exhausted_peer_cycle(&peers);
        let SidecarRetry::Single { failed_peers, .. } = retry else { unreachable!() };
        assert!(failed_peers.contains(&requester));
        assert!(!failed_peers.contains(&failed_relay));
        assert_eq!(choose_sidecar_peer(&peers, None, &failed_peers), Some(failed_relay));
    }

    #[test]
    fn one_peer_can_serve_a_partial_batch_suffix() {
        let peer = B512::repeat_byte(0x11);
        let first = B256::repeat_byte(0x22);
        let second = B256::repeat_byte(0x33);
        let retry = retry_missing_batch(peer, &[first, second], 1, Vec::new(), HashSet::new())
            .expect("partial response must retry its suffix");
        let SidecarRetry::Batch { block_hashes, failed_peers, .. } = retry else { unreachable!() };

        assert_eq!(block_hashes, vec![second]);
        assert!(!failed_peers.contains(&peer));
        assert!(!batch_response_penalizes_peer(1, 0));
        assert!(batch_response_penalizes_peer(0, 0));
        assert!(batch_response_penalizes_peer(1, 1));
    }

    #[test]
    fn block_without_blob_transactions_has_a_typed_validation_error() {
        let error = validate_block_sidecars(&BlockBody::default(), &[]).unwrap_err();
        assert!(matches!(error, SidecarValidationError::NoBlobTransactions));
    }
}
