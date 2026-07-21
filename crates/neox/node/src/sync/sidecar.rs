//! Finalized Neo X blob-sidecar synchronization state and validation.

use alloy_eips::eip4844::{env_settings::EnvKzgSettings, BlobTransactionValidationError};
use alloy_primitives::{B256, B512, U256};
use reth_ethereum_primitives::{Block, EthPrimitives, PooledTransactionVariant, TransactionSigned};
use reth_neox_network::{
    BatchBlobs, BeaconBlobSidecar, BeaconCommand, BeaconProtocol, BeaconStatus, Blobs,
    GetBatchBlobs, GetBlobs, NeoXSidecarStore, NewBlobsRoot,
};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::BlockReader;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, info, warn};

const SIDECAR_RESPONSE_SOFT_LIMIT: usize = 5 * 1024 * 1024;
const SIDECAR_BATCH_BLOCK_LIMIT: usize = 16;
const SIDECAR_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const SIDECAR_RETAINED_BLOCK_WINDOW: u64 = 8_192 * 32;

#[derive(Debug)]
pub(super) struct SidecarSync {
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

/// Whether a peer's advertised head is ahead of the given local head — by block number, or by
/// total difficulty when the peer omits a head number.
fn status_ahead_of(status: &BeaconStatus, head_number: u64, total_difficulty: U256) -> bool {
    status
        .head_number()
        .map_or_else(|| status.total_difficulty() > total_difficulty, |number| number > head_number)
}

impl SidecarSync {
    pub(super) fn new(store: NeoXSidecarStore) -> Self {
        info!(target: "neox::sync", path = %store.root().display(), "Neo X finalized sidecar store initialized");
        Self { store, peers: HashMap::new(), pending: HashMap::new(), next_request_id: 1 }
    }

    /// Records a connected peer's latest status.
    pub(super) fn connect_peer(&mut self, peer_id: B512, status: BeaconStatus) {
        self.peers.insert(peer_id, status);
    }

    /// Whether the given connected peer advertises a head ahead of the local head.
    pub(super) fn peer_ahead_of(
        &self,
        peer_id: B512,
        head_number: u64,
        total_difficulty: U256,
    ) -> bool {
        self.peers
            .get(&peer_id)
            .is_some_and(|status| status_ahead_of(status, head_number, total_difficulty))
    }

    /// Removes a disconnected peer and every sidecar request assigned to it.
    pub(super) fn disconnect_peer(&mut self, peer_id: B512) {
        self.peers.remove(&peer_id);
        self.pending.retain(|_, request| request.peer_id() != peer_id);
    }

    /// Whether any connected beacon peer advertises a head ahead of the given local head.
    pub(super) fn network_ahead_of(&self, head_number: u64, total_difficulty: U256) -> bool {
        self.peers.values().any(|peer| status_ahead_of(peer, head_number, total_difficulty))
    }

    pub(super) fn expire_requests(&mut self) {
        self.pending.retain(|request_id, request| {
            let retain = request.requested_at().elapsed() < SIDECAR_REQUEST_TIMEOUT;
            if !retain {
                debug!(target: "neox::sync", request_id, peer_id = %request.peer_id(), "Neo X sidecar request timed out");
            }
            retain
        });
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

    pub(super) fn serve_or_forward<Provider>(
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

pub(super) fn validate_block_sidecars(
    body: &reth_ethereum_primitives::BlockBody,
    sidecars: &[BeaconBlobSidecar],
) -> Result<(), SidecarValidationError> {
    let blob_hashes: Vec<_> =
        body.transactions.iter().filter_map(transaction_blob_hashes).collect();
    if blob_hashes.is_empty() {
        return Err(SidecarValidationError::NoBlobTransactions)
    }
    if blob_hashes.len() != sidecars.len() {
        return Err(SidecarValidationError::Count {
            expected: blob_hashes.len(),
            actual: sidecars.len(),
        })
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
    use super::{status_ahead_of, validate_block_sidecars, SidecarValidationError};
    use alloy_eips::eip2124::{ForkHash, ForkId};
    use alloy_primitives::{B256, U256};
    use reth_ethereum_primitives::BlockBody;
    use reth_neox_network::{BeaconStatus, BeaconStatusV1, BeaconStatusV2};

    const FORK_ID: ForkId = ForkId { hash: ForkHash([1, 2, 3, 4]), next: 0 };

    #[test]
    fn peer_head_comparison_uses_the_version_specific_signal() {
        let v1 = BeaconStatus::V1(BeaconStatusV1 {
            protocol_version: 1,
            network_id: 47_763,
            total_difficulty: U256::from(11),
            head: B256::ZERO,
            genesis: B256::ZERO,
            fork_id: FORK_ID,
            blob_sync: false,
        });
        assert!(status_ahead_of(&v1, u64::MAX, U256::from(10)));

        let v2 = BeaconStatus::V2(BeaconStatusV2 {
            protocol_version: 2,
            network_id: 47_763,
            total_difficulty: U256::MAX,
            head: B256::ZERO,
            head_number: 10,
            genesis: B256::ZERO,
            fork_id: FORK_ID,
            blob_sync: false,
        });
        assert!(!status_ahead_of(&v2, 10, U256::ZERO));
        assert!(status_ahead_of(&v2, 9, U256::MAX));
    }

    #[test]
    fn block_without_blob_transactions_has_a_typed_validation_error() {
        let error = validate_block_sidecars(&BlockBody::default(), &[]).unwrap_err();
        assert!(matches!(error, SidecarValidationError::NoBlobTransactions));
    }
}
