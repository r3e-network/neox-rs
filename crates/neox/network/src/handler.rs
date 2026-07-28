//! Reth `RLPx` handler for Neo X's beacon protocol.

use crate::{
    encode_frame,
    protocol::{DecodedMessage, MAX_MESSAGE_SIZE},
    BatchBlobs, BeaconLocalStatus, BeaconMessageId, BeaconStatus, BeaconVersion, Blobs,
    GetBatchBlobs, GetBlobs, GetTransactions, NewBlobsRoot, NewBlockPacket, TransactionsPacket,
    MAX_BLOB_REQUEST_TTL,
};
use alloy_eips::eip2124::{ForkHash, ForkId, Head};
use alloy_primitives::{
    bytes::{Buf, BytesMut},
    Bytes, B256,
};
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
};
use reth_eth_wire_types::NewBlockHashes;
use reth_ethereum_forks::{ForkCondition, Hardforks};
use reth_neox_chainspec::NeoXChainSpec;
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::{Direction, PeerId};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, RwLock, Weak},
    task::{ready, Context, Poll},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, warn};

/// Maximum number of decoded Beacon events retained for the sync driver.
pub const BEACON_EVENT_QUEUE_CAPACITY: usize = 64;
/// Maximum aggregate wire size retained by the decoded Beacon event queue.
pub const BEACON_EVENT_QUEUE_BYTE_CAPACITY: usize = 32 * 1024 * 1024;
/// Maximum wire size retained per event class for any one Beacon peer.
pub const BEACON_PEER_EVENT_BYTE_CAPACITY: usize = MAX_MESSAGE_SIZE + 1;
/// Maximum decoded data events retained per event class for any one Beacon peer.
pub const BEACON_PEER_EVENT_QUEUE_CAPACITY: usize = 8;

const BEACON_COMMAND_QUEUE_CAPACITY: usize = 4;
/// Lifecycle event slots held in reserve, on top of [`BEACON_EVENT_QUEUE_CAPACITY`] data events.
///
/// Divided by [`BEACON_CONTROL_EVENTS_PER_CONNECTION`], this is the ceiling on concurrently
/// admitted beacon peers: past it `reserve_control_events` fails and the stream is declined at
/// admission. Raising the node's peer limit does not widen it, so this has to grow alongside that
/// limit or the surplus peers negotiate the capability and then get dropped.
const BEACON_CONTROL_EVENT_QUEUE_CAPACITY: usize = 384;
/// Lifecycle events one connection can emit: `Established` once the handshake lands, at most one
/// `Violation`, and `Disconnected` on drop. All three are reserved before the connection is
/// admitted so a saturated event queue cannot swallow a peer's disconnect and leave the sync driver
/// believing it is still connected.
///
/// This must stay equal to the number of `emit_control` calls reachable on one connection. That
/// helper pops a reserved permit and expects one to be present, and `Drop` is one of its callers,
/// where a panic while already unwinding aborts the process. Adding a fourth lifecycle event
/// without raising this turns that expect into an abort.
const BEACON_CONTROL_EVENTS_PER_CONNECTION: usize = 3;
const BEACON_REQUIRED_EVENT_QUEUE_RESERVE: usize = BEACON_PEER_EVENT_QUEUE_CAPACITY;
const BEACON_DROPPABLE_EVENT_QUEUE_CAPACITY: usize =
    BEACON_EVENT_QUEUE_CAPACITY - BEACON_REQUIRED_EVENT_QUEUE_RESERVE;
const BEACON_REQUIRED_EVENT_BYTE_RESERVE: usize = MAX_MESSAGE_SIZE + 1;
const BEACON_DROPPABLE_EVENT_BYTE_CAPACITY: usize =
    BEACON_EVENT_QUEUE_BYTE_CAPACITY - BEACON_REQUIRED_EVENT_BYTE_RESERVE;
/// The Ethereum mainnet genesis timestamp, used by `core/forkid.timestampThreshold` in the pinned
/// Neo X Geth baseline to guess whether a peer's announced `fork_id.next` is a block number or a
/// timestamp. Any plausible block number falls below it and any plausible timestamp above it.
///
/// Geth calls the trick hacky itself and keeps it only to cover the block-fork to time-fork
/// transition. The value is not Neo X's own genesis time and must not be replaced with it: it is
/// copied verbatim so [`BeaconForkFilter::validate`] accepts and rejects exactly the peers Geth
/// does.
const GETH_FORK_TIMESTAMP_THRESHOLD: u64 = 1_438_269_973;

/// A validated message or peer lifecycle event emitted by the beacon protocol.
#[derive(Debug, Clone)]
pub enum BeaconEvent {
    /// A version-specific status handshake completed.
    Established {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Connection direction.
        direction: Direction,
        /// Negotiated beacon version.
        version: BeaconVersion,
        /// Validated remote status.
        status: BeaconStatus,
    },
    /// The beacon protocol stream ended.
    Disconnected {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Negotiated beacon version.
        version: BeaconVersion,
    },
    /// Remote block-hash announcements.
    NewBlockHashes {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Announcements.
        announcement: NewBlockHashes,
    },
    /// A propagated full block.
    NewBlock {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Propagated packet.
        packet: Box<NewBlockPacket>,
    },
    /// Blob-sidecar availability announcement.
    NewBlobsRoot {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Announcement.
        announcement: NewBlobsRoot,
    },
    /// Beacon/2 transaction request.
    GetTransactions {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Request.
        request: GetTransactions,
    },
    /// Beacon/2 transaction response.
    Transactions {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Response.
        response: TransactionsPacket,
    },
    /// Requests all sidecars belonging to one block.
    GetBlobs {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Request.
        request: GetBlobs,
    },
    /// Returns all sidecars belonging to one block.
    Blobs {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Response.
        response: Blobs,
    },
    /// Requests sidecars for several blocks.
    GetBatchBlobs {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Request.
        request: GetBatchBlobs,
    },
    /// Returns sidecars for several blocks.
    BatchBlobs {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Response.
        response: BatchBlobs,
    },
    /// A protocol violation closed this beacon stream.
    Violation {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Violation reason.
        reason: BeaconProtocolViolation,
    },
}

#[derive(Debug)]
struct QueuedBeaconEvent {
    event: Option<BeaconEvent>,
    _data_slot: Option<OwnedSemaphorePermit>,
    _droppable_slot: Option<OwnedSemaphorePermit>,
    _peer_slot: Option<OwnedSemaphorePermit>,
    _global_bytes: Option<OwnedSemaphorePermit>,
    _droppable_bytes: Option<OwnedSemaphorePermit>,
    _peer_bytes: Option<OwnedSemaphorePermit>,
    _peer_budget: Option<Arc<PeerEventBudget>>,
}

impl QueuedBeaconEvent {
    fn into_event(mut self) -> BeaconEvent {
        self.event.take().expect("queued Beacon event must be present")
    }
}

/// Bounded receiver for validated Beacon events.
///
/// Wire-byte reservations are released when an event is dequeued, before the
/// sync driver begins potentially expensive block or sidecar processing.
#[derive(Debug)]
pub struct BeaconEventReceiver {
    receiver: mpsc::Receiver<QueuedBeaconEvent>,
    data_slots: Arc<Semaphore>,
}

impl BeaconEventReceiver {
    /// Receives the next validated event.
    pub async fn recv(&mut self) -> Option<BeaconEvent> {
        self.receiver.recv().await.map(QueuedBeaconEvent::into_event)
    }

    /// Attempts to receive an event without waiting.
    pub fn try_recv(&mut self) -> Result<BeaconEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv().map(QueuedBeaconEvent::into_event)
    }

    /// Returns the remaining event-count capacity.
    pub fn capacity(&self) -> usize {
        self.data_slots.available_permits()
    }

    /// Returns the configured event-count capacity.
    pub const fn max_capacity(&self) -> usize {
        BEACON_EVENT_QUEUE_CAPACITY
    }
}

/// Commands routed to one or all connected beacon peers.
#[derive(Debug, Clone)]
pub enum BeaconCommand {
    /// Announce block hashes and numbers.
    NewBlockHashes(NewBlockHashes),
    /// Propagate a full block.
    NewBlock(Box<NewBlockPacket>),
    /// Announce blob sidecars for a block.
    NewBlobsRoot(NewBlobsRoot),
    /// Request all sidecars belonging to one block.
    GetBlobs(GetBlobs),
    /// Return all sidecars belonging to one block.
    Blobs(Blobs),
    /// Request sidecars for several blocks.
    GetBatchBlobs(GetBatchBlobs),
    /// Return sidecars for several blocks.
    BatchBlobs(BatchBlobs),
    /// Request consensus proposal transactions from a beacon/2 peer.
    GetTransactions(GetTransactions),
    /// Reply to a beacon/2 transaction request.
    Transactions(TransactionsPacket),
    /// Send an already RLP-encoded version-specific payload.
    Raw {
        /// Message identifier.
        message_id: BeaconMessageId,
        /// RLP payload without the identifier byte.
        payload: Bytes,
    },
}

impl BeaconCommand {
    fn supported(&self, version: BeaconVersion) -> bool {
        match self {
            Self::GetTransactions(_) | Self::Transactions(_) => version == BeaconVersion::V2,
            Self::Raw { message_id, .. } => (*message_id as u8) < version.message_count(),
            _ => true,
        }
    }

    fn encoded(self, version: BeaconVersion) -> Option<BytesMut> {
        match self {
            Self::NewBlockHashes(value) => {
                Some(encode_frame(BeaconMessageId::NewBlockHashes, &value))
            }
            Self::NewBlock(value) => Some(encode_frame(BeaconMessageId::NewBlock, value.as_ref())),
            Self::NewBlobsRoot(value) => Some(encode_frame(BeaconMessageId::NewBlobsRoot, &value)),
            Self::GetBlobs(value) => Some(encode_frame(BeaconMessageId::GetBlobs, &value)),
            Self::Blobs(value) => Some(value.encoded(version)),
            Self::GetBatchBlobs(value) => {
                Some(encode_frame(BeaconMessageId::GetBatchBlobs, &value))
            }
            Self::BatchBlobs(value) => Some(value.encoded(version)),
            Self::GetTransactions(value) if version == BeaconVersion::V2 => {
                Some(encode_frame(BeaconMessageId::GetTransactions, &value))
            }
            Self::Transactions(value) if version == BeaconVersion::V2 => {
                Some(encode_frame(BeaconMessageId::Transactions, &value))
            }
            Self::Raw { message_id, payload } if (message_id as u8) < version.message_count() => {
                let mut frame = BytesMut::with_capacity(payload.len() + 1);
                frame.extend_from_slice(&[message_id as u8]);
                frame.extend_from_slice(&payload);
                Some(frame)
            }
            Self::GetTransactions(_) | Self::Transactions(_) | Self::Raw { .. } => None,
        }
    }
}

/// Reason a beacon stream was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconProtocolViolation {
    /// Empty frame.
    EmptyMessage,
    /// Payload exceeds Neo X Geth's 10 MiB limit.
    MessageTooLarge(usize),
    /// First packet was not status.
    MissingStatus(u8),
    /// Unknown message identifier.
    InvalidMessageId(u8),
    /// Malformed RLP payload.
    InvalidRlp(String),
    /// Remote claimed a different negotiated version.
    VersionMismatch {
        /// Negotiated local version.
        expected: u32,
        /// Version claimed by the remote status.
        received: u32,
    },
    /// Remote is on another devp2p network.
    NetworkMismatch {
        /// Configured local network identifier.
        expected: u64,
        /// Network identifier claimed by the remote status.
        received: u64,
    },
    /// Remote is on a different genesis.
    GenesisMismatch {
        /// Configured canonical genesis hash.
        expected: B256,
        /// Genesis hash claimed by the remote status.
        received: B256,
    },
    /// EIP-2124 fork identifiers are incompatible.
    ForkIdRejected,
    /// The bounded inbound event queue cannot retain another peer message.
    InboundQueueSaturated,
    /// A blob request used a zero or excessive forwarding TTL.
    InvalidBlobTtl(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForkPoint {
    Block(u64),
    Time(u64),
}

impl ForkPoint {
    const fn value(self) -> u64 {
        match self {
            Self::Block(value) | Self::Time(value) => value,
        }
    }

    const fn passed(self, head: Head) -> bool {
        match self {
            Self::Block(number) => head.number >= number,
            Self::Time(timestamp) => head.timestamp >= timestamp,
        }
    }
}

/// Neo X Geth's EIP-2124 schedule: all block forks, then all time forks.
#[derive(Debug)]
struct BeaconForkFilter {
    points: Vec<ForkPoint>,
    sums: Vec<ForkHash>,
    block_forks: usize,
    has_time_forks: bool,
}

impl BeaconForkFilter {
    fn new(chain_spec: &NeoXChainSpec) -> Self {
        let mut block_forks = Vec::new();
        let mut time_forks = Vec::new();
        let genesis_timestamp = chain_spec.inner.genesis().timestamp;

        for (_, condition) in chain_spec.forks_iter() {
            match condition {
                ForkCondition::Block(number) if number > 0 => block_forks.push(number),
                ForkCondition::TTD { fork_block: Some(number), .. } if number > 0 => {
                    block_forks.push(number)
                }
                ForkCondition::Timestamp(timestamp) if timestamp > genesis_timestamp => {
                    time_forks.push(timestamp)
                }
                _ => {}
            }
        }
        block_forks.sort_unstable();
        block_forks.dedup();
        time_forks.sort_unstable();
        time_forks.dedup();

        let block_fork_count = block_forks.len();
        let has_time_forks = !time_forks.is_empty();
        let points = block_forks
            .into_iter()
            .map(ForkPoint::Block)
            .chain(time_forks.into_iter().map(ForkPoint::Time))
            .collect::<Vec<_>>();
        let mut sums = Vec::with_capacity(points.len() + 1);
        let mut sum = ForkHash::from(chain_spec.inner.genesis_hash());
        sums.push(sum);
        for point in &points {
            sum += point.value();
            sums.push(sum);
        }

        Self { points, sums, block_forks: block_fork_count, has_time_forks }
    }

    fn current_index(&self, head: Head) -> usize {
        self.points.iter().position(|point| !point.passed(head)).unwrap_or(self.points.len())
    }

    fn fork_id(&self, head: Head) -> ForkId {
        let index = self.current_index(head);
        ForkId {
            hash: self.sums[index],
            next: self.points.get(index).map_or(0, |point| point.value()),
        }
    }

    /// Mirrors `core/forkid.newFilter` at the pinned Neo X Geth baseline.
    fn validate(&self, remote: ForkId, head: Head) -> bool {
        let index = self.current_index(head);
        let local = self.fork_id(head);

        // Rule 1: peers at the same checksum are compatible until a remote-only
        // next fork has already passed locally.
        if local.hash == remote.hash {
            if remote.next == 0 {
                return true;
            }
            let dimension_head = if index < self.block_forks || !self.has_time_forks {
                head.number
            } else {
                head.timestamp
            };
            return dimension_head < remote.next &&
                (remote.next <= GETH_FORK_TIMESTAMP_THRESHOLD || head.timestamp < remote.next);
        }

        // Rule 2: an older peer must announce the exact locally following fork.
        for previous in 0..index {
            if self.sums[previous] == remote.hash {
                return self.points[previous].value() == remote.next;
            }
        }

        // Rule 3: a checksum reachable by applying locally known future forks
        // means the local node is merely behind.
        self.sums[index.saturating_add(1)..].contains(&remote.hash)
    }
}

#[derive(Debug, Clone)]
struct BeaconPeerCommands {
    version: BeaconVersion,
    sender: mpsc::Sender<BeaconCommand>,
}

#[derive(Debug)]
struct PeerEventBudget {
    required_slots: Arc<Semaphore>,
    required_bytes: Arc<Semaphore>,
    droppable_slots: Arc<Semaphore>,
    droppable_bytes: Arc<Semaphore>,
}

impl PeerEventBudget {
    fn new() -> Self {
        Self {
            required_slots: Arc::new(Semaphore::new(BEACON_PEER_EVENT_QUEUE_CAPACITY)),
            required_bytes: Arc::new(Semaphore::new(BEACON_PEER_EVENT_BYTE_CAPACITY)),
            droppable_slots: Arc::new(Semaphore::new(BEACON_PEER_EVENT_QUEUE_CAPACITY)),
            droppable_bytes: Arc::new(Semaphore::new(BEACON_PEER_EVENT_BYTE_CAPACITY)),
        }
    }
}

#[derive(Debug)]
struct BeaconProtocolInner {
    fork_filter: BeaconForkFilter,
    status: RwLock<BeaconLocalStatus>,
    events: mpsc::Sender<QueuedBeaconEvent>,
    data_slots: Arc<Semaphore>,
    droppable_slots: Arc<Semaphore>,
    event_bytes: Arc<Semaphore>,
    droppable_bytes: Arc<Semaphore>,
    peer_event_budgets: Mutex<HashMap<PeerId, Weak<PeerEventBudget>>>,
    peers: Mutex<HashMap<PeerId, BeaconPeerCommands>>,
}

/// Shared beacon protocol state and peer command handle.
#[derive(Debug, Clone)]
pub struct BeaconProtocol {
    inner: Arc<BeaconProtocolInner>,
}

impl BeaconProtocol {
    /// Creates protocol state and its validated-event receiver.
    pub fn new(
        chain_spec: Arc<NeoXChainSpec>,
        status: BeaconLocalStatus,
    ) -> (Self, BeaconEventReceiver) {
        let (events, receiver) =
            mpsc::channel(BEACON_EVENT_QUEUE_CAPACITY + BEACON_CONTROL_EVENT_QUEUE_CAPACITY);
        let data_slots = Arc::new(Semaphore::new(BEACON_EVENT_QUEUE_CAPACITY));
        let fork_filter = BeaconForkFilter::new(&chain_spec);
        let this = Self {
            inner: Arc::new(BeaconProtocolInner {
                fork_filter,
                status: RwLock::new(status),
                events,
                data_slots: Arc::clone(&data_slots),
                droppable_slots: Arc::new(Semaphore::new(BEACON_DROPPABLE_EVENT_QUEUE_CAPACITY)),
                event_bytes: Arc::new(Semaphore::new(BEACON_EVENT_QUEUE_BYTE_CAPACITY)),
                droppable_bytes: Arc::new(Semaphore::new(BEACON_DROPPABLE_EVENT_BYTE_CAPACITY)),
                peer_event_budgets: Mutex::new(HashMap::new()),
                peers: Mutex::new(HashMap::new()),
            }),
        };
        (this, BeaconEventReceiver { receiver, data_slots })
    }

    /// Builds a version-specific `RLPx` handler. Register both V2 and V1 with the network.
    pub fn handler(&self, version: BeaconVersion) -> BeaconProtocolHandler {
        BeaconProtocolHandler { protocol: self.clone(), version }
    }

    /// Updates the status used by new handshakes.
    pub fn update_status(&self, status: BeaconLocalStatus) {
        *self.inner.status.write().expect("beacon status lock poisoned") = status;
    }

    /// Returns the current local status.
    pub fn status(&self) -> BeaconLocalStatus {
        *self.inner.status.read().expect("beacon status lock poisoned")
    }

    /// Sends a command to one negotiated beacon peer.
    pub fn send(&self, peer_id: PeerId, command: BeaconCommand) -> bool {
        let peers = self.inner.peers.lock().expect("beacon peers lock poisoned");
        let Some(peer) = peers.get(&peer_id) else { return false };
        command.supported(peer.version) && peer.sender.try_send(command).is_ok()
    }

    /// Broadcasts a command to all negotiated beacon peers.
    pub fn broadcast(&self, command: BeaconCommand) -> usize {
        self.inner
            .peers
            .lock()
            .expect("beacon peers lock poisoned")
            .values()
            .filter(|peer| {
                command.supported(peer.version) && peer.sender.try_send(command.clone()).is_ok()
            })
            .count()
    }

    /// Number of peers with a completed beacon status handshake.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.lock().expect("beacon peers lock poisoned").len()
    }
}

impl BeaconProtocolInner {
    fn peer_event_budget(&self, peer_id: PeerId) -> Arc<PeerEventBudget> {
        let mut budgets =
            self.peer_event_budgets.lock().expect("beacon event budgets lock poisoned");
        if let Some(budget) = budgets.get(&peer_id).and_then(Weak::upgrade) {
            return budget;
        }
        budgets.retain(|_, budget| budget.strong_count() > 0);
        let budget = Arc::new(PeerEventBudget::new());
        budgets.insert(peer_id, Arc::downgrade(&budget));
        budget
    }

    fn reserve_control_events(&self) -> Option<Vec<mpsc::OwnedPermit<QueuedBeaconEvent>>> {
        let mut permits = Vec::with_capacity(BEACON_CONTROL_EVENTS_PER_CONNECTION);
        for _ in 0..BEACON_CONTROL_EVENTS_PER_CONNECTION {
            permits.push(self.events.clone().try_reserve_owned().ok()?);
        }
        Some(permits)
    }

    fn queue_event(
        &self,
        event: BeaconEvent,
        peer_budget: &Arc<PeerEventBudget>,
        wire_size: usize,
        droppable: bool,
    ) -> Result<(), BeaconProtocolViolation> {
        let permits =
            u32::try_from(wire_size).map_err(|_| BeaconProtocolViolation::InboundQueueSaturated)?;
        let droppable_slot = if droppable {
            match Arc::clone(&self.droppable_slots).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return Ok(()),
            }
        } else {
            None
        };
        let droppable_bytes = if droppable && permits > 0 {
            match Arc::clone(&self.droppable_bytes).try_acquire_many_owned(permits) {
                Ok(permit) => Some(permit),
                Err(_) => return Ok(()),
            }
        } else {
            None
        };
        let data_slot = match Arc::clone(&self.data_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) if droppable => return Ok(()),
            Err(_) => return Err(BeaconProtocolViolation::InboundQueueSaturated),
        };
        let peer_slots =
            if droppable { &peer_budget.droppable_slots } else { &peer_budget.required_slots };
        let peer_slot = match Arc::clone(peer_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) if droppable => return Ok(()),
            Err(_) => return Err(BeaconProtocolViolation::InboundQueueSaturated),
        };
        let global_bytes = if permits == 0 {
            None
        } else {
            match Arc::clone(&self.event_bytes).try_acquire_many_owned(permits) {
                Ok(permit) => Some(permit),
                Err(_) if droppable => return Ok(()),
                Err(_) => return Err(BeaconProtocolViolation::InboundQueueSaturated),
            }
        };
        let peer_event_bytes =
            if droppable { &peer_budget.droppable_bytes } else { &peer_budget.required_bytes };
        let peer_bytes = if permits == 0 {
            None
        } else {
            match Arc::clone(peer_event_bytes).try_acquire_many_owned(permits) {
                Ok(permit) => Some(permit),
                Err(_) if droppable => return Ok(()),
                Err(_) => return Err(BeaconProtocolViolation::InboundQueueSaturated),
            }
        };
        let queued = QueuedBeaconEvent {
            event: Some(event),
            _data_slot: Some(data_slot),
            _droppable_slot: droppable_slot,
            _peer_slot: Some(peer_slot),
            _global_bytes: global_bytes,
            _droppable_bytes: droppable_bytes,
            _peer_bytes: peer_bytes,
            _peer_budget: Some(Arc::clone(peer_budget)),
        };
        match self.events.try_send(queued) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) if droppable => Ok(()),
            Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                Err(BeaconProtocolViolation::InboundQueueSaturated)
            }
        }
    }
}

/// Version-specific protocol handler announced during `RLPx` capability negotiation.
#[derive(Debug, Clone)]
pub struct BeaconProtocolHandler {
    protocol: BeaconProtocol,
    version: BeaconVersion,
}

impl ProtocolHandler for BeaconProtocolHandler {
    type ConnectionHandler = BeaconConnectionHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(BeaconConnectionHandler { protocol: self.protocol.clone(), version: self.version })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(BeaconConnectionHandler { protocol: self.protocol.clone(), version: self.version })
    }
}

/// Authenticates one negotiated beacon capability.
#[derive(Debug)]
pub struct BeaconConnectionHandler {
    protocol: BeaconProtocol,
    version: BeaconVersion,
}

impl ConnectionHandler for BeaconConnectionHandler {
    type Connection = BeaconConnection;

    fn protocol(&self) -> Protocol {
        self.version.protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let local_status = self.protocol.status();
        let head = Head {
            number: local_status.head_number,
            timestamp: local_status.head_timestamp,
            total_difficulty: local_status.total_difficulty,
            hash: local_status.head,
            ..Default::default()
        };
        let fork_id = self.protocol.inner.fork_filter.fork_id(head);
        let initial_status = local_status.wire_status(self.version, fork_id).encoded();
        let (commands, command_rx) = mpsc::channel(BEACON_COMMAND_QUEUE_CAPACITY);
        let control_events = self.protocol.inner.reserve_control_events();
        let event_budget = self.protocol.inner.peer_event_budget(peer_id);
        // Without a full lifecycle reservation the stream cannot report its own disconnect, so it
        // is declined instead of admitted. Log it: the peer still completes the RLPx
        // handshake, so otherwise this looks like a silently idle beacon connection rather
        // than a peer ceiling.
        let closed = control_events.is_none();
        if closed {
            warn!(
                target: "neox::network::beacon",
                peer_id = %peer_id,
                ?direction,
                admitted_peer_limit =
                    BEACON_CONTROL_EVENT_QUEUE_CAPACITY / BEACON_CONTROL_EVENTS_PER_CONNECTION,
                "Declined beacon stream: no lifecycle event capacity left"
            );
        }

        BeaconConnection {
            conn,
            protocol: self.protocol,
            version: self.version,
            direction,
            peer_id,
            initial_status: Some(initial_status),
            commands,
            command_rx,
            event_budget,
            control_events: control_events.unwrap_or_default(),
            handshake_complete: false,
            closed,
        }
    }
}

/// One multiplexed beacon protocol stream.
#[derive(Debug)]
pub struct BeaconConnection {
    conn: ProtocolConnection,
    protocol: BeaconProtocol,
    version: BeaconVersion,
    direction: Direction,
    peer_id: PeerId,
    initial_status: Option<BytesMut>,
    commands: mpsc::Sender<BeaconCommand>,
    command_rx: mpsc::Receiver<BeaconCommand>,
    event_budget: Arc<PeerEventBudget>,
    control_events: Vec<mpsc::OwnedPermit<QueuedBeaconEvent>>,
    handshake_complete: bool,
    closed: bool,
}

impl BeaconConnection {
    fn emit_data(
        &self,
        event: BeaconEvent,
        wire_size: usize,
        droppable: bool,
    ) -> Result<(), BeaconProtocolViolation> {
        self.protocol.inner.queue_event(event, &self.event_budget, wire_size, droppable)
    }

    fn emit_control(&mut self, event: BeaconEvent) {
        self.control_events
            .pop()
            .expect("admitted Beacon connection reserves all lifecycle events")
            .send(QueuedBeaconEvent {
                event: Some(event),
                _data_slot: None,
                _droppable_slot: None,
                _peer_slot: None,
                _global_bytes: None,
                _droppable_bytes: None,
                _peer_bytes: None,
                _peer_budget: None,
            });
    }

    fn close_with(&mut self, reason: BeaconProtocolViolation) -> Poll<Option<BytesMut>> {
        warn!(target: "neox::network::beacon", peer_id=%self.peer_id, ?reason, "Closing invalid beacon stream");
        self.emit_control(BeaconEvent::Violation { peer_id: self.peer_id, reason });
        self.closed = true;
        Poll::Ready(None)
    }

    fn validate_status(&self, mut payload: &[u8]) -> Result<BeaconStatus, BeaconProtocolViolation> {
        let status = BeaconStatus::decode(self.version, &mut payload)
            .map_err(|error| BeaconProtocolViolation::InvalidRlp(error.to_string()))?;
        if !payload.is_empty() {
            return Err(BeaconProtocolViolation::InvalidRlp("trailing bytes".to_string()));
        }

        let expected_version = self.version as u32;
        if status.protocol_version() != expected_version {
            return Err(BeaconProtocolViolation::VersionMismatch {
                expected: expected_version,
                received: status.protocol_version(),
            });
        }

        let local = self.protocol.status();
        if status.network_id() != local.network_id {
            return Err(BeaconProtocolViolation::NetworkMismatch {
                expected: local.network_id,
                received: status.network_id(),
            });
        }
        if status.genesis() != local.genesis {
            return Err(BeaconProtocolViolation::GenesisMismatch {
                expected: local.genesis,
                received: status.genesis(),
            });
        }

        let head = Head {
            number: local.head_number,
            timestamp: local.head_timestamp,
            total_difficulty: local.total_difficulty,
            hash: local.head,
            ..Default::default()
        };
        if !self.protocol.inner.fork_filter.validate(status.fork_id(), head) {
            warn!(
                target: "neox::network::beacon",
                peer_id = %self.peer_id,
                remote_fork_id = ?status.fork_id(),
                local_fork_id = ?self.protocol.inner.fork_filter.fork_id(head),
                local_head_number = local.head_number,
                local_head_timestamp = local.head_timestamp,
                "Rejected Neo X beacon fork id"
            );
            return Err(BeaconProtocolViolation::ForkIdRejected);
        }
        Ok(status)
    }

    fn handle_message(&mut self, mut frame: BytesMut) -> Result<(), BeaconProtocolViolation> {
        if frame.is_empty() {
            return Err(BeaconProtocolViolation::EmptyMessage);
        }
        if frame.len() - 1 > MAX_MESSAGE_SIZE {
            return Err(BeaconProtocolViolation::MessageTooLarge(frame.len() - 1));
        }

        let wire_size = frame.len();
        let raw_id = frame.get_u8();
        let message_id =
            BeaconMessageId::try_from(raw_id).map_err(BeaconProtocolViolation::InvalidMessageId)?;

        if !self.handshake_complete {
            if message_id != BeaconMessageId::Status {
                return Err(BeaconProtocolViolation::MissingStatus(raw_id));
            }
            let status = self.validate_status(&frame)?;
            self.protocol.inner.peers.lock().expect("beacon peers lock poisoned").insert(
                self.peer_id,
                BeaconPeerCommands { version: self.version, sender: self.commands.clone() },
            );
            self.handshake_complete = true;
            debug!(target: "neox::network::beacon", peer_id=%self.peer_id, version=?self.version, head=%status.head(), head_number=?status.head_number(), "Neo X beacon handshake completed");
            self.emit_control(BeaconEvent::Established {
                peer_id: self.peer_id,
                direction: self.direction,
                version: self.version,
                status,
            });
            return Ok(());
        }

        let message = DecodedMessage::decode(self.version, message_id, &frame)
            .map_err(|error| BeaconProtocolViolation::InvalidRlp(error.to_string()))?;
        let event = match message {
            DecodedMessage::NewBlockHashes(announcement) => {
                BeaconEvent::NewBlockHashes { peer_id: self.peer_id, announcement }
            }
            DecodedMessage::NewBlock(packet) => {
                BeaconEvent::NewBlock { peer_id: self.peer_id, packet }
            }
            DecodedMessage::NewBlobsRoot(announcement) => {
                BeaconEvent::NewBlobsRoot { peer_id: self.peer_id, announcement }
            }
            DecodedMessage::GetBlobs(request) => {
                if !(1..=MAX_BLOB_REQUEST_TTL).contains(&request.ttl) {
                    return Err(BeaconProtocolViolation::InvalidBlobTtl(request.ttl));
                }
                BeaconEvent::GetBlobs { peer_id: self.peer_id, request }
            }
            DecodedMessage::Blobs(response) => {
                BeaconEvent::Blobs { peer_id: self.peer_id, response }
            }
            DecodedMessage::GetBatchBlobs(request) => {
                BeaconEvent::GetBatchBlobs { peer_id: self.peer_id, request }
            }
            DecodedMessage::BatchBlobs(response) => {
                BeaconEvent::BatchBlobs { peer_id: self.peer_id, response }
            }
            DecodedMessage::GetTransactions(request) => {
                BeaconEvent::GetTransactions { peer_id: self.peer_id, request }
            }
            DecodedMessage::Transactions(response) => {
                BeaconEvent::Transactions { peer_id: self.peer_id, response }
            }
        };
        let droppable =
            matches!(message_id, BeaconMessageId::NewBlockHashes | BeaconMessageId::NewBlobsRoot);
        self.emit_data(event, wire_size, droppable)
    }
}

impl Stream for BeaconConnection {
    type Item = BytesMut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        if let Some(status) = self.initial_status.take() {
            return Poll::Ready(Some(status));
        }

        loop {
            if self.handshake_complete {
                while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
                    if let Some(frame) = command.encoded(self.version) {
                        return Poll::Ready(Some(frame));
                    }
                }
            }

            let Some(frame) = ready!(self.conn.poll_next_unpin(cx)) else {
                self.closed = true;
                return Poll::Ready(None);
            };
            if let Err(reason) = self.handle_message(frame) {
                return self.close_with(reason);
            }
        }
    }
}

impl Drop for BeaconConnection {
    fn drop(&mut self) {
        if self.handshake_complete {
            self.protocol
                .inner
                .peers
                .lock()
                .expect("beacon peers lock poisoned")
                .remove(&self.peer_id);
            self.emit_control(BeaconEvent::Disconnected {
                peer_id: self.peer_id,
                version: self.version,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions_request;
    use alloy_primitives::{b256, U256};

    fn protocol() -> BeaconProtocol {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let genesis = chain_spec.inner.genesis_hash();
        BeaconProtocol::new(
            chain_spec,
            BeaconLocalStatus {
                network_id: 47_763,
                total_difficulty: U256::from(1),
                head: genesis,
                head_number: 0,
                head_timestamp: 0,
                genesis,
                blob_sync: true,
            },
        )
        .0
    }

    fn mixed_fork_spec() -> Arc<NeoXChainSpec> {
        let raw = r#"{
            "config": {
                "chainId": 47763777,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "shanghaiTime": 0,
                "cancunTime": 1763000000,
                "pragueTime": 1763000000,
                "osakaTime": 1782700000,
                "neoXDKGBlock": 1000000000000,
                "neoXAMEVBlock": 1000000000000,
                "neoXEthSigBlock": 1000000000000,
                "dbft": {
                    "period": 1,
                    "standbyValidators": [
                        "0x34a3b2abb99b4c128acf61dcbbd1fcac0b161652",
                        "0x641ec1c538fa17e6ad8193c9b580f6850b114280",
                        "0xe3973f57e8a0aa312c1917ab0e6a05d8b6af6609",
                        "0xa61ac4a4f006f4fceeb72ee0012a2d3367168d10",
                        "0xe6d1a9db6a0893926bd81c0ef93aaaa543c116f0",
                        "0x4fe8af0dbb633283d8e9703668142fd130f2818d",
                        "0x763452f65353fffe73d46539e51a6ddfc0e2c86a"
                    ],
                    "coinbase": "0x1212000000000000000000000000000000000004"
                }
            },
            "gasLimit": "30000000",
            "difficulty": "1",
            "alloc": {}
        }"#;
        let genesis: alloy_genesis::Genesis = serde_json::from_str(raw).unwrap();
        Arc::new(NeoXChainSpec::from_genesis(genesis).unwrap())
    }

    #[test]
    fn fork_id_matches_geth_for_mixed_block_and_time_schedule() {
        let filter = BeaconForkFilter::new(&mixed_fork_spec());
        let fresh = filter.fork_id(Head::default());
        let live =
            filter.fork_id(Head { number: 57, timestamp: 1_784_485_765, ..Default::default() });

        // Geth processes every block fork before any time fork. An already
        // active time fork therefore does not change the checksum while the
        // far-future Neo X block fork is still pending.
        assert_eq!(live, fresh);
        assert_eq!(live.next, 1_000_000_000_000);

        let complete = filter.fork_id(Head {
            number: 1_000_000_000_000,
            timestamp: 1_784_485_765,
            ..Default::default()
        });
        assert_ne!(complete.hash, live.hash);
        assert_eq!(complete.next, 0);
    }

    #[test]
    fn mainnet_fork_ids_match_pinned_geth_vectors() {
        let filter = BeaconForkFilter::new(&NeoXChainSpec::mainnet().unwrap());
        let cases = [
            (0, 0, [0x9e, 0xb2, 0xeb, 0x0c], 3_623_040),
            (3_623_040, 0, [0xfe, 0x22, 0xa6, 0xfc], 3_749_760),
            (3_749_760, 0, [0x02, 0xf8, 0x8f, 0x32], 1_763_000_000),
            (3_749_760, 1_763_000_000, [0xd9, 0xf7, 0xd9, 0xb9], 1_782_700_000),
            (3_749_760, 1_782_700_000, [0x55, 0x02, 0x21, 0xca], 0),
        ];

        for (number, timestamp, hash, next) in cases {
            assert_eq!(
                filter.fork_id(Head { number, timestamp, ..Default::default() }),
                ForkId { hash: ForkHash(hash), next }
            );
        }
    }

    #[test]
    fn fork_id_next_validation_matches_geth() {
        let filter = BeaconForkFilter::new(&NeoXChainSpec::mainnet().unwrap());
        let local_head = Head { number: 3_700_000, timestamp: 1_760_000_000, ..Default::default() };
        let local = filter.fork_id(local_head);

        // Equal checksums tolerate unknown future schedules until their fork
        // point has passed locally, exactly as Geth's rule 1 requires.
        assert!(filter.validate(ForkId { hash: local.hash, next: 0 }, local_head));
        assert!(filter.validate(ForkId { hash: local.hash, next: u64::MAX }, local_head));
        assert!(!filter.validate(ForkId { hash: local.hash, next: local_head.number }, local_head));
        assert!(
            !filter.validate(ForkId { hash: local.hash, next: local_head.timestamp }, local_head)
        );

        // An older checksum is accepted only when `next` names the exact
        // locally following fork; a locally reachable newer checksum is
        // accepted regardless of its `next` value.
        let old_head = Head { number: 1, timestamp: 1, ..Default::default() };
        let old = filter.fork_id(old_head);
        assert!(filter.validate(old, local_head));
        assert!(!filter.validate(ForkId { hash: old.hash, next: old.next + 1 }, local_head));

        let future =
            filter.fork_id(Head { number: u64::MAX, timestamp: u64::MAX, ..Default::default() });
        assert!(filter.validate(ForkId { hash: future.hash, next: 123 }, local_head));
        assert!(!filter
            .validate(ForkId { hash: ForkHash([0xde, 0xad, 0xbe, 0xef]), next: 0 }, local_head));
    }

    #[test]
    fn inbound_event_queue_enforces_count_and_peer_byte_limits() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let genesis = chain_spec.inner.genesis_hash();
        let (protocol, mut receiver) = BeaconProtocol::new(
            chain_spec,
            BeaconLocalStatus {
                network_id: 47_763,
                total_difficulty: U256::from(1),
                head: genesis,
                head_number: 0,
                head_timestamp: 0,
                genesis,
                blob_sync: true,
            },
        );
        let peer_id = PeerId::random();
        let mut control_events = protocol.inner.reserve_control_events().unwrap();
        let event = || BeaconEvent::NewBlobsRoot {
            peer_id,
            announcement: NewBlobsRoot { block_hash: genesis },
        };

        let global_budgets = (0..BEACON_EVENT_QUEUE_CAPACITY)
            .map(|_| Arc::new(PeerEventBudget::new()))
            .collect::<Vec<_>>();
        for budget in &global_budgets {
            protocol.inner.queue_event(event(), budget, 1, false).unwrap();
        }
        assert_eq!(receiver.capacity(), 0);
        let fresh_budget = Arc::new(PeerEventBudget::new());
        assert_eq!(
            protocol.inner.queue_event(event(), &fresh_budget, 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        assert_eq!(protocol.inner.queue_event(event(), &fresh_budget, 1, true), Ok(()));

        receiver.try_recv().unwrap();
        protocol.inner.queue_event(event(), &fresh_budget, 1, false).unwrap();
        control_events.pop().unwrap().send(QueuedBeaconEvent {
            event: Some(BeaconEvent::Disconnected { peer_id, version: BeaconVersion::V2 }),
            _data_slot: None,
            _droppable_slot: None,
            _peer_slot: None,
            _global_bytes: None,
            _droppable_bytes: None,
            _peer_bytes: None,
            _peer_budget: None,
        });
        for _ in 0..BEACON_EVENT_QUEUE_CAPACITY {
            assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::NewBlobsRoot { .. })));
        }
        assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::Disconnected { .. })));

        let peer_budget = Arc::new(PeerEventBudget::new());
        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY {
            protocol.inner.queue_event(event(), &peer_budget, 1, false).unwrap();
        }
        assert_eq!(
            protocol.inner.queue_event(event(), &peer_budget, 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        assert_eq!(protocol.inner.queue_event(event(), &peer_budget, 1, true), Ok(()));
        protocol.inner.queue_event(event(), &fresh_budget, 1, false).unwrap();
        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY + 2 {
            receiver.try_recv().unwrap();
        }

        let reconnect_budget = protocol.inner.peer_event_budget(peer_id);
        let queued_budget = Arc::downgrade(&reconnect_budget);
        protocol.inner.queue_event(event(), &reconnect_budget, 1, false).unwrap();
        drop(reconnect_budget);
        let reconnected_budget = protocol.inner.peer_event_budget(peer_id);
        assert!(Arc::ptr_eq(&queued_budget.upgrade().unwrap(), &reconnected_budget));
        receiver.try_recv().unwrap();

        protocol
            .inner
            .queue_event(event(), &peer_budget, BEACON_PEER_EVENT_BYTE_CAPACITY, false)
            .unwrap();
        assert_eq!(
            protocol.inner.queue_event(event(), &peer_budget, 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        receiver.try_recv().unwrap();
        protocol.inner.queue_event(event(), &peer_budget, 1, false).unwrap();
        receiver.try_recv().unwrap();

        let global_byte_budgets =
            (0..3).map(|_| Arc::new(PeerEventBudget::new())).collect::<Vec<_>>();
        for budget in &global_byte_budgets {
            protocol
                .inner
                .queue_event(event(), budget, BEACON_PEER_EVENT_BYTE_CAPACITY, false)
                .unwrap();
        }
        let remaining = BEACON_EVENT_QUEUE_BYTE_CAPACITY -
            global_byte_budgets.len() * BEACON_PEER_EVENT_BYTE_CAPACITY;
        assert_eq!(
            protocol.inner.queue_event(event(), &fresh_budget, remaining + 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        for _ in &global_byte_budgets {
            receiver.try_recv().unwrap();
        }
    }

    #[test]
    fn droppable_announcements_preserve_required_event_capacity() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let genesis = chain_spec.inner.genesis_hash();
        let (protocol, mut receiver) = BeaconProtocol::new(
            chain_spec,
            BeaconLocalStatus {
                network_id: 47_763,
                total_difficulty: U256::from(1),
                head: genesis,
                head_number: 0,
                head_timestamp: 0,
                genesis,
                blob_sync: true,
            },
        );
        let event = || BeaconEvent::NewBlobsRoot {
            peer_id: PeerId::random(),
            announcement: NewBlobsRoot { block_hash: genesis },
        };

        let announcement_budgets = (0..BEACON_DROPPABLE_EVENT_QUEUE_CAPACITY)
            .map(|_| Arc::new(PeerEventBudget::new()))
            .collect::<Vec<_>>();
        for budget in &announcement_budgets {
            protocol.inner.queue_event(event(), budget, 1, true).unwrap();
        }
        assert_eq!(receiver.capacity(), BEACON_REQUIRED_EVENT_QUEUE_RESERVE);

        let dropped_budget = Arc::new(PeerEventBudget::new());
        protocol.inner.queue_event(event(), &dropped_budget, 1, true).unwrap();
        assert_eq!(receiver.capacity(), BEACON_REQUIRED_EVENT_QUEUE_RESERVE);

        let required_budget = Arc::new(PeerEventBudget::new());
        protocol.inner.queue_event(event(), &required_budget, 1, false).unwrap();
        assert_eq!(receiver.capacity(), BEACON_REQUIRED_EVENT_QUEUE_RESERVE - 1);
        while receiver.try_recv().is_ok() {}

        let mut remaining = BEACON_DROPPABLE_EVENT_BYTE_CAPACITY;
        while remaining > 0 {
            let wire_size = remaining.min(BEACON_PEER_EVENT_BYTE_CAPACITY);
            let budget = Arc::new(PeerEventBudget::new());
            protocol.inner.queue_event(event(), &budget, wire_size, true).unwrap();
            remaining -= wire_size;
        }
        assert_eq!(protocol.inner.droppable_bytes.available_permits(), 0);
        assert_eq!(
            protocol.inner.event_bytes.available_permits(),
            BEACON_REQUIRED_EVENT_BYTE_RESERVE
        );

        protocol.inner.queue_event(event(), &dropped_budget, 1, true).unwrap();
        assert_eq!(
            protocol.inner.event_bytes.available_permits(),
            BEACON_REQUIRED_EVENT_BYTE_RESERVE
        );
        protocol
            .inner
            .queue_event(event(), &required_budget, BEACON_REQUIRED_EVENT_BYTE_RESERVE, false)
            .unwrap();
        assert_eq!(protocol.inner.event_bytes.available_permits(), 0);
    }

    #[test]
    fn droppable_announcements_preserve_same_peer_required_capacity() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let genesis = chain_spec.inner.genesis_hash();
        let (protocol, mut receiver) = BeaconProtocol::new(
            chain_spec,
            BeaconLocalStatus {
                network_id: 47_763,
                total_difficulty: U256::from(1),
                head: genesis,
                head_number: 0,
                head_timestamp: 0,
                genesis,
                blob_sync: true,
            },
        );
        let peer_id = PeerId::random();
        let peer_budget = protocol.inner.peer_event_budget(peer_id);
        let droppable_event = || BeaconEvent::NewBlobsRoot {
            peer_id,
            announcement: NewBlobsRoot { block_hash: genesis },
        };
        let required_event = || BeaconEvent::GetTransactions {
            peer_id,
            request: transactions_request(1, Vec::new()),
        };

        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY {
            protocol.inner.queue_event(droppable_event(), &peer_budget, 1, true).unwrap();
        }
        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY {
            protocol.inner.queue_event(required_event(), &peer_budget, 1, false).unwrap();
        }
        let retained_capacity = BEACON_EVENT_QUEUE_CAPACITY - 2 * BEACON_PEER_EVENT_QUEUE_CAPACITY;
        assert_eq!(peer_budget.droppable_slots.available_permits(), 0);
        assert_eq!(peer_budget.required_slots.available_permits(), 0);
        assert_eq!(receiver.capacity(), retained_capacity);
        assert_eq!(protocol.inner.queue_event(droppable_event(), &peer_budget, 1, true), Ok(()));
        assert_eq!(receiver.capacity(), retained_capacity);
        assert_eq!(
            protocol.inner.queue_event(required_event(), &peer_budget, 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        assert_eq!(receiver.capacity(), retained_capacity);

        let queued_budget = Arc::downgrade(&peer_budget);
        drop(peer_budget);
        let peer_budget = protocol.inner.peer_event_budget(peer_id);
        assert!(Arc::ptr_eq(&queued_budget.upgrade().unwrap(), &peer_budget));

        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY {
            assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::NewBlobsRoot { .. })));
        }
        for _ in 0..BEACON_PEER_EVENT_QUEUE_CAPACITY {
            assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::GetTransactions { .. })));
        }
        assert!(matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        assert_eq!(receiver.capacity(), BEACON_EVENT_QUEUE_CAPACITY);

        protocol
            .inner
            .queue_event(droppable_event(), &peer_budget, BEACON_PEER_EVENT_BYTE_CAPACITY, true)
            .unwrap();
        protocol
            .inner
            .queue_event(required_event(), &peer_budget, BEACON_PEER_EVENT_BYTE_CAPACITY, false)
            .unwrap();
        let retained_bytes = 2 * BEACON_PEER_EVENT_BYTE_CAPACITY;
        assert_eq!(peer_budget.droppable_bytes.available_permits(), 0);
        assert_eq!(peer_budget.required_bytes.available_permits(), 0);
        assert_eq!(
            protocol.inner.event_bytes.available_permits(),
            BEACON_EVENT_QUEUE_BYTE_CAPACITY - retained_bytes
        );
        assert_eq!(protocol.inner.queue_event(droppable_event(), &peer_budget, 1, true), Ok(()));
        assert_eq!(
            protocol.inner.queue_event(required_event(), &peer_budget, 1, false),
            Err(BeaconProtocolViolation::InboundQueueSaturated)
        );
        assert_eq!(
            protocol.inner.event_bytes.available_permits(),
            BEACON_EVENT_QUEUE_BYTE_CAPACITY - retained_bytes
        );
        assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::NewBlobsRoot { .. })));
        assert!(matches!(receiver.try_recv(), Ok(BeaconEvent::GetTransactions { .. })));
        assert!(matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        assert_eq!(receiver.capacity(), BEACON_EVENT_QUEUE_CAPACITY);
        assert_eq!(
            protocol.inner.event_bytes.available_permits(),
            BEACON_EVENT_QUEUE_BYTE_CAPACITY
        );
    }

    #[test]
    fn status_updates_are_visible_to_new_connections() {
        let protocol = protocol();
        let genesis = protocol.status().genesis;
        protocol.update_status(BeaconLocalStatus {
            network_id: 47_763,
            total_difficulty: U256::from(3),
            head: b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            head_number: 1,
            head_timestamp: 5,
            genesis,
            blob_sync: false,
        });
        assert_eq!(protocol.status().head_number, 1);
        assert!(!protocol.status().blob_sync);
    }

    #[test]
    fn commands_are_not_counted_without_completed_peers() {
        let protocol = protocol();
        assert_eq!(protocol.peer_count(), 0);
        assert_eq!(
            protocol.broadcast(BeaconCommand::NewBlobsRoot(NewBlobsRoot {
                block_hash: protocol.status().genesis,
            })),
            0
        );
    }

    #[test]
    fn outbound_queues_are_bounded_and_raw_fanout_shares_payload() {
        let protocol = protocol();
        let first = PeerId::random();
        let second = PeerId::random();
        let (first_sender, mut first_receiver) = mpsc::channel(BEACON_COMMAND_QUEUE_CAPACITY);
        let (second_sender, mut second_receiver) = mpsc::channel(BEACON_COMMAND_QUEUE_CAPACITY);
        protocol.inner.peers.lock().unwrap().extend([
            (first, BeaconPeerCommands { version: BeaconVersion::V2, sender: first_sender }),
            (second, BeaconPeerCommands { version: BeaconVersion::V2, sender: second_sender }),
        ]);

        let payload = Bytes::from(vec![0x42; 1024]);
        let payload_ptr = payload.as_ptr();
        assert_eq!(
            protocol
                .broadcast(BeaconCommand::Raw { message_id: BeaconMessageId::NewBlock, payload }),
            2
        );
        for received in [first_receiver.try_recv().unwrap(), second_receiver.try_recv().unwrap()] {
            let BeaconCommand::Raw { payload, .. } = received else {
                panic!("expected a raw Beacon command")
            };
            assert_eq!(payload.as_ptr(), payload_ptr);
        }

        let command =
            BeaconCommand::NewBlobsRoot(NewBlobsRoot { block_hash: protocol.status().genesis });
        for _ in 0..BEACON_COMMAND_QUEUE_CAPACITY {
            assert!(protocol.send(first, command.clone()));
        }
        assert!(!protocol.send(first, command));
    }

    #[test]
    fn transaction_requests_are_beacon2_only() {
        let request = transactions_request(7, vec![B256::repeat_byte(0x11)]);
        assert!(BeaconCommand::GetTransactions(request.clone())
            .encoded(BeaconVersion::V1)
            .is_none());
        let encoded =
            BeaconCommand::GetTransactions(request.clone()).encoded(BeaconVersion::V2).unwrap();
        assert_eq!(encoded[0], BeaconMessageId::GetTransactions as u8);
        assert_eq!(
            DecodedMessage::decode(
                BeaconVersion::V2,
                BeaconMessageId::GetTransactions,
                &encoded[1..],
            )
            .unwrap(),
            DecodedMessage::GetTransactions(request)
        );
    }
}
