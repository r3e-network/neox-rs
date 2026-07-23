//! Neo X `dbft/0` consensus-message propagation protocol.

use crate::protocol::decode_exact;
use alloy_primitives::{
    bytes::{Buf, BufMut, BytesMut},
    keccak256, Address, Bytes, Signature, B256,
};
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable, RlpEncodable};
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol, Capability,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::{Direction, PeerId};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, RwLock, Weak},
    task::{ready, Context, Poll},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, trace, warn};

/// Maximum payload accepted by Neo X Geth for a `dbft/0` message.
pub const DBFT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
/// Maximum number of verified dBFT message events retained for the sync driver.
pub const DBFT_EVENT_QUEUE_CAPACITY: usize = 64;
/// Maximum aggregate encoded size of retained dBFT message events.
pub const DBFT_EVENT_QUEUE_BYTE_CAPACITY: usize = 32 * 1024 * 1024;
/// Maximum number of queued dBFT message events attributed to one peer.
pub const DBFT_PEER_EVENT_QUEUE_CAPACITY: usize = 32;
/// Maximum aggregate encoded size of queued dBFT message events attributed to one peer.
pub const DBFT_PEER_EVENT_BYTE_CAPACITY: usize = 24 * 1024 * 1024;
/// Maximum aggregate encoded size retained by the verified dBFT message cache.
pub const DBFT_MESSAGE_CACHE_BYTE_CAPACITY: usize = 64 * 1024 * 1024;
/// Maximum number of messages retained by the verified dBFT message cache.
pub const DBFT_MESSAGE_CACHE_CAPACITY: usize = 256;
/// Maximum aggregate encoded size retained by any one peer's outbound command queue.
pub const DBFT_COMMAND_QUEUE_BYTE_CAPACITY: usize = 32 * 1024 * 1024;
const DBFT_MESSAGE_COUNT: u8 = 3;
const DBFT_SENDER_CACHE_CAPACITY: usize = 20;
const DBFT_COMMAND_QUEUE_CAPACITY: usize = 32;
const DBFT_CONTROL_EVENT_QUEUE_CAPACITY: usize = 384;
const DBFT_CONTROL_EVENTS_PER_CONNECTION: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum DbftWireMessageId {
    Announce = 0,
    Get = 1,
    Message = 2,
}

impl TryFrom<u8> for DbftWireMessageId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Announce),
            1 => Ok(Self::Get),
            2 => Ok(Self::Message),
            other => Err(other),
        }
    }
}

/// Neo X dBFT consensus message kind stored in the signed message data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DbftMessageType {
    /// Requests a view change.
    ChangeView = 0x00,
    /// Primary block proposal.
    PrepareRequest = 0x20,
    /// Backup proposal acknowledgement.
    PrepareResponse = 0x21,
    /// Anti-MEV pre-commit share.
    PreCommit = 0x31,
    /// Final block-signature share.
    Commit = 0x30,
    /// Requests recovery state.
    RecoveryRequest = 0x40,
    /// Aggregated recovery state.
    RecoveryMessage = 0x41,
}

impl TryFrom<u8> for DbftMessageType {
    type Error = alloy_rlp::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::ChangeView),
            0x20 => Ok(Self::PrepareRequest),
            0x21 => Ok(Self::PrepareResponse),
            0x31 => Ok(Self::PreCommit),
            0x30 => Ok(Self::Commit),
            0x40 => Ok(Self::RecoveryRequest),
            0x41 => Ok(Self::RecoveryMessage),
            _ => Err(alloy_rlp::Error::Custom("unsupported Neo X dBFT message type")),
        }
    }
}

/// Decoded inner dBFT message header with its type-specific payload retained as raw RLP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbftConsensusData {
    /// Consensus message kind.
    pub message_type: DbftMessageType,
    /// Proposed block height.
    pub block_index: u64,
    /// Index of the sender in the active validator set.
    pub validator_index: u8,
    /// Current dBFT view.
    pub view_number: u8,
    /// Complete RLP item for the type-specific payload.
    pub payload: Bytes,
}

impl Encodable for DbftConsensusData {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.payload_length() }.encode(out);
        (self.message_type as u8).encode(out);
        self.block_index.encode(out);
        self.validator_index.encode(out);
        self.view_number.encode(out);
        out.put_slice(&self.payload);
    }

    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl Decodable for DbftConsensusData {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let message_type = u8::decode(&mut payload)?;
        let block_index = u64::decode(&mut payload)?;
        let validator_index = u8::decode(&mut payload)?;
        let view_number = u8::decode(&mut payload)?;
        let encoded_payload = take_rlp_item(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch { expected: 5, got: 6 });
        }
        Ok(Self {
            message_type: DbftMessageType::try_from(message_type)?,
            block_index,
            validator_index,
            view_number,
            payload: Bytes::copy_from_slice(encoded_payload),
        })
    }
}

/// Takes one complete RLP item without walking any nested list payload.
fn take_rlp_item<'a>(buf: &mut &'a [u8]) -> alloy_rlp::Result<&'a [u8]> {
    let item = *buf;
    let header = Header::decode(buf)?;
    let header_length = item.len() - buf.len();
    let item_length = header_length + header.payload_length;
    let (item, remaining) = item.split_at(item_length);
    *buf = remaining;
    Ok(item)
}

impl DbftConsensusData {
    fn payload_length(&self) -> usize {
        (self.message_type as u8).length() +
            self.block_index.length() +
            self.validator_index.length() +
            self.view_number.length() +
            self.payload.len()
    }
}

/// Signed outer dBFT extensible payload propagated by `dbft/0`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DbftMessage {
    /// First canonical height at which the payload is valid.
    pub valid_block_start: u64,
    /// Height after which the payload is stale; also the proposed block height.
    pub valid_block_end: u64,
    /// Consensus account signing the payload.
    pub sender: Address,
    /// RLP-encoded [`DbftConsensusData`].
    pub data: Bytes,
    /// Recoverable secp256k1 signature over [`DbftMessage::hash`].
    pub witness: Bytes,
}

impl DbftMessage {
    /// Returns the Geth-compatible hash of the message with an empty witness.
    pub fn hash(&self) -> B256 {
        let mut unsigned = self.clone();
        unsigned.witness = Bytes::new();
        let mut encoded = Vec::with_capacity(unsigned.length());
        unsigned.encode(&mut encoded);
        keccak256(encoded)
    }

    /// Decodes and validates the generic inner dBFT message header.
    pub fn consensus_data(&self) -> alloy_rlp::Result<DbftConsensusData> {
        let data = decode_exact::<DbftConsensusData>(&self.data)?;
        if data.block_index != self.valid_block_end {
            return Err(alloy_rlp::Error::Custom(
                "dBFT inner block index does not match validity end",
            ));
        }
        Ok(data)
    }

    /// Recovers the witness and checks that it belongs to `sender`.
    pub fn verify_witness(&self) -> Result<(), DbftProtocolViolation> {
        let raw: &[u8; 65] = self
            .witness
            .as_ref()
            .try_into()
            .map_err(|_| DbftProtocolViolation::InvalidWitnessLength(self.witness.len()))?;
        let parity = match raw[64] {
            0 => false,
            1 => true,
            value => return Err(DbftProtocolViolation::InvalidRecoveryId(value)),
        };
        let signature = Signature::from_bytes_and_parity(raw, parity);
        let recovered = signature
            .recover_address_from_prehash(&self.hash())
            .map_err(|_| DbftProtocolViolation::InvalidWitness)?;
        if recovered != self.sender {
            return Err(DbftProtocolViolation::SenderMismatch { expected: self.sender, recovered });
        }
        Ok(())
    }
}

/// Validated dBFT network event.
#[derive(Debug, Clone)]
pub enum DbftEvent {
    /// A peer negotiated `dbft/0`.
    Established {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Connection direction.
        direction: Direction,
    },
    /// A peer disconnected.
    Disconnected {
        /// Remote peer identity.
        peer_id: PeerId,
    },
    /// A new cryptographically valid consensus payload was received.
    Message {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Verified message.
        message: Arc<DbftMessage>,
    },
    /// An invalid stream was closed.
    Violation {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Protocol violation.
        reason: DbftProtocolViolation,
    },
}

#[derive(Debug)]
struct QueuedDbftEvent {
    event: Option<DbftEvent>,
    _data_slot: Option<OwnedSemaphorePermit>,
    _peer_slot: Option<OwnedSemaphorePermit>,
    _event_bytes: Option<OwnedSemaphorePermit>,
    _peer_bytes: Option<OwnedSemaphorePermit>,
    _peer_budget: Option<Arc<DbftPeerEventBudget>>,
}

impl QueuedDbftEvent {
    fn into_event(mut self) -> DbftEvent {
        self.event.take().expect("queued dBFT event must be present")
    }
}

#[derive(Debug)]
struct ReservedDbftMessageEvent {
    channel: mpsc::OwnedPermit<QueuedDbftEvent>,
    data_slot: OwnedSemaphorePermit,
    peer_slot: OwnedSemaphorePermit,
    event_bytes: Option<OwnedSemaphorePermit>,
    peer_bytes: Option<OwnedSemaphorePermit>,
    peer_budget: Arc<DbftPeerEventBudget>,
}

impl ReservedDbftMessageEvent {
    fn send(self, peer_id: PeerId, message: Arc<DbftMessage>) {
        let Self { channel, data_slot, peer_slot, event_bytes, peer_bytes, peer_budget } = self;
        channel.send(QueuedDbftEvent {
            event: Some(DbftEvent::Message { peer_id, message }),
            _data_slot: Some(data_slot),
            _peer_slot: Some(peer_slot),
            _event_bytes: event_bytes,
            _peer_bytes: peer_bytes,
            _peer_budget: Some(peer_budget),
        });
    }
}

/// Bounded receiver for validated dBFT events.
///
/// Count and encoded-byte reservations are released when a message event is dequeued, before the
/// sync driver begins consensus processing. Peer lifecycle events use separately reserved channel
/// capacity and do not consume the message-event budget.
#[derive(Debug)]
pub struct DbftEventReceiver {
    receiver: mpsc::Receiver<QueuedDbftEvent>,
    data_slots: Arc<Semaphore>,
    event_bytes: Arc<Semaphore>,
}

impl DbftEventReceiver {
    /// Receives the next validated event.
    pub async fn recv(&mut self) -> Option<DbftEvent> {
        self.receiver.recv().await.map(QueuedDbftEvent::into_event)
    }

    /// Attempts to receive an event without waiting.
    pub fn try_recv(&mut self) -> Result<DbftEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv().map(QueuedDbftEvent::into_event)
    }

    /// Returns the remaining message-event count capacity.
    pub fn capacity(&self) -> usize {
        self.data_slots.available_permits()
    }

    /// Returns the configured message-event count capacity.
    pub const fn max_capacity(&self) -> usize {
        DBFT_EVENT_QUEUE_CAPACITY
    }

    /// Returns the remaining encoded-byte capacity for message events.
    pub fn byte_capacity(&self) -> usize {
        self.event_bytes.available_permits()
    }

    /// Returns the configured encoded-byte capacity for message events.
    pub const fn max_byte_capacity(&self) -> usize {
        DBFT_EVENT_QUEUE_BYTE_CAPACITY
    }
}

/// Commands routed to dBFT peers.
#[derive(Debug, Clone)]
pub enum DbftCommand {
    /// Announces a cached message hash.
    Announce(B256),
    /// Requests a message by hash.
    Get(B256),
    /// Sends a complete signed message.
    Message(Arc<DbftMessage>),
}

impl DbftCommand {
    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Announce(hash) | Self::Get(hash) => hash.length(),
            Self::Message(message) => message.length(),
        }
    }

    fn encoded(self) -> BytesMut {
        match self {
            Self::Announce(hash) => encode_frame(DbftWireMessageId::Announce, &hash),
            Self::Get(hash) => encode_frame(DbftWireMessageId::Get, &hash),
            Self::Message(message) => encode_frame(DbftWireMessageId::Message, message.as_ref()),
        }
    }
}

#[derive(Debug)]
struct DbftPeerEventBudget {
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

impl DbftPeerEventBudget {
    fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(DBFT_PEER_EVENT_QUEUE_CAPACITY)),
            bytes: Arc::new(Semaphore::new(DBFT_PEER_EVENT_BYTE_CAPACITY)),
        }
    }
}

#[derive(Debug)]
struct CachedDbftMessage {
    message: Arc<DbftMessage>,
    encoded_size: usize,
}

#[derive(Debug, Default)]
struct DbftMessageCache {
    messages: HashMap<B256, CachedDbftMessage>,
    senders: HashMap<Address, VecDeque<B256>>,
    order: VecDeque<B256>,
    retained_bytes: usize,
}

impl DbftMessageCache {
    fn clear(&mut self) {
        self.messages.clear();
        self.senders.clear();
        self.order.clear();
        self.retained_bytes = 0;
    }

    fn get(&self, hash: &B256) -> Option<Arc<DbftMessage>> {
        self.messages.get(hash).map(|cached| Arc::clone(&cached.message))
    }

    fn contains(&self, hash: &B256) -> bool {
        self.messages.contains_key(hash)
    }

    fn remove(&mut self, hash: &B256) -> Option<Arc<DbftMessage>> {
        let cached = self.messages.remove(hash)?;
        self.retained_bytes = self.retained_bytes.saturating_sub(cached.encoded_size);
        let sender = cached.message.sender;
        if let Some(hashes) = self.senders.get_mut(&sender) {
            hashes.retain(|candidate| candidate != hash);
            if hashes.is_empty() {
                self.senders.remove(&sender);
            }
        }
        if let Some(position) = self.order.iter().position(|candidate| candidate == hash) {
            self.order.remove(position);
        }
        Some(cached.message)
    }

    fn retain(&mut self, mut keep: impl FnMut(&Arc<DbftMessage>) -> bool) {
        let stale = self
            .messages
            .iter()
            .filter_map(|(hash, cached)| (!keep(&cached.message)).then_some(*hash))
            .collect::<Vec<_>>();
        for hash in stale {
            let _ = self.remove(&hash);
        }
    }

    fn insert(
        &mut self,
        hash: B256,
        message: Arc<DbftMessage>,
    ) -> Result<CacheMessageOutcome, usize> {
        if self.messages.contains_key(&hash) {
            return Ok(CacheMessageOutcome::Duplicate);
        }
        let encoded_size = message.length();
        if encoded_size > DBFT_MESSAGE_CACHE_BYTE_CAPACITY {
            return Err(encoded_size);
        }
        let sender = message.sender;
        let sender_evicted = self
            .senders
            .get(&sender)
            .filter(|hashes| hashes.len() >= DBFT_SENDER_CACHE_CAPACITY)
            .and_then(|hashes| hashes.front().copied());
        if let Some(evicted) = sender_evicted {
            let _ = self.remove(&evicted);
        }
        while self.messages.len() >= DBFT_MESSAGE_CACHE_CAPACITY ||
            self.retained_bytes.saturating_add(encoded_size) > DBFT_MESSAGE_CACHE_BYTE_CAPACITY
        {
            let Some(evicted) = self.order.front().copied() else { break };
            let _ = self.remove(&evicted);
        }
        self.retained_bytes = self.retained_bytes.saturating_add(encoded_size);
        self.order.push_back(hash);
        self.senders.entry(sender).or_default().push_back(hash);
        self.messages.insert(hash, CachedDbftMessage { message, encoded_size });
        Ok(CacheMessageOutcome::Inserted)
    }
}

#[derive(Debug)]
struct QueuedDbftCommand {
    command: Option<DbftCommand>,
    _bytes: Option<OwnedSemaphorePermit>,
}

impl QueuedDbftCommand {
    fn into_command(mut self) -> DbftCommand {
        self.command.take().expect("queued dBFT command must be present")
    }
}

#[derive(Debug, Clone)]
struct DbftPeerCommands {
    sender: mpsc::Sender<QueuedDbftCommand>,
    bytes: Arc<Semaphore>,
}

impl DbftPeerCommands {
    fn try_send(&self, command: DbftCommand) -> Result<(), DbftProtocolViolation> {
        let permits = u32::try_from(command.encoded_len())
            .map_err(|_| DbftProtocolViolation::OutboundQueueSaturated)?;
        let bytes = if permits == 0 {
            None
        } else {
            Some(
                Arc::clone(&self.bytes)
                    .try_acquire_many_owned(permits)
                    .map_err(|_| DbftProtocolViolation::OutboundQueueSaturated)?,
            )
        };
        self.sender
            .try_send(QueuedDbftCommand { command: Some(command), _bytes: bytes })
            .map_err(|_| DbftProtocolViolation::OutboundQueueSaturated)
    }
}

/// `dbft/0` stream violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbftProtocolViolation {
    /// Empty capability frame.
    EmptyMessage,
    /// Payload exceeds four MiB.
    MessageTooLarge(usize),
    /// Unknown message identifier.
    InvalidMessageId(u8),
    /// Malformed RLP.
    InvalidRlp(String),
    /// Witness is not 65 bytes.
    InvalidWitnessLength(usize),
    /// Signature recovery ID is not zero or one.
    InvalidRecoveryId(u8),
    /// Signature recovery failed.
    InvalidWitness,
    /// Recovered account differs from the declared sender.
    SenderMismatch {
        /// Account declared in the message.
        expected: Address,
        /// Account recovered from the witness.
        recovered: Address,
    },
    /// Message is outside its validity range.
    InvalidHeight {
        /// Current local height.
        current: u64,
        /// First valid height.
        start: u64,
        /// Exclusive ending height.
        end: u64,
    },
    /// The bounded network-to-consensus event queue cannot accept another message from this peer.
    InboundQueueSaturated,
    /// The bounded outbound queue cannot retain another command for this peer.
    OutboundQueueSaturated,
    /// The full node is syncing or has not loaded the current Governance validator set.
    ConsensusInactive,
    /// Governance returned an empty or duplicate validator set.
    InvalidValidatorSet,
    /// Inner validator index is not present in the current Governance set.
    ValidatorIndexOutOfBounds {
        /// Received index.
        index: u8,
        /// Active validator count.
        validator_count: usize,
    },
    /// The signed sender does not match the validator at the declared index.
    UnauthorizedValidator {
        /// Declared validator index.
        index: u8,
        /// Expected validator account.
        expected: Address,
        /// Recovered message sender.
        actual: Address,
    },
}

#[derive(Debug)]
struct DbftProtocolInner {
    admission: RwLock<DbftAdmission>,
    events: mpsc::Sender<QueuedDbftEvent>,
    data_slots: Arc<Semaphore>,
    event_bytes: Arc<Semaphore>,
    peer_event_budgets: Mutex<HashMap<PeerId, Weak<DbftPeerEventBudget>>>,
    peers: Mutex<HashMap<PeerId, DbftPeerCommands>>,
    cache: Mutex<DbftMessageCache>,
}

#[derive(Debug)]
struct DbftAdmission {
    height: u64,
    validators: Option<Vec<Address>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheMessageOutcome {
    Inserted,
    Duplicate,
    OutsideActiveRound { current: u64 },
}

/// Shared Neo X `dbft/0` service, verified-message cache, and peer command handle.
#[derive(Debug, Clone)]
pub struct DbftProtocol {
    inner: Arc<DbftProtocolInner>,
}

impl DbftProtocol {
    /// Creates a dBFT protocol service at the current canonical height.
    pub fn new(height: u64) -> (Self, DbftEventReceiver) {
        let (events, receiver) =
            mpsc::channel(DBFT_EVENT_QUEUE_CAPACITY + DBFT_CONTROL_EVENT_QUEUE_CAPACITY);
        let data_slots = Arc::new(Semaphore::new(DBFT_EVENT_QUEUE_CAPACITY));
        let event_bytes = Arc::new(Semaphore::new(DBFT_EVENT_QUEUE_BYTE_CAPACITY));
        let protocol = Self {
            inner: Arc::new(DbftProtocolInner {
                admission: RwLock::new(DbftAdmission { height, validators: None }),
                events,
                data_slots: Arc::clone(&data_slots),
                event_bytes: Arc::clone(&event_bytes),
                peer_event_budgets: Mutex::new(HashMap::new()),
                peers: Mutex::new(HashMap::new()),
                cache: Mutex::new(DbftMessageCache::default()),
            }),
        };
        (protocol, DbftEventReceiver { receiver, data_slots, event_bytes })
    }

    /// Returns the `dbft/0` `RLPx` handler.
    pub fn handler(&self) -> DbftProtocolHandler {
        DbftProtocolHandler { protocol: self.clone() }
    }

    /// Updates the canonical height and evicts stale cached messages.
    pub fn update_height(&self, height: u64) {
        let mut admission = self.inner.admission.write().expect("dBFT admission lock poisoned");
        admission.height = height;
        self.purge_cached_messages(height, admission.validators.as_deref());
    }

    /// Enables consensus-message admission with the Governance-selected validator set.
    pub fn activate(
        &self,
        height: u64,
        mut validators: Vec<Address>,
    ) -> Result<(), DbftProtocolViolation> {
        if validators.is_empty() {
            return Err(DbftProtocolViolation::InvalidValidatorSet);
        }
        validators.sort_unstable();
        if validators.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DbftProtocolViolation::InvalidValidatorSet);
        }
        let mut admission = self.inner.admission.write().expect("dBFT admission lock poisoned");
        admission.height = height;
        self.purge_cached_messages(height, Some(&validators));
        admission.validators = Some(validators);
        Ok(())
    }

    /// Disables dBFT admission while the canonical state is unavailable or still syncing.
    pub fn deactivate(&self) {
        let mut admission = self.inner.admission.write().expect("dBFT admission lock poisoned");
        admission.validators = None;
        self.inner.cache.lock().expect("dBFT cache lock poisoned").clear();
    }

    /// Returns whether a current validator set is available for message admission.
    pub fn is_active(&self) -> bool {
        self.inner.admission.read().expect("dBFT admission lock poisoned").validators.is_some()
    }

    /// Returns a verified cached message.
    pub fn get(&self, hash: B256) -> Option<Arc<DbftMessage>> {
        let admission = self.inner.admission.read().expect("dBFT admission lock poisoned");
        let validators = admission.validators.as_deref()?;
        let message = self.inner.cache.lock().expect("dBFT cache lock poisoned").get(&hash)?;
        if !is_next_height_message(admission.height, message.valid_block_end) ||
            Self::validate_height(admission.height, &message).is_err()
        {
            return None;
        }
        let data = message.consensus_data().ok()?;
        Self::validate_sender_against(validators, &message, &data).ok()?;
        Some(message)
    }

    /// Verifies, caches, and announces a locally produced consensus message.
    pub fn publish(&self, message: DbftMessage) -> Result<bool, DbftProtocolViolation> {
        let data = self.validate_message(&message)?;
        self.validate_sender(&message, &data)?;
        Self::validate_payload(&data)?;
        let hash = message.hash();
        let start = message.valid_block_start;
        let end = message.valid_block_end;
        let inserted = match self.cache_message(hash, Arc::new(message), &data)? {
            CacheMessageOutcome::Inserted => true,
            CacheMessageOutcome::Duplicate => false,
            CacheMessageOutcome::OutsideActiveRound { current } => {
                return Err(DbftProtocolViolation::InvalidHeight { current, start, end })
            }
        };
        if inserted {
            let peers = self.peer_count();
            let sent = self.broadcast(DbftCommand::Announce(hash));
            if sent < peers {
                debug!(
                    target: "neox::network::dbft",
                    sent,
                    peers,
                    "dBFT announcement was not queued for every peer"
                );
            }
        }
        Ok(inserted)
    }

    /// Sends a command to one negotiated peer.
    pub fn send(&self, peer_id: PeerId, command: DbftCommand) -> bool {
        self.inner
            .peers
            .lock()
            .expect("dBFT peers lock poisoned")
            .get(&peer_id)
            .is_some_and(|peer| peer.try_send(command).is_ok())
    }

    /// Broadcasts a command to all dBFT peers.
    pub fn broadcast(&self, command: DbftCommand) -> usize {
        self.inner
            .peers
            .lock()
            .expect("dBFT peers lock poisoned")
            .values()
            .filter(|peer| peer.try_send(command.clone()).is_ok())
            .count()
    }

    /// Number of negotiated dBFT peers.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.lock().expect("dBFT peers lock poisoned").len()
    }

    fn validate_message(
        &self,
        message: &DbftMessage,
    ) -> Result<DbftConsensusData, DbftProtocolViolation> {
        if message.length() > DBFT_MAX_MESSAGE_SIZE {
            return Err(DbftProtocolViolation::MessageTooLarge(message.length()));
        }
        message.verify_witness()?;
        message
            .consensus_data()
            .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))
    }

    const fn validate_height(
        current: u64,
        message: &DbftMessage,
    ) -> Result<(), DbftProtocolViolation> {
        if current < message.valid_block_start || message.valid_block_end < current {
            return Err(DbftProtocolViolation::InvalidHeight {
                current,
                start: message.valid_block_start,
                end: message.valid_block_end,
            });
        }
        Ok(())
    }

    /// Fully decodes the typed payload to reject malformed bodies.
    ///
    /// A `RecoveryMessage` body runs a BLS12-381 subgroup check on every embedded decryption share,
    /// so this is the expensive step. It runs only after [`Self::validate_sender`] authorizes the
    /// message against the active validator set, so an unauthenticated peer cannot force the work
    /// (a `dbft/0` peer without a validator key is rejected first by the cheap sender check). This
    /// mirrors Neo X Geth, which only decodes recovery payloads from accountable validators.
    fn validate_payload(data: &DbftConsensusData) -> Result<(), DbftProtocolViolation> {
        data.decoded_payload()
            .map(|_| ())
            .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))
    }

    fn validate_sender(
        &self,
        message: &DbftMessage,
        data: &DbftConsensusData,
    ) -> Result<u64, DbftProtocolViolation> {
        let admission = self.inner.admission.read().expect("dBFT admission lock poisoned");
        Self::validate_height(admission.height, message)?;
        let validators =
            admission.validators.as_ref().ok_or(DbftProtocolViolation::ConsensusInactive)?;
        Self::validate_sender_against(validators, message, data)?;
        Ok(admission.height)
    }

    fn validate_sender_against(
        validators: &[Address],
        message: &DbftMessage,
        data: &DbftConsensusData,
    ) -> Result<(), DbftProtocolViolation> {
        let expected = validators.get(usize::from(data.validator_index)).copied().ok_or(
            DbftProtocolViolation::ValidatorIndexOutOfBounds {
                index: data.validator_index,
                validator_count: validators.len(),
            },
        )?;
        if expected != message.sender {
            return Err(DbftProtocolViolation::UnauthorizedValidator {
                index: data.validator_index,
                expected,
                actual: message.sender,
            });
        }
        Ok(())
    }

    fn cache_message(
        &self,
        hash: B256,
        message: Arc<DbftMessage>,
        data: &DbftConsensusData,
    ) -> Result<CacheMessageOutcome, DbftProtocolViolation> {
        // Recheck admission while holding the read guard through insertion. Activation takes the
        // write guard while replacing the validator set and purging, so a removed validator cannot
        // race rotation and reinsert a message after the purge.
        let admission = self.inner.admission.read().expect("dBFT admission lock poisoned");
        Self::validate_height(admission.height, &message)?;
        let validators =
            admission.validators.as_ref().ok_or(DbftProtocolViolation::ConsensusInactive)?;
        Self::validate_sender_against(validators, &message, data)?;
        if !is_next_height_message(admission.height, message.valid_block_end) {
            return Ok(CacheMessageOutcome::OutsideActiveRound { current: admission.height });
        }
        self.inner
            .cache
            .lock()
            .expect("dBFT cache lock poisoned")
            .insert(hash, message)
            .map_err(DbftProtocolViolation::MessageTooLarge)
    }

    fn purge_cached_messages(&self, height: u64, validators: Option<&[Address]>) {
        self.inner.cache.lock().expect("dBFT cache lock poisoned").retain(|message| {
            is_next_height_message(height, message.valid_block_end) &&
                validators.is_none_or(|validators| {
                    message.consensus_data().is_ok_and(|data| {
                        validators.get(usize::from(data.validator_index)) == Some(&message.sender)
                    })
                })
        });
    }

    fn handle_inbound_message(
        &self,
        peer_id: PeerId,
        message: DbftMessage,
    ) -> Result<(), DbftProtocolViolation> {
        let data = self.validate_message(&message)?;
        let current = match self.validate_sender(&message, &data) {
            Ok(current) => current,
            Err(DbftProtocolViolation::ConsensusInactive) => {
                trace!(target: "neox::network::dbft", %peer_id, height=data.block_index, "Ignoring dBFT message while validator state is unavailable");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        Self::validate_payload(&data)?;

        // Neo X Geth authenticates and structurally validates a message before ignoring the exact
        // finalized-height race. Older messages remain protocol violations.
        if is_exact_late_message(current, message.valid_block_end) {
            return Ok(());
        }
        if !is_next_height_message(current, message.valid_block_end) {
            debug!(
                target: "neox::network::dbft",
                %peer_id,
                current,
                message_end = message.valid_block_end,
                "Ignoring authenticated dBFT message beyond the active round"
            );
            return Ok(());
        }

        let hash = message.hash();
        let wire_size = message.length().saturating_add(1);
        let message = Arc::new(message);
        // Reserve the complete consensus-delivery path before marking a new hash as cached. A full
        // queue must not turn a valid message into a cache hit that was never delivered.
        let event = self.reserve_message_event(peer_id, wire_size)?;
        let inserted = match self.cache_message(hash, Arc::clone(&message), &data)? {
            CacheMessageOutcome::Inserted => true,
            CacheMessageOutcome::Duplicate => false,
            CacheMessageOutcome::OutsideActiveRound { current } => {
                debug!(
                    target: "neox::network::dbft",
                    %peer_id,
                    current,
                    message_end = message.valid_block_end,
                    "Ignoring dBFT message after the active round advanced"
                );
                return Ok(());
            }
        };

        // The cache deduplicates storage and gossip, not state-machine delivery. A validator that
        // retransmits the complete signed message after a view change must reach the state machine
        // again; a bare hash announcement does not have that authority.
        event.send(peer_id, message);
        if inserted {
            let peers = self.peer_count();
            let sent = self.broadcast(DbftCommand::Announce(hash));
            if sent < peers {
                debug!(
                    target: "neox::network::dbft",
                    sent,
                    peers,
                    "dBFT announcement was not queued for every peer"
                );
            }
        }
        Ok(())
    }

    fn handle_announcement(
        &self,
        hash: B256,
        commands: &DbftPeerCommands,
    ) -> Result<(), DbftProtocolViolation> {
        // Announcements are inventory hints. A known hash has already arrived as a fully signed
        // validator message, so replaying it here would let any non-validator peer manufacture
        // fresh consensus events. Explicit full-message retransmissions remain deliverable above.
        let known = self.inner.cache.lock().expect("dBFT cache lock poisoned").contains(&hash);
        if !known {
            commands.try_send(DbftCommand::Get(hash))?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn queue_message_event(
        &self,
        peer_id: PeerId,
        message: Arc<DbftMessage>,
        wire_size: usize,
    ) -> Result<(), DbftProtocolViolation> {
        self.reserve_message_event(peer_id, wire_size)?.send(peer_id, message);
        Ok(())
    }

    fn reserve_message_event(
        &self,
        peer_id: PeerId,
        wire_size: usize,
    ) -> Result<ReservedDbftMessageEvent, DbftProtocolViolation> {
        let peer_budget = self.inner.peer_event_budget(peer_id);
        let data_slot = Arc::clone(&self.inner.data_slots)
            .try_acquire_owned()
            .map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?;
        let peer_slot = Arc::clone(&peer_budget.slots)
            .try_acquire_owned()
            .map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?;
        let permits =
            u32::try_from(wire_size).map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?;
        let event_bytes = if permits == 0 {
            None
        } else {
            Some(
                Arc::clone(&self.inner.event_bytes)
                    .try_acquire_many_owned(permits)
                    .map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?,
            )
        };
        let peer_bytes = if permits == 0 {
            None
        } else {
            Some(
                Arc::clone(&peer_budget.bytes)
                    .try_acquire_many_owned(permits)
                    .map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?,
            )
        };
        let channel = self
            .inner
            .events
            .clone()
            .try_reserve_owned()
            .map_err(|_| DbftProtocolViolation::InboundQueueSaturated)?;
        Ok(ReservedDbftMessageEvent {
            channel,
            data_slot,
            peer_slot,
            event_bytes,
            peer_bytes,
            peer_budget,
        })
    }
}

impl DbftProtocolInner {
    fn peer_event_budget(&self, peer_id: PeerId) -> Arc<DbftPeerEventBudget> {
        let mut budgets = self.peer_event_budgets.lock().expect("dBFT event budgets lock poisoned");
        if let Some(budget) = budgets.get(&peer_id).and_then(Weak::upgrade) {
            return budget;
        }
        budgets.retain(|_, budget| budget.strong_count() > 0);
        let budget = Arc::new(DbftPeerEventBudget::new());
        budgets.insert(peer_id, Arc::downgrade(&budget));
        budget
    }

    fn reserve_control_events(&self) -> Option<Vec<mpsc::OwnedPermit<QueuedDbftEvent>>> {
        let mut permits = Vec::with_capacity(DBFT_CONTROL_EVENTS_PER_CONNECTION);
        for _ in 0..DBFT_CONTROL_EVENTS_PER_CONNECTION {
            permits.push(self.events.clone().try_reserve_owned().ok()?);
        }
        Some(permits)
    }
}

/// Protocol handler for Neo X `dbft/0`.
#[derive(Debug, Clone)]
pub struct DbftProtocolHandler {
    protocol: DbftProtocol,
}

impl ProtocolHandler for DbftProtocolHandler {
    type ConnectionHandler = DbftConnectionHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(DbftConnectionHandler { protocol: self.protocol.clone() })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(DbftConnectionHandler { protocol: self.protocol.clone() })
    }
}

/// Authenticates one negotiated `dbft/0` capability.
#[derive(Debug)]
pub struct DbftConnectionHandler {
    protocol: DbftProtocol,
}

impl ConnectionHandler for DbftConnectionHandler {
    type Connection = DbftConnection;

    fn protocol(&self) -> Protocol {
        Protocol::new(Capability::new_static("dbft", 0), DBFT_MESSAGE_COUNT)
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
        let (command_sender, command_rx) = mpsc::channel(DBFT_COMMAND_QUEUE_CAPACITY);
        let commands = DbftPeerCommands {
            sender: command_sender,
            bytes: Arc::new(Semaphore::new(DBFT_COMMAND_QUEUE_BYTE_CAPACITY)),
        };
        let control_events = self.protocol.inner.reserve_control_events();
        let admitted = control_events.is_some();
        let mut connection = DbftConnection {
            conn,
            protocol: self.protocol,
            peer_id,
            commands,
            command_rx,
            control_events: control_events.unwrap_or_default(),
            admitted,
            closed: !admitted,
        };
        if admitted {
            connection
                .protocol
                .inner
                .peers
                .lock()
                .expect("dBFT peers lock poisoned")
                .insert(peer_id, connection.commands.clone());
            connection.emit_control(DbftEvent::Established { peer_id, direction });
            debug!(target: "neox::network::dbft", %peer_id, "Neo X dbft/0 peer established");
        }
        connection
    }
}

/// One multiplexed Neo X `dbft/0` stream.
#[derive(Debug)]
pub struct DbftConnection {
    conn: ProtocolConnection,
    protocol: DbftProtocol,
    peer_id: PeerId,
    commands: DbftPeerCommands,
    command_rx: mpsc::Receiver<QueuedDbftCommand>,
    control_events: Vec<mpsc::OwnedPermit<QueuedDbftEvent>>,
    admitted: bool,
    closed: bool,
}

impl DbftConnection {
    fn emit_control(&mut self, event: DbftEvent) {
        self.control_events
            .pop()
            .expect("admitted dBFT connection reserves all lifecycle events")
            .send(QueuedDbftEvent {
                event: Some(event),
                _data_slot: None,
                _peer_slot: None,
                _event_bytes: None,
                _peer_bytes: None,
                _peer_budget: None,
            });
    }

    fn close_with(&mut self, reason: DbftProtocolViolation) -> Poll<Option<BytesMut>> {
        warn!(target: "neox::network::dbft", peer_id = %self.peer_id, ?reason, "Closing invalid dbft/0 stream");
        self.emit_control(DbftEvent::Violation { peer_id: self.peer_id, reason });
        self.closed = true;
        Poll::Ready(None)
    }

    fn handle_message(&self, mut frame: BytesMut) -> Result<(), DbftProtocolViolation> {
        if frame.is_empty() {
            return Err(DbftProtocolViolation::EmptyMessage);
        }
        if frame.len() - 1 > DBFT_MAX_MESSAGE_SIZE {
            return Err(DbftProtocolViolation::MessageTooLarge(frame.len() - 1));
        }
        let raw_id = frame.get_u8();
        let message_id =
            DbftWireMessageId::try_from(raw_id).map_err(DbftProtocolViolation::InvalidMessageId)?;
        match message_id {
            DbftWireMessageId::Announce => {
                let hash = decode_exact::<B256>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                self.protocol.handle_announcement(hash, &self.commands)?;
            }
            DbftWireMessageId::Get => {
                let hash = decode_exact::<B256>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                if let Some(message) = self.protocol.get(hash) {
                    self.commands.try_send(DbftCommand::Message(message))?;
                }
            }
            DbftWireMessageId::Message => {
                let message = decode_exact::<DbftMessage>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                self.protocol.handle_inbound_message(self.peer_id, message)?;
            }
        }
        Ok(())
    }
}

impl Stream for DbftConnection {
    type Item = BytesMut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        loop {
            if let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
                return Poll::Ready(Some(command.into_command().encoded()));
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

impl Drop for DbftConnection {
    fn drop(&mut self) {
        if self.admitted {
            self.protocol
                .inner
                .peers
                .lock()
                .expect("dBFT peers lock poisoned")
                .remove(&self.peer_id);
            self.emit_control(DbftEvent::Disconnected { peer_id: self.peer_id });
        }
    }
}

const fn is_exact_late_message(current: u64, message_end: u64) -> bool {
    message_end == current
}

fn is_next_height_message(current: u64, message_end: u64) -> bool {
    current.checked_add(1) == Some(message_end)
}

fn encode_frame<T: Encodable>(message_id: DbftWireMessageId, value: &T) -> BytesMut {
    let mut frame = BytesMut::with_capacity(value.length() + 1);
    frame.put_u8(message_id as u8);
    value.encode(&mut frame);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    struct TestValidator {
        address: Address,
        key: k256::ecdsa::SigningKey,
    }

    fn test_validators(count: u8) -> Vec<TestValidator> {
        let mut validators = (1..=count)
            .map(|byte| {
                let key = k256::ecdsa::SigningKey::from_slice(B256::repeat_byte(byte).as_slice())
                    .unwrap();
                TestValidator { address: Address::from_public_key(key.verifying_key()), key }
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|validator| validator.address);
        validators
    }

    fn signed_consensus_message(
        validator: &TestValidator,
        height: u64,
        validator_index: u8,
        view_number: u8,
        message_type: DbftMessageType,
        payload: Bytes,
    ) -> DbftMessage {
        let data = DbftConsensusData {
            message_type,
            block_index: height,
            validator_index,
            view_number,
            payload,
        };
        let mut encoded_data = Vec::with_capacity(data.length());
        data.encode(&mut encoded_data);
        let mut message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: height,
            sender: validator.address,
            data: encoded_data.into(),
            witness: Bytes::new(),
        };
        let (signature, recovery_id) =
            validator.key.sign_prehash_recoverable(message.hash().as_slice()).unwrap();
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();
        message
    }

    fn signed_message() -> DbftMessage {
        let key = B256::repeat_byte(0x11);
        let signer = k256::ecdsa::SigningKey::from_slice(key.as_slice()).unwrap();
        let sender = Address::from_public_key(signer.verifying_key());
        let data = DbftConsensusData {
            message_type: DbftMessageType::PrepareResponse,
            block_index: 42,
            validator_index: 3,
            view_number: 1,
            payload: Bytes::from(alloy_rlp::encode(B256::repeat_byte(0x22))),
        };
        let mut encoded_data = Vec::new();
        data.encode(&mut encoded_data);
        let mut message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: 42,
            sender,
            data: encoded_data.into(),
            witness: Bytes::new(),
        };
        let (signature, recovery_id) =
            signer.sign_prehash_recoverable(message.hash().as_slice()).unwrap();
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();
        message
    }

    #[test]
    fn consensus_data_preserves_raw_payload_rlp() {
        let message = signed_message();
        let decoded = message.consensus_data().unwrap();
        assert_eq!(decoded.message_type, DbftMessageType::PrepareResponse);
        assert_eq!(decoded.block_index, 42);
        assert_eq!(decoded.validator_index, 3);
        assert_eq!(decoded.view_number, 1);
        assert_eq!(decode_exact::<B256>(&decoded.payload).unwrap(), B256::repeat_byte(0x22));
    }

    #[test]
    fn consensus_data_rejects_many_extra_items_without_materializing_them() {
        let mut payload = Vec::new();
        (DbftMessageType::PrepareResponse as u8).encode(&mut payload);
        42_u64.encode(&mut payload);
        0_u8.encode(&mut payload);
        0_u8.encode(&mut payload);
        Header { list: true, payload_length: 0 }.encode(&mut payload);
        payload.extend(std::iter::repeat_n(0x80, 1_000_000));

        let mut encoded = Vec::new();
        Header { list: true, payload_length: payload.len() }.encode(&mut encoded);
        encoded.extend_from_slice(&payload);
        assert!(matches!(
            decode_exact::<DbftConsensusData>(&encoded),
            Err(alloy_rlp::Error::ListLengthMismatch { expected: 5, got: 6 })
        ));
    }

    #[test]
    fn recovery_payload_is_not_decoded_before_sender_authorization() {
        // Regression for the pre-authorization CPU DoS: a RecoveryMessage body runs a BLS12-381
        // subgroup check per embedded decryption share, so the typed-payload decode must happen
        // only after the cheap sender-authorization check. An unauthenticated `dbft/0` peer
        // must be rejected without the node decoding its payload.
        let attacker_key = B256::repeat_byte(0x99);
        let signer = k256::ecdsa::SigningKey::from_slice(attacker_key.as_slice()).unwrap();
        let attacker = Address::from_public_key(signer.verifying_key());

        // A well-formed outer envelope whose RecoveryMessage payload is a string, not the list the
        // decoder requires: `validate_payload` would error (and, for a real attack, burn CPU).
        let data = DbftConsensusData {
            message_type: DbftMessageType::RecoveryMessage,
            block_index: 10,
            validator_index: 0,
            view_number: 0,
            payload: Bytes::from(alloy_rlp::encode(B256::repeat_byte(0x22))),
        };
        let mut encoded_data = Vec::new();
        data.encode(&mut encoded_data);
        let mut message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: 10,
            sender: attacker,
            data: encoded_data.into(),
            witness: Bytes::new(),
        };
        let (signature, recovery_id) =
            signer.sign_prehash_recoverable(message.hash().as_slice()).unwrap();
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();

        let (protocol, _events) = DbftProtocol::new(10);
        // An honest validator set that does not include the attacker.
        protocol
            .activate(10, vec![Address::repeat_byte(0x01), Address::repeat_byte(0x02)])
            .unwrap();

        // Header validation succeeds without touching the payload.
        let validated = protocol.validate_message(&message).unwrap();
        // The sender check rejects the attacker before any payload decode.
        assert!(matches!(
            protocol.validate_sender(&message, &validated),
            Err(DbftProtocolViolation::UnauthorizedValidator { .. })
        ));
        // The payload really is undecodable, confirming validate_message skipped the expensive
        // step.
        assert!(DbftProtocol::validate_payload(&validated).is_err());
    }

    #[test]
    fn message_encoding_matches_neox_geth_golden_vector() {
        let data = DbftConsensusData {
            message_type: DbftMessageType::PrepareResponse,
            block_index: 42,
            validator_index: 3,
            view_number: 1,
            // `prepareResponse` is a one-field Go struct and is therefore an RLP list.
            payload: hex::decode(
                "e1a02222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap()
            .into(),
        };
        let mut encoded_data = Vec::new();
        data.encode(&mut encoded_data);
        assert_eq!(
            hex::encode(&encoded_data),
            "e6212a0301e1a02222222222222222222222222222222222222222222222222222222222222222"
        );

        let message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: 42,
            sender: Address::repeat_byte(0x11),
            data: encoded_data.into(),
            witness: hex::decode(
                "4444444444444444444444444444444444444444444444444444444444444444\
                 444444444444444444444444444444444444444444444444444444444444444401",
            )
            .unwrap()
            .into(),
        };
        assert_eq!(
            hex::encode(alloy_rlp::encode(&message)),
            "f882802a941111111111111111111111111111111111111111a7e6212a0301e1a02222222222222222222222222222222222222222222222222222222222222222b8414444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444401"
        );
        assert_eq!(
            message.hash(),
            B256::from_slice(
                &hex::decode("1d684570e30a8cfb832299bf03ae26bdcfe0a42358ad5780fd86a00cf9bd074d")
                    .unwrap()
            )
        );
    }

    #[test]
    fn signed_message_roundtrips_and_verifies() {
        let message = signed_message();
        message.verify_witness().unwrap();
        let encoded = alloy_rlp::encode(&message);
        assert_eq!(decode_exact::<DbftMessage>(&encoded).unwrap(), message);

        let mut invalid = message;
        invalid.sender = Address::repeat_byte(0x44);
        assert!(matches!(
            invalid.verify_witness(),
            Err(DbftProtocolViolation::SenderMismatch { .. })
        ));
    }

    #[test]
    fn late_message_grace_is_exact_and_authenticated() {
        assert!(is_exact_late_message(42, 42));
        assert!(!is_exact_late_message(42, 41));
        assert!(!is_exact_late_message(42, 43));
        assert!(is_next_height_message(42, 43));
        assert!(!is_next_height_message(42, 44));
        assert!(!is_next_height_message(u64::MAX, u64::MAX));

        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, mut events) = DbftProtocol::new(42);
        protocol.activate(42, accounts).unwrap();
        let peer_id = PeerId::random();
        let payload = Bytes::from(alloy_rlp::encode(crate::DbftPrepareResponse {
            preparation_hash: B256::repeat_byte(0x22),
        }));

        let exact = signed_consensus_message(
            &validators[0],
            42,
            0,
            0,
            DbftMessageType::PrepareResponse,
            payload.clone(),
        );
        let exact_hash = exact.hash();
        protocol.handle_inbound_message(peer_id, exact.clone()).unwrap();
        assert!(protocol.get(exact_hash).is_none());
        assert!(events.try_recv().is_err());

        let mut unauthenticated = exact;
        unauthenticated.witness = Bytes::new();
        assert!(matches!(
            protocol.handle_inbound_message(peer_id, unauthenticated),
            Err(DbftProtocolViolation::InvalidWitnessLength(0))
        ));

        let outsider_key =
            k256::ecdsa::SigningKey::from_slice(B256::repeat_byte(0x99).as_slice()).unwrap();
        let outsider = TestValidator {
            address: Address::from_public_key(outsider_key.verifying_key()),
            key: outsider_key,
        };
        let unauthorized = signed_consensus_message(
            &outsider,
            42,
            0,
            0,
            DbftMessageType::PrepareResponse,
            payload.clone(),
        );
        assert!(matches!(
            protocol.handle_inbound_message(peer_id, unauthorized),
            Err(DbftProtocolViolation::UnauthorizedValidator { .. })
        ));

        let malformed = signed_consensus_message(
            &validators[0],
            42,
            0,
            0,
            DbftMessageType::PrepareResponse,
            Bytes::from_static(&[0x80]),
        );
        assert!(matches!(
            protocol.handle_inbound_message(peer_id, malformed),
            Err(DbftProtocolViolation::InvalidRlp(_))
        ));

        let old = signed_consensus_message(
            &validators[0],
            41,
            0,
            0,
            DbftMessageType::PrepareResponse,
            payload,
        );
        assert!(matches!(
            protocol.handle_inbound_message(peer_id, old),
            Err(DbftProtocolViolation::InvalidHeight { current: 42, end: 41, .. })
        ));
    }

    #[test]
    fn authenticated_far_future_message_is_validated_then_dropped_at_fresh_sync() {
        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, mut events) = DbftProtocol::new(0);
        protocol.activate(0, accounts).unwrap();
        let peer_id = PeerId::random();
        let height = 7_100_000;
        let payload = alloy_rlp::encode(crate::DbftPrepareResponse {
            preparation_hash: B256::repeat_byte(0x42),
        })
        .into();
        let message = signed_consensus_message(
            &validators[0],
            height,
            0,
            0,
            DbftMessageType::PrepareResponse,
            payload,
        );
        let hash = message.hash();

        protocol.handle_inbound_message(peer_id, message).unwrap();
        assert!(protocol.get(hash).is_none());
        assert!(protocol.inner.cache.lock().unwrap().messages.is_empty());
        assert!(events.try_recv().is_err());

        let malformed = signed_consensus_message(
            &validators[0],
            height,
            0,
            0,
            DbftMessageType::PrepareResponse,
            Bytes::from_static(&[0x80]),
        );
        assert!(matches!(
            protocol.handle_inbound_message(peer_id, malformed),
            Err(DbftProtocolViolation::InvalidRlp(_))
        ));
    }

    #[test]
    fn rollback_purges_cached_messages_outside_the_exact_next_height() {
        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, _) = DbftProtocol::new(42);
        protocol.activate(42, accounts).unwrap();
        let message = signed_consensus_message(
            &validators[0],
            43,
            0,
            0,
            DbftMessageType::PrepareResponse,
            alloy_rlp::encode(crate::DbftPrepareResponse {
                preparation_hash: B256::repeat_byte(0x43),
            })
            .into(),
        );
        let hash = message.hash();
        assert!(protocol.publish(message).unwrap());
        assert!(protocol.get(hash).is_some());

        protocol.update_height(0);
        assert!(protocol.get(hash).is_none());
        assert!(protocol.inner.cache.lock().unwrap().messages.is_empty());
        assert!(protocol.inner.cache.lock().unwrap().senders.is_empty());
    }

    #[test]
    fn full_message_retransmission_is_redelivered_after_cache_hit() {
        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, mut events) = DbftProtocol::new(42);
        protocol.activate(42, accounts).unwrap();
        let first_peer = PeerId::random();
        let retry_peer = PeerId::random();
        let message = signed_consensus_message(
            &validators[0],
            43,
            0,
            1,
            DbftMessageType::PrepareResponse,
            alloy_rlp::encode(crate::DbftPrepareResponse {
                preparation_hash: B256::repeat_byte(0x33),
            })
            .into(),
        );
        let hash = message.hash();

        protocol.handle_inbound_message(first_peer, message.clone()).unwrap();
        protocol.handle_inbound_message(retry_peer, message).unwrap();
        assert_eq!(protocol.inner.cache.lock().unwrap().messages.len(), 1);

        for expected_peer in [first_peer, retry_peer] {
            let DbftEvent::Message { peer_id, message } = events.try_recv().unwrap() else {
                panic!("expected a dBFT message event")
            };
            assert_eq!(peer_id, expected_peer);
            assert_eq!(message.hash(), hash);
        }

        assert!(events.try_recv().is_err());
    }

    #[test]
    fn known_hash_announcement_does_not_replay_cached_message() {
        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, mut events) = DbftProtocol::new(42);
        protocol.activate(42, accounts).unwrap();
        let message = signed_consensus_message(
            &validators[0],
            43,
            0,
            1,
            DbftMessageType::PrepareResponse,
            alloy_rlp::encode(crate::DbftPrepareResponse {
                preparation_hash: B256::repeat_byte(0x44),
            })
            .into(),
        );
        let hash = message.hash();
        assert!(protocol.publish(message).unwrap());

        let (sender, mut receiver) = mpsc::channel(DBFT_COMMAND_QUEUE_CAPACITY);
        let commands = DbftPeerCommands {
            sender,
            bytes: Arc::new(Semaphore::new(DBFT_COMMAND_QUEUE_BYTE_CAPACITY)),
        };
        protocol.handle_announcement(hash, &commands).unwrap();
        assert!(matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        assert!(matches!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty)));

        // Cache membership, not typed-payload decoding, drives inventory handling. A malformed
        // entry cannot pass normal admission, but makes this regression distinguish the O(1)
        // presence probe from the verified lookup used to answer Get requests.
        let mut cache_only = signed_message();
        cache_only.valid_block_end = 43;
        cache_only.data = Bytes::from_static(&[0xc0]);
        let cache_only_hash = cache_only.hash();
        assert_eq!(
            protocol
                .inner
                .cache
                .lock()
                .unwrap()
                .insert(cache_only_hash, Arc::new(cache_only))
                .unwrap(),
            CacheMessageOutcome::Inserted
        );
        assert!(protocol.get(cache_only_hash).is_none());
        protocol.handle_announcement(cache_only_hash, &commands).unwrap();
        assert!(matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)));

        let unknown = B256::repeat_byte(0xff);
        protocol.handle_announcement(unknown, &commands).unwrap();
        let queued = receiver.try_recv().unwrap().into_command();
        assert!(matches!(queued, DbftCommand::Get(hash) if hash == unknown));
    }

    #[test]
    fn validator_rotation_purges_removed_and_reindexed_senders() {
        let validators = test_validators(4);
        let old_accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, _) = DbftProtocol::new(42);
        protocol.activate(42, old_accounts).unwrap();
        let payload = |byte| {
            alloy_rlp::encode(crate::DbftPrepareResponse {
                preparation_hash: B256::repeat_byte(byte),
            })
            .into()
        };
        let removed = signed_consensus_message(
            &validators[0],
            43,
            0,
            1,
            DbftMessageType::PrepareResponse,
            payload(0x44),
        );
        let reindexed = signed_consensus_message(
            &validators[1],
            43,
            1,
            1,
            DbftMessageType::PrepareResponse,
            payload(0x55),
        );
        let removed_hash = removed.hash();
        let reindexed_hash = reindexed.hash();
        assert!(protocol.publish(removed).unwrap());
        assert!(protocol.publish(reindexed).unwrap());

        let rotated = validators[1..].iter().map(|validator| validator.address).collect();
        protocol.activate(42, rotated).unwrap();
        assert!(protocol.get(removed_hash).is_none());
        assert!(protocol.get(reindexed_hash).is_none());
        assert!(protocol.inner.cache.lock().unwrap().senders.is_empty());
    }

    #[test]
    fn wire_message_ids_and_capability_match_geth() {
        let message = signed_message();
        assert_eq!(
            DbftConnectionHandler { protocol: DbftProtocol::new(41).0 }.protocol(),
            Protocol::new(Capability::new_static("dbft", 0), 3)
        );
        assert_eq!(encode_frame(DbftWireMessageId::Announce, &message.hash())[0], 0);
        assert_eq!(encode_frame(DbftWireMessageId::Get, &message.hash())[0], 1);
        assert_eq!(encode_frame(DbftWireMessageId::Message, &message)[0], 2);
        assert!(!hex::encode(message.hash()).is_empty());
    }

    #[test]
    fn per_sender_cache_is_bounded() {
        let (protocol, _) = DbftProtocol::new(0);
        let base = signed_message();
        let mut validators = vec![
            base.sender,
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ];
        validators.sort_unstable();
        let validator_index =
            validators.iter().position(|address| *address == base.sender).unwrap();
        protocol.activate(0, validators).unwrap();
        for nonce in 1..=DBFT_SENDER_CACHE_CAPACITY as u64 + 1 {
            let mut message = base.clone();
            message.valid_block_end = 1;
            let data = DbftConsensusData {
                message_type: DbftMessageType::PrepareResponse,
                block_index: 1,
                validator_index: validator_index as u8,
                view_number: 1,
                payload: Bytes::from(alloy_rlp::encode(B256::repeat_byte(nonce as u8))),
            };
            let mut bytes = Vec::new();
            data.encode(&mut bytes);
            message.data = bytes.into();
            // Cache bounding is independent from signature validation here.
            let hash = message.hash();
            assert_eq!(
                protocol.cache_message(hash, Arc::new(message), &data).unwrap(),
                CacheMessageOutcome::Inserted
            );
        }
        assert_eq!(protocol.inner.cache.lock().unwrap().messages.len(), DBFT_SENDER_CACHE_CAPACITY);
    }

    #[test]
    fn event_queue_saturation_does_not_cache_undelivered_message() {
        let validators = test_validators(4);
        let accounts = validators.iter().map(|validator| validator.address).collect();
        let (protocol, mut events) = DbftProtocol::new(42);
        protocol.activate(42, accounts).unwrap();
        let filler = Arc::new(signed_message());
        let first_filler_peer = PeerId::random();
        let second_filler_peer = PeerId::random();
        for _ in 0..DBFT_PEER_EVENT_QUEUE_CAPACITY {
            assert!(protocol
                .queue_message_event(first_filler_peer, Arc::clone(&filler), 1)
                .is_ok());
        }
        assert!(matches!(
            protocol.queue_message_event(first_filler_peer, Arc::clone(&filler), 1),
            Err(DbftProtocolViolation::InboundQueueSaturated)
        ));
        for _ in DBFT_PEER_EVENT_QUEUE_CAPACITY..DBFT_EVENT_QUEUE_CAPACITY {
            assert!(protocol
                .queue_message_event(second_filler_peer, Arc::clone(&filler), 1)
                .is_ok());
        }
        assert_eq!(events.capacity(), 0);

        let message = signed_consensus_message(
            &validators[0],
            43,
            0,
            0,
            DbftMessageType::PrepareResponse,
            alloy_rlp::encode(crate::DbftPrepareResponse {
                preparation_hash: B256::repeat_byte(0x77),
            })
            .into(),
        );
        let hash = message.hash();
        let source = PeerId::random();
        assert!(matches!(
            protocol.handle_inbound_message(source, message.clone()),
            Err(DbftProtocolViolation::InboundQueueSaturated)
        ));
        assert!(protocol.get(hash).is_none());
        assert!(!protocol.inner.cache.lock().unwrap().messages.contains_key(&hash));
        assert_eq!(events.capacity(), 0);

        let DbftEvent::Message { peer_id, .. } = events.try_recv().unwrap() else {
            panic!("expected a filler message event")
        };
        assert_eq!(peer_id, first_filler_peer);
        protocol.handle_inbound_message(source, message).unwrap();
        assert!(protocol.get(hash).is_some());

        for _ in 0..DBFT_EVENT_QUEUE_CAPACITY - 1 {
            assert!(matches!(events.try_recv().unwrap(), DbftEvent::Message { .. }));
        }
        let DbftEvent::Message { peer_id, message } = events.try_recv().unwrap() else {
            panic!("expected the retried message event")
        };
        assert_eq!(peer_id, source);
        assert_eq!(message.hash(), hash);
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn event_queue_enforces_encoded_byte_budget_and_releases_on_dequeue() {
        let (protocol, mut events) = DbftProtocol::new(0);
        let message = Arc::new(signed_message());
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let retry_peer = PeerId::random();
        assert!(protocol
            .queue_message_event(first_peer, Arc::clone(&message), DBFT_PEER_EVENT_BYTE_CAPACITY,)
            .is_ok());
        assert!(matches!(
            protocol.queue_message_event(first_peer, Arc::clone(&message), 1),
            Err(DbftProtocolViolation::InboundQueueSaturated)
        ));
        assert!(protocol
            .queue_message_event(
                second_peer,
                Arc::clone(&message),
                DBFT_EVENT_QUEUE_BYTE_CAPACITY - DBFT_PEER_EVENT_BYTE_CAPACITY,
            )
            .is_ok());
        assert_eq!(events.byte_capacity(), 0);
        assert!(matches!(
            protocol.queue_message_event(retry_peer, Arc::clone(&message), 1),
            Err(DbftProtocolViolation::InboundQueueSaturated)
        ));
        assert_eq!(events.capacity(), DBFT_EVENT_QUEUE_CAPACITY - 2);
        assert!(matches!(events.try_recv().unwrap(), DbftEvent::Message { .. }));
        assert_eq!(events.byte_capacity(), DBFT_PEER_EVENT_BYTE_CAPACITY);
        assert!(protocol.queue_message_event(retry_peer, message, 1).is_ok());
    }

    #[test]
    fn message_cache_enforces_global_count_and_byte_bounds() {
        let base = signed_message();
        let mut count_cache = DbftMessageCache::default();
        for index in 0..=DBFT_MESSAGE_CACHE_CAPACITY {
            let mut message = base.clone();
            message.sender = Address::repeat_byte(index as u8);
            let mut raw_hash = [0_u8; 32];
            raw_hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert_eq!(
                count_cache.insert(B256::from(raw_hash), Arc::new(message)).unwrap(),
                CacheMessageOutcome::Inserted
            );
        }
        assert_eq!(count_cache.messages.len(), DBFT_MESSAGE_CACHE_CAPACITY);
        assert!(count_cache.get(&B256::ZERO).is_none());

        let mut byte_cache = DbftMessageCache::default();
        let mut first = base;
        first.sender = Address::repeat_byte(0x01);
        first.data = Bytes::from(vec![0_u8; DBFT_MESSAGE_CACHE_BYTE_CAPACITY / 2]);
        let mut second = first.clone();
        second.sender = Address::repeat_byte(0x02);
        let first_hash = B256::repeat_byte(0x01);
        let second_hash = B256::repeat_byte(0x02);
        byte_cache.insert(first_hash, Arc::new(first)).unwrap();
        byte_cache.insert(second_hash, Arc::new(second)).unwrap();
        assert!(byte_cache.retained_bytes <= DBFT_MESSAGE_CACHE_BYTE_CAPACITY);
        assert!(byte_cache.get(&first_hash).is_none());
        assert!(byte_cache.get(&second_hash).is_some());
    }

    #[test]
    fn outbound_command_queue_enforces_byte_bound_and_releases_on_dequeue() {
        let (sender, mut receiver) = mpsc::channel(DBFT_COMMAND_QUEUE_CAPACITY);
        let commands = DbftPeerCommands {
            sender,
            bytes: Arc::new(Semaphore::new(DBFT_COMMAND_QUEUE_BYTE_CAPACITY)),
        };
        let mut message = signed_message();
        message.data = Bytes::from(vec![0_u8; 4_000_000]);
        let command = DbftCommand::Message(Arc::new(message));
        let retained = DBFT_COMMAND_QUEUE_BYTE_CAPACITY / command.encoded_len();
        assert!(retained < DBFT_COMMAND_QUEUE_CAPACITY);
        for _ in 0..retained {
            commands.try_send(command.clone()).unwrap();
        }
        assert!(matches!(
            commands.try_send(command.clone()),
            Err(DbftProtocolViolation::OutboundQueueSaturated)
        ));
        drop(receiver.try_recv().unwrap().into_command());
        commands.try_send(command).unwrap();
    }

    #[test]
    fn lifecycle_events_have_reserved_fifo_capacity() {
        let (protocol, mut events) = DbftProtocol::new(0);
        let mut permits = protocol.inner.reserve_control_events().unwrap();
        let peer_id = PeerId::random();
        let established = DbftEvent::Established { peer_id, direction: Direction::Incoming };
        let violation =
            DbftEvent::Violation { peer_id, reason: DbftProtocolViolation::EmptyMessage };
        let disconnected = DbftEvent::Disconnected { peer_id };
        for event in [established, violation, disconnected] {
            permits.pop().unwrap().send(QueuedDbftEvent {
                event: Some(event),
                _data_slot: None,
                _peer_slot: None,
                _event_bytes: None,
                _peer_bytes: None,
                _peer_budget: None,
            });
        }
        assert!(matches!(events.try_recv().unwrap(), DbftEvent::Established { .. }));
        assert!(matches!(events.try_recv().unwrap(), DbftEvent::Violation { .. }));
        assert!(matches!(events.try_recv().unwrap(), DbftEvent::Disconnected { .. }));
    }
}
