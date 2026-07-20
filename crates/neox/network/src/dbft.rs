//! Neo X `dbft/0` consensus-message propagation protocol.

use crate::protocol::decode_exact;
use alloy_primitives::{
    bytes::{Buf, BufMut, BytesMut},
    keccak256, Address, Bytes, Signature, B256,
};
use alloy_rlp::{Decodable, Encodable, Header, PayloadView, RlpDecodable, RlpEncodable};
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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    task::{ready, Context, Poll},
};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Maximum payload accepted by Neo X Geth for a `dbft/0` message.
pub const DBFT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const DBFT_MESSAGE_COUNT: u8 = 3;
const DBFT_SENDER_CACHE_CAPACITY: usize = 20;

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
        let PayloadView::List(items) = Header::decode_raw(buf)? else {
            return Err(alloy_rlp::Error::UnexpectedString)
        };
        let [message_type, block_index, validator_index, view_number, payload] = items.as_slice()
        else {
            return Err(alloy_rlp::Error::ListLengthMismatch { expected: 5, got: items.len() })
        };
        let message_type = decode_exact::<u8>(message_type)?;
        Ok(Self {
            message_type: DbftMessageType::try_from(message_type)?,
            block_index: decode_exact(block_index)?,
            validator_index: decode_exact(validator_index)?,
            view_number: decode_exact(view_number)?,
            payload: Bytes::copy_from_slice(payload),
        })
    }
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
            ))
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
            return Err(DbftProtocolViolation::SenderMismatch { expected: self.sender, recovered })
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
    fn encoded(self) -> BytesMut {
        match self {
            Self::Announce(hash) => encode_frame(DbftWireMessageId::Announce, &hash),
            Self::Get(hash) => encode_frame(DbftWireMessageId::Get, &hash),
            Self::Message(message) => encode_frame(DbftWireMessageId::Message, message.as_ref()),
        }
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
    height: AtomicU64,
    validators: RwLock<Option<Vec<Address>>>,
    events: mpsc::UnboundedSender<DbftEvent>,
    peers: Mutex<HashMap<PeerId, mpsc::UnboundedSender<DbftCommand>>>,
    messages: Mutex<HashMap<B256, Arc<DbftMessage>>>,
    senders: Mutex<HashMap<Address, VecDeque<B256>>>,
}

/// Shared Neo X `dbft/0` service, verified-message cache, and peer command handle.
#[derive(Debug, Clone)]
pub struct DbftProtocol {
    inner: Arc<DbftProtocolInner>,
}

impl DbftProtocol {
    /// Creates a dBFT protocol service at the current canonical height.
    pub fn new(height: u64) -> (Self, mpsc::UnboundedReceiver<DbftEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let protocol = Self {
            inner: Arc::new(DbftProtocolInner {
                height: AtomicU64::new(height),
                validators: RwLock::new(None),
                events,
                peers: Mutex::new(HashMap::new()),
                messages: Mutex::new(HashMap::new()),
                senders: Mutex::new(HashMap::new()),
            }),
        };
        (protocol, receiver)
    }

    /// Returns the `dbft/0` `RLPx` handler.
    pub fn handler(&self) -> DbftProtocolHandler {
        DbftProtocolHandler { protocol: self.clone() }
    }

    /// Updates the canonical height and evicts stale cached messages.
    pub fn update_height(&self, height: u64) {
        self.inner.height.store(height, Ordering::Relaxed);
        let mut messages = self.inner.messages.lock().expect("dBFT messages lock poisoned");
        messages.retain(|_, message| message.valid_block_end > height);
        let messages = &*messages;
        self.inner.senders.lock().expect("dBFT senders lock poisoned").retain(|_, hashes| {
            hashes.retain(|hash| messages.contains_key(hash));
            !hashes.is_empty()
        });
    }

    /// Enables consensus-message admission with the Governance-selected validator set.
    pub fn activate(
        &self,
        height: u64,
        mut validators: Vec<Address>,
    ) -> Result<(), DbftProtocolViolation> {
        if validators.is_empty() {
            return Err(DbftProtocolViolation::InvalidValidatorSet)
        }
        validators.sort_unstable();
        if validators.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DbftProtocolViolation::InvalidValidatorSet)
        }
        self.update_height(height);
        *self.inner.validators.write().expect("dBFT validators lock poisoned") = Some(validators);
        Ok(())
    }

    /// Disables dBFT admission while the canonical state is unavailable or still syncing.
    pub fn deactivate(&self) {
        *self.inner.validators.write().expect("dBFT validators lock poisoned") = None;
        self.inner.messages.lock().expect("dBFT messages lock poisoned").clear();
        self.inner.senders.lock().expect("dBFT senders lock poisoned").clear();
    }

    /// Returns whether a current validator set is available for message admission.
    pub fn is_active(&self) -> bool {
        self.inner.validators.read().expect("dBFT validators lock poisoned").is_some()
    }

    /// Returns a verified cached message.
    pub fn get(&self, hash: B256) -> Option<Arc<DbftMessage>> {
        self.inner.messages.lock().expect("dBFT messages lock poisoned").get(&hash).cloned()
    }

    /// Verifies, caches, and announces a locally produced consensus message.
    pub fn publish(&self, message: DbftMessage) -> Result<bool, DbftProtocolViolation> {
        let data = self.validate_message(&message)?;
        self.validate_sender(&message, &data)?;
        Self::validate_payload(&data)?;
        let hash = message.hash();
        let inserted = self.cache_message(hash, Arc::new(message));
        if inserted {
            self.broadcast(DbftCommand::Announce(hash));
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
            .is_some_and(|peer| peer.send(command).is_ok())
    }

    /// Broadcasts a command to all dBFT peers.
    pub fn broadcast(&self, command: DbftCommand) -> usize {
        self.inner
            .peers
            .lock()
            .expect("dBFT peers lock poisoned")
            .values()
            .filter(|peer| peer.send(command.clone()).is_ok())
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
        message.verify_witness()?;
        let data = message
            .consensus_data()
            .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
        let current = self.inner.height.load(Ordering::Relaxed);
        if current < message.valid_block_start || message.valid_block_end < current {
            return Err(DbftProtocolViolation::InvalidHeight {
                current,
                start: message.valid_block_start,
                end: message.valid_block_end,
            })
        }
        Ok(data)
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
    ) -> Result<(), DbftProtocolViolation> {
        let validators = self.inner.validators.read().expect("dBFT validators lock poisoned");
        let validators = validators.as_ref().ok_or(DbftProtocolViolation::ConsensusInactive)?;
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
            })
        }
        Ok(())
    }

    fn cache_message(&self, hash: B256, message: Arc<DbftMessage>) -> bool {
        let mut messages = self.inner.messages.lock().expect("dBFT messages lock poisoned");
        if messages.contains_key(&hash) {
            return false
        }
        let mut senders = self.inner.senders.lock().expect("dBFT senders lock poisoned");
        let sender_messages = senders.entry(message.sender).or_default();
        let evicted = (sender_messages.len() >= DBFT_SENDER_CACHE_CAPACITY)
            .then(|| sender_messages.pop_front())
            .flatten();
        if let Some(evicted) = evicted {
            messages.remove(&evicted);
        }
        sender_messages.push_back(hash);
        messages.insert(hash, message);
        true
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
        let (commands, command_rx) = mpsc::unbounded_channel();
        self.protocol
            .inner
            .peers
            .lock()
            .expect("dBFT peers lock poisoned")
            .insert(peer_id, commands.clone());
        let _ = self.protocol.inner.events.send(DbftEvent::Established { peer_id, direction });
        debug!(target: "neox::network::dbft", %peer_id, "Neo X dbft/0 peer established");
        DbftConnection {
            conn,
            protocol: self.protocol,
            peer_id,
            commands,
            command_rx,
            closed: false,
        }
    }
}

/// One multiplexed Neo X `dbft/0` stream.
#[derive(Debug)]
pub struct DbftConnection {
    conn: ProtocolConnection,
    protocol: DbftProtocol,
    peer_id: PeerId,
    commands: mpsc::UnboundedSender<DbftCommand>,
    command_rx: mpsc::UnboundedReceiver<DbftCommand>,
    closed: bool,
}

impl DbftConnection {
    fn close_with(&mut self, reason: DbftProtocolViolation) -> Poll<Option<BytesMut>> {
        warn!(target: "neox::network::dbft", peer_id = %self.peer_id, ?reason, "Closing invalid dbft/0 stream");
        let _ =
            self.protocol.inner.events.send(DbftEvent::Violation { peer_id: self.peer_id, reason });
        self.closed = true;
        Poll::Ready(None)
    }

    fn handle_message(&self, mut frame: BytesMut) -> Result<(), DbftProtocolViolation> {
        if frame.is_empty() {
            return Err(DbftProtocolViolation::EmptyMessage)
        }
        if frame.len() - 1 > DBFT_MAX_MESSAGE_SIZE {
            return Err(DbftProtocolViolation::MessageTooLarge(frame.len() - 1))
        }
        let raw_id = frame.get_u8();
        let message_id =
            DbftWireMessageId::try_from(raw_id).map_err(DbftProtocolViolation::InvalidMessageId)?;
        match message_id {
            DbftWireMessageId::Announce => {
                let hash = decode_exact::<B256>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                if self.protocol.get(hash).is_none() {
                    let _ = self.commands.send(DbftCommand::Get(hash));
                }
            }
            DbftWireMessageId::Get => {
                let hash = decode_exact::<B256>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                if let Some(message) = self.protocol.get(hash) {
                    let _ = self.commands.send(DbftCommand::Message(message));
                }
            }
            DbftWireMessageId::Message => {
                let message = decode_exact::<DbftMessage>(&frame)
                    .map_err(|error| DbftProtocolViolation::InvalidRlp(error.to_string()))?;
                // A requested payload can arrive while the canonical notification advances the
                // local height. Preserve Geth's harmless-late-message exception across that
                // single-height race, but keep rejecting older stale traffic.
                let current = self.protocol.inner.height.load(Ordering::Relaxed);
                if is_harmless_late_message(current, message.valid_block_end) {
                    return Ok(())
                }
                let data = self.protocol.validate_message(&message)?;
                if !self.protocol.is_active() {
                    trace!(target: "neox::network::dbft", peer_id=%self.peer_id, height=data.block_index, "Ignoring dBFT message while validator state is unavailable");
                    return Ok(())
                }
                // Authorize the sender against the validator set before decoding the typed payload:
                // a RecoveryMessage body triggers a BLS12-381 subgroup check per embedded share, so
                // only accountable validators may pay that cost, not any peer that negotiated
                // dbft/0.
                self.protocol.validate_sender(&message, &data)?;
                DbftProtocol::validate_payload(&data)?;
                let hash = message.hash();
                let message = Arc::new(message);
                if self.protocol.cache_message(hash, Arc::clone(&message)) {
                    let _ = self
                        .protocol
                        .inner
                        .events
                        .send(DbftEvent::Message { peer_id: self.peer_id, message });
                    self.protocol.broadcast(DbftCommand::Announce(hash));
                }
            }
        }
        Ok(())
    }
}

impl Stream for DbftConnection {
    type Item = BytesMut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None)
        }
        loop {
            if let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
                return Poll::Ready(Some(command.encoded()))
            }
            let Some(frame) = ready!(self.conn.poll_next_unpin(cx)) else {
                self.closed = true;
                return Poll::Ready(None)
            };
            if let Err(reason) = self.handle_message(frame) {
                return self.close_with(reason)
            }
        }
    }
}

impl Drop for DbftConnection {
    fn drop(&mut self) {
        self.protocol.inner.peers.lock().expect("dBFT peers lock poisoned").remove(&self.peer_id);
        let _ = self.protocol.inner.events.send(DbftEvent::Disconnected { peer_id: self.peer_id });
    }
}

fn is_harmless_late_message(current: u64, message_end: u64) -> bool {
    message_end == current || current.checked_sub(1) == Some(message_end)
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
    fn late_message_grace_is_limited_to_one_height() {
        assert!(is_harmless_late_message(42, 42));
        assert!(is_harmless_late_message(42, 41));
        assert!(!is_harmless_late_message(42, 40));
        assert!(!is_harmless_late_message(42, 43));
        assert!(is_harmless_late_message(0, 0));
        assert!(!is_harmless_late_message(0, u64::MAX));
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
        for height in 1..=DBFT_SENDER_CACHE_CAPACITY as u64 + 1 {
            let mut message = base.clone();
            message.valid_block_end = height;
            message.data = {
                let data = DbftConsensusData {
                    message_type: DbftMessageType::PrepareResponse,
                    block_index: height,
                    validator_index: 3,
                    view_number: 1,
                    payload: Bytes::from(alloy_rlp::encode(B256::repeat_byte(height as u8))),
                };
                let mut bytes = Vec::new();
                data.encode(&mut bytes);
                bytes.into()
            };
            // Cache bounding is independent from signature validation here.
            let hash = message.hash();
            protocol.cache_message(hash, Arc::new(message));
        }
        assert_eq!(protocol.inner.messages.lock().unwrap().len(), DBFT_SENDER_CACHE_CAPACITY);
    }
}
