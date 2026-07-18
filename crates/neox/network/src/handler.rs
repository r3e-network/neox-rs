//! Reth `RLPx` handler for Neo X's beacon protocol.

use crate::{
    encode_frame,
    protocol::{DecodedMessage, MAX_MESSAGE_SIZE},
    BatchBlobs, BeaconLocalStatus, BeaconMessageId, BeaconStatus, BeaconVersion, Blobs,
    GetBatchBlobs, GetBlobs, GetTransactions, NewBlobsRoot, NewBlockPacket, TransactionsPacket,
    MAX_BLOB_REQUEST_TTL,
};
use alloy_eips::eip2124::{ForkFilter, Head};
use alloy_primitives::{
    bytes::{Buf, BytesMut},
    Bytes, B256,
};
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
};
use reth_eth_wire_types::NewBlockHashes;
use reth_ethereum_forks::Hardforks;
use reth_neox_chainspec::NeoXChainSpec;
use reth_network::protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler};
use reth_network_api::{Direction, PeerId};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{ready, Context, Poll},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

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
    /// A blob request used a zero or excessive forwarding TTL.
    InvalidBlobTtl(u8),
}

#[derive(Debug)]
struct BeaconProtocolInner {
    chain_spec: Arc<NeoXChainSpec>,
    status: RwLock<BeaconLocalStatus>,
    events: mpsc::UnboundedSender<BeaconEvent>,
    peers: Mutex<HashMap<PeerId, mpsc::UnboundedSender<BeaconCommand>>>,
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
    ) -> (Self, mpsc::UnboundedReceiver<BeaconEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let this = Self {
            inner: Arc::new(BeaconProtocolInner {
                chain_spec,
                status: RwLock::new(status),
                events,
                peers: Mutex::new(HashMap::new()),
            }),
        };
        (this, receiver)
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
        self.inner
            .peers
            .lock()
            .expect("beacon peers lock poisoned")
            .get(&peer_id)
            .is_some_and(|peer| peer.send(command).is_ok())
    }

    /// Broadcasts a command to all negotiated beacon peers.
    pub fn broadcast(&self, command: BeaconCommand) -> usize {
        self.inner
            .peers
            .lock()
            .expect("beacon peers lock poisoned")
            .values()
            .filter(|peer| peer.send(command.clone()).is_ok())
            .count()
    }

    /// Number of peers with a completed beacon status handshake.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.lock().expect("beacon peers lock poisoned").len()
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
        let fork_id = self.protocol.inner.chain_spec.fork_id(&head);
        let initial_status = local_status.wire_status(self.version, fork_id).encoded();
        let (commands, command_rx) = mpsc::unbounded_channel();

        BeaconConnection {
            conn,
            protocol: self.protocol,
            version: self.version,
            direction,
            peer_id,
            initial_status: Some(initial_status),
            commands,
            command_rx,
            handshake_complete: false,
            registered: false,
            closed: false,
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
    commands: mpsc::UnboundedSender<BeaconCommand>,
    command_rx: mpsc::UnboundedReceiver<BeaconCommand>,
    handshake_complete: bool,
    registered: bool,
    closed: bool,
}

impl BeaconConnection {
    fn emit(&self, event: BeaconEvent) {
        let _ = self.protocol.inner.events.send(event);
    }

    fn close_with(&mut self, reason: BeaconProtocolViolation) -> Poll<Option<BytesMut>> {
        warn!(target: "neox::network::beacon", peer_id=%self.peer_id, ?reason, "Closing invalid beacon stream");
        self.emit(BeaconEvent::Violation { peer_id: self.peer_id, reason });
        self.closed = true;
        Poll::Ready(None)
    }

    fn validate_status(&self, mut payload: &[u8]) -> Result<BeaconStatus, BeaconProtocolViolation> {
        let status = BeaconStatus::decode(self.version, &mut payload)
            .map_err(|error| BeaconProtocolViolation::InvalidRlp(error.to_string()))?;
        if !payload.is_empty() {
            return Err(BeaconProtocolViolation::InvalidRlp("trailing bytes".to_string()))
        }

        let expected_version = self.version as u32;
        if status.protocol_version() != expected_version {
            return Err(BeaconProtocolViolation::VersionMismatch {
                expected: expected_version,
                received: status.protocol_version(),
            })
        }

        let local = self.protocol.status();
        if status.network_id() != local.network_id {
            return Err(BeaconProtocolViolation::NetworkMismatch {
                expected: local.network_id,
                received: status.network_id(),
            })
        }
        if status.genesis() != local.genesis {
            return Err(BeaconProtocolViolation::GenesisMismatch {
                expected: local.genesis,
                received: status.genesis(),
            })
        }

        let head = Head {
            number: local.head_number,
            timestamp: local.head_timestamp,
            total_difficulty: local.total_difficulty,
            hash: local.head,
            ..Default::default()
        };
        let filter: ForkFilter = self.protocol.inner.chain_spec.fork_filter(head);
        filter.validate(status.fork_id()).map_err(|_| BeaconProtocolViolation::ForkIdRejected)?;
        Ok(status)
    }

    fn handle_message(&mut self, mut frame: BytesMut) -> Result<(), BeaconProtocolViolation> {
        if frame.is_empty() {
            return Err(BeaconProtocolViolation::EmptyMessage)
        }
        if frame.len() - 1 > MAX_MESSAGE_SIZE {
            return Err(BeaconProtocolViolation::MessageTooLarge(frame.len() - 1))
        }

        let raw_id = frame.get_u8();
        let message_id =
            BeaconMessageId::try_from(raw_id).map_err(BeaconProtocolViolation::InvalidMessageId)?;

        if !self.handshake_complete {
            if message_id != BeaconMessageId::Status {
                return Err(BeaconProtocolViolation::MissingStatus(raw_id))
            }
            let status = self.validate_status(&frame)?;
            self.protocol
                .inner
                .peers
                .lock()
                .expect("beacon peers lock poisoned")
                .insert(self.peer_id, self.commands.clone());
            self.handshake_complete = true;
            self.registered = true;
            debug!(target: "neox::network::beacon", peer_id=%self.peer_id, version=?self.version, head=%status.head(), head_number=?status.head_number(), "Neo X beacon handshake completed");
            self.emit(BeaconEvent::Established {
                peer_id: self.peer_id,
                direction: self.direction,
                version: self.version,
                status,
            });
            return Ok(())
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
                    return Err(BeaconProtocolViolation::InvalidBlobTtl(request.ttl))
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
        self.emit(event);
        Ok(())
    }
}

impl Stream for BeaconConnection {
    type Item = BytesMut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None)
        }
        if let Some(status) = self.initial_status.take() {
            return Poll::Ready(Some(status))
        }

        loop {
            if self.handshake_complete {
                while let Poll::Ready(Some(command)) = self.command_rx.poll_recv(cx) {
                    if let Some(frame) = command.encoded(self.version) {
                        return Poll::Ready(Some(frame))
                    }
                }
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

impl Drop for BeaconConnection {
    fn drop(&mut self) {
        if self.registered {
            self.protocol
                .inner
                .peers
                .lock()
                .expect("beacon peers lock poisoned")
                .remove(&self.peer_id);
            self.emit(BeaconEvent::Disconnected { peer_id: self.peer_id, version: self.version });
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
