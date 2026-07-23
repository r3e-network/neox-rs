//! Wire types for Neo X's `beacon/1` and `beacon/2` protocols.

use alloy_eips::{
    eip2124::ForkId,
    eip4844::{Blob, BlobTransactionSidecar, Bytes48},
    eip7594::{BlobTransactionSidecarEip7594, BlobTransactionSidecarVariant},
};
use alloy_primitives::{bytes::BufMut, B256, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use reth_eth_wire::{protocol::Protocol, Capability};
use reth_eth_wire_types::{
    message::RequestPair, BlockHashNumber, GetPooledTransactions, NewBlockHashes,
    PooledTransactions,
};
use reth_ethereum_primitives::{Block, PooledTransactionVariant};

/// Maximum payload accepted by Neo X Geth for a beacon message.
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Negotiated Neo X beacon protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BeaconVersion {
    /// Original protocol with the legacy blob-sidecar encoding.
    V1 = 1,
    /// Current protocol with head number and transaction retrieval.
    V2 = 2,
}

impl BeaconVersion {
    /// Returns the devp2p capability advertised in the Hello message.
    pub const fn capability(self) -> Capability {
        Capability::new_static("beacon", self as usize)
    }

    /// Returns the `RLPx` protocol and its reserved message count.
    pub const fn protocol(self) -> Protocol {
        Protocol::new(self.capability(), self.message_count())
    }

    /// Number of message identifiers reserved by this version.
    pub const fn message_count(self) -> u8 {
        match self {
            Self::V1 => 8,
            Self::V2 => 10,
        }
    }
}

/// Beacon message identifier relative to the negotiated capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BeaconMessageId {
    /// Mandatory first message exchanged by both peers.
    Status = 0x00,
    /// Announces block hashes and numbers.
    NewBlockHashes = 0x01,
    /// Propagates a full block and its total difficulty.
    NewBlock = 0x02,
    /// Announces that blob sidecars are available for a block.
    NewBlobsRoot = 0x03,
    /// Requests sidecars for one block.
    GetBlobs = 0x04,
    /// Returns sidecars for one block.
    Blobs = 0x05,
    /// Requests sidecars for multiple blocks.
    GetBatchBlobs = 0x06,
    /// Returns sidecars for multiple blocks.
    BatchBlobs = 0x07,
    /// Requests transactions by hash. Beacon/2 only.
    GetTransactions = 0x08,
    /// Returns requested transactions. Beacon/2 only.
    Transactions = 0x09,
}

impl TryFrom<u8> for BeaconMessageId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Status),
            0x01 => Ok(Self::NewBlockHashes),
            0x02 => Ok(Self::NewBlock),
            0x03 => Ok(Self::NewBlobsRoot),
            0x04 => Ok(Self::GetBlobs),
            0x05 => Ok(Self::Blobs),
            0x06 => Ok(Self::GetBatchBlobs),
            0x07 => Ok(Self::BatchBlobs),
            0x08 => Ok(Self::GetTransactions),
            0x09 => Ok(Self::Transactions),
            other => Err(other),
        }
    }
}

/// Node-local status including the timestamp needed to calculate an EIP-2124 fork ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconLocalStatus {
    /// Devp2p network identifier.
    pub network_id: u64,
    /// Total difficulty at the advertised head.
    pub total_difficulty: U256,
    /// Advertised canonical head hash.
    pub head: B256,
    /// Advertised canonical head number.
    pub head_number: u64,
    /// Advertised canonical head timestamp.
    pub head_timestamp: u64,
    /// Canonical genesis block hash.
    pub genesis: B256,
    /// Whether this node serves Neo X blob-sidecar requests.
    pub blob_sync: bool,
}

impl BeaconLocalStatus {
    /// Builds the version-specific status message with the supplied current fork ID.
    pub const fn wire_status(self, version: BeaconVersion, fork_id: ForkId) -> BeaconStatus {
        match version {
            BeaconVersion::V1 => BeaconStatus::V1(BeaconStatusV1 {
                protocol_version: version as u32,
                network_id: self.network_id,
                total_difficulty: self.total_difficulty,
                head: self.head,
                genesis: self.genesis,
                fork_id,
                blob_sync: self.blob_sync,
            }),
            BeaconVersion::V2 => BeaconStatus::V2(BeaconStatusV2 {
                protocol_version: version as u32,
                network_id: self.network_id,
                total_difficulty: self.total_difficulty,
                head: self.head,
                head_number: self.head_number,
                genesis: self.genesis,
                fork_id,
                blob_sync: self.blob_sync,
            }),
        }
    }
}

/// `beacon/1` status packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BeaconStatusV1 {
    /// Negotiated protocol version, always one.
    pub protocol_version: u32,
    /// Devp2p network identifier.
    pub network_id: u64,
    /// Total difficulty at `head`.
    pub total_difficulty: U256,
    /// Canonical head hash.
    pub head: B256,
    /// Genesis block hash.
    pub genesis: B256,
    /// EIP-2124 fork identifier.
    pub fork_id: ForkId,
    /// Whether blob sidecars are served.
    pub blob_sync: bool,
}

/// `beacon/2` status packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BeaconStatusV2 {
    /// Negotiated protocol version, always two.
    pub protocol_version: u32,
    /// Devp2p network identifier.
    pub network_id: u64,
    /// Total difficulty at `head`.
    pub total_difficulty: U256,
    /// Canonical head hash.
    pub head: B256,
    /// Canonical head number.
    pub head_number: u64,
    /// Genesis block hash.
    pub genesis: B256,
    /// EIP-2124 fork identifier.
    pub fork_id: ForkId,
    /// Whether blob sidecars are served.
    pub blob_sync: bool,
}

/// Version-normalized remote status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconStatus {
    /// Beacon/1 status.
    V1(BeaconStatusV1),
    /// Beacon/2 status.
    V2(BeaconStatusV2),
}

impl BeaconStatus {
    /// Decodes the status packet for the negotiated protocol version.
    pub fn decode(version: BeaconVersion, payload: &mut &[u8]) -> alloy_rlp::Result<Self> {
        match version {
            BeaconVersion::V1 => BeaconStatusV1::decode(payload).map(Self::V1),
            BeaconVersion::V2 => BeaconStatusV2::decode(payload).map(Self::V2),
        }
    }

    /// Encodes this packet as a complete capability-local frame.
    pub fn encoded(self) -> alloy_primitives::bytes::BytesMut {
        match self {
            Self::V1(status) => encode_frame(BeaconMessageId::Status, &status),
            Self::V2(status) => encode_frame(BeaconMessageId::Status, &status),
        }
    }

    /// Protocol version claimed in the remote packet.
    pub const fn protocol_version(self) -> u32 {
        match self {
            Self::V1(status) => status.protocol_version,
            Self::V2(status) => status.protocol_version,
        }
    }

    /// Remote network identifier.
    pub const fn network_id(self) -> u64 {
        match self {
            Self::V1(status) => status.network_id,
            Self::V2(status) => status.network_id,
        }
    }

    /// Remote canonical head hash.
    pub const fn head(self) -> B256 {
        match self {
            Self::V1(status) => status.head,
            Self::V2(status) => status.head,
        }
    }

    /// Remote canonical head number when provided by the protocol.
    pub const fn head_number(self) -> Option<u64> {
        match self {
            Self::V1(_) => None,
            Self::V2(status) => Some(status.head_number),
        }
    }

    /// Remote head total difficulty.
    pub const fn total_difficulty(self) -> U256 {
        match self {
            Self::V1(status) => status.total_difficulty,
            Self::V2(status) => status.total_difficulty,
        }
    }

    /// Remote genesis hash.
    pub const fn genesis(self) -> B256 {
        match self {
            Self::V1(status) => status.genesis,
            Self::V2(status) => status.genesis,
        }
    }

    /// Remote fork identifier.
    pub const fn fork_id(self) -> ForkId {
        match self {
            Self::V1(status) => status.fork_id,
            Self::V2(status) => status.fork_id,
        }
    }

    /// Whether the remote serves blob sidecars.
    pub const fn blob_sync(self) -> bool {
        match self {
            Self::V1(status) => status.blob_sync,
            Self::V2(status) => status.blob_sync,
        }
    }
}

/// Full-block propagation packet.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct NewBlockPacket {
    /// Propagated block.
    pub block: Block,
    /// Total difficulty including this block.
    pub total_difficulty: U256,
}

/// Blob-sidecar availability announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct NewBlobsRoot {
    /// Hash of the block whose sidecars became available.
    pub block_hash: B256,
}

/// Highest `GetBlobs` forwarding TTL accepted by Neo X Geth.
pub const MAX_BLOB_REQUEST_TTL: u8 = 3;

/// Blob sidecar normalized across beacon/1's legacy encoding and beacon/2's versioned encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconBlobSidecar {
    /// EIP-4844 blob, commitment, and blob-proof tuple.
    Eip4844(BlobTransactionSidecar),
    /// EIP-7594 blob, commitment, and cell-proof tuple.
    Eip7594(BlobTransactionSidecarEip7594),
}

impl BeaconBlobSidecar {
    /// Converts the wire sidecar into Alloy's canonical versioned representation.
    pub fn into_variant(self) -> BlobTransactionSidecarVariant {
        match self {
            Self::Eip4844(sidecar) => BlobTransactionSidecarVariant::Eip4844(sidecar),
            Self::Eip7594(sidecar) => BlobTransactionSidecarVariant::Eip7594(sidecar),
        }
    }

    /// Borrows the blob payloads.
    pub fn blobs(&self) -> &[Blob] {
        match self {
            Self::Eip4844(sidecar) => &sidecar.blobs,
            Self::Eip7594(sidecar) => &sidecar.blobs,
        }
    }

    /// Returns Alloy's in-memory size estimate, which closely bounds the wire payload.
    pub const fn size(&self) -> usize {
        match self {
            Self::Eip4844(sidecar) => sidecar.size(),
            Self::Eip7594(sidecar) => sidecar.size(),
        }
    }
}

impl From<BlobTransactionSidecarVariant> for BeaconBlobSidecar {
    fn from(sidecar: BlobTransactionSidecarVariant) -> Self {
        match sidecar {
            BlobTransactionSidecarVariant::Eip4844(sidecar) => Self::Eip4844(sidecar),
            BlobTransactionSidecarVariant::Eip7594(sidecar) => Self::Eip7594(sidecar),
        }
    }
}

/// Requests all transaction sidecars belonging to one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct GetBlobs {
    /// Request/response correlation identifier.
    pub request_id: u64,
    /// Block whose transaction sidecars are requested.
    pub block_hash: B256,
    /// Remaining forwarding hops. Valid Neo X requests use `1..=3`.
    pub ttl: u8,
}

/// Requests sidecars for several blocks in canonical request order.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct GetBatchBlobs {
    /// Request/response correlation identifier.
    pub request_id: u64,
    /// Block hashes whose sidecars are requested.
    pub block_hashes: Vec<B256>,
}

/// Sidecars returned for one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blobs {
    /// Request/response correlation identifier.
    pub request_id: u64,
    /// One sidecar per blob transaction in the block.
    pub sidecars: Vec<BeaconBlobSidecar>,
}

/// Sidecars returned for several blocks, preserving the requested block order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchBlobs {
    /// Request/response correlation identifier.
    pub request_id: u64,
    /// One vector of blob-transaction sidecars per returned block.
    pub blocks: Vec<Vec<BeaconBlobSidecar>>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct VersionedBlobSidecar {
    version: u8,
    blobs: Vec<Blob>,
    commitments: Vec<Bytes48>,
    proofs: Vec<Bytes48>,
}

impl TryFrom<VersionedBlobSidecar> for BeaconBlobSidecar {
    type Error = alloy_rlp::Error;

    fn try_from(sidecar: VersionedBlobSidecar) -> Result<Self, Self::Error> {
        match sidecar.version {
            0 => Ok(Self::Eip4844(BlobTransactionSidecar {
                blobs: sidecar.blobs,
                commitments: sidecar.commitments,
                proofs: sidecar.proofs,
            })),
            1 => Ok(Self::Eip7594(BlobTransactionSidecarEip7594::new(
                sidecar.blobs,
                sidecar.commitments,
                sidecar.proofs,
            ))),
            _ => Err(alloy_rlp::Error::Custom("unsupported Neo X blob sidecar version")),
        }
    }
}

impl From<BeaconBlobSidecar> for VersionedBlobSidecar {
    fn from(sidecar: BeaconBlobSidecar) -> Self {
        match sidecar {
            BeaconBlobSidecar::Eip4844(sidecar) => Self {
                version: 0,
                blobs: sidecar.blobs,
                commitments: sidecar.commitments,
                proofs: sidecar.proofs,
            },
            BeaconBlobSidecar::Eip7594(sidecar) => Self {
                version: 1,
                blobs: sidecar.blobs,
                commitments: sidecar.commitments,
                proofs: sidecar.cell_proofs,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct LegacyBlobs {
    request_id: u64,
    sidecars: Vec<BlobTransactionSidecar>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct VersionedBlobs {
    request_id: u64,
    sidecars: Vec<VersionedBlobSidecar>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct LegacyBatchBlobs {
    request_id: u64,
    blocks: Vec<Vec<BlobTransactionSidecar>>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct VersionedBatchBlobs {
    request_id: u64,
    blocks: Vec<Vec<VersionedBlobSidecar>>,
}

impl Blobs {
    /// Decodes the negotiated version's Geth-compatible sidecar response.
    pub fn decode(version: BeaconVersion, payload: &[u8]) -> alloy_rlp::Result<Self> {
        match version {
            BeaconVersion::V1 => {
                let response: LegacyBlobs = decode_exact(payload)?;
                Ok(Self {
                    request_id: response.request_id,
                    sidecars: response
                        .sidecars
                        .into_iter()
                        .map(BeaconBlobSidecar::Eip4844)
                        .collect(),
                })
            }
            BeaconVersion::V2 => {
                let response: VersionedBlobs = decode_exact(payload)?;
                Ok(Self {
                    request_id: response.request_id,
                    sidecars: response
                        .sidecars
                        .into_iter()
                        .map(BeaconBlobSidecar::try_from)
                        .collect::<Result<_, _>>()?,
                })
            }
        }
    }

    pub(crate) fn encoded(self, version: BeaconVersion) -> alloy_primitives::bytes::BytesMut {
        match version {
            BeaconVersion::V1 => encode_frame(
                BeaconMessageId::Blobs,
                &LegacyBlobs {
                    request_id: self.request_id,
                    sidecars: self
                        .sidecars
                        .into_iter()
                        .filter_map(|sidecar| match sidecar {
                            BeaconBlobSidecar::Eip4844(sidecar) => Some(sidecar),
                            BeaconBlobSidecar::Eip7594(_) => None,
                        })
                        .collect(),
                },
            ),
            BeaconVersion::V2 => encode_frame(
                BeaconMessageId::Blobs,
                &VersionedBlobs {
                    request_id: self.request_id,
                    sidecars: self.sidecars.into_iter().map(VersionedBlobSidecar::from).collect(),
                },
            ),
        }
    }
}

impl BatchBlobs {
    /// Decodes the negotiated version's Geth-compatible batch response.
    pub fn decode(version: BeaconVersion, payload: &[u8]) -> alloy_rlp::Result<Self> {
        match version {
            BeaconVersion::V1 => {
                let response: LegacyBatchBlobs = decode_exact(payload)?;
                Ok(Self {
                    request_id: response.request_id,
                    blocks: response
                        .blocks
                        .into_iter()
                        .map(|sidecars| {
                            sidecars.into_iter().map(BeaconBlobSidecar::Eip4844).collect()
                        })
                        .collect(),
                })
            }
            BeaconVersion::V2 => {
                let response: VersionedBatchBlobs = decode_exact(payload)?;
                Ok(Self {
                    request_id: response.request_id,
                    blocks: response
                        .blocks
                        .into_iter()
                        .map(|sidecars| {
                            sidecars
                                .into_iter()
                                .map(BeaconBlobSidecar::try_from)
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .collect::<Result<_, _>>()?,
                })
            }
        }
    }

    pub(crate) fn encoded(self, version: BeaconVersion) -> alloy_primitives::bytes::BytesMut {
        match version {
            BeaconVersion::V1 => encode_frame(
                BeaconMessageId::BatchBlobs,
                &LegacyBatchBlobs {
                    request_id: self.request_id,
                    blocks: self
                        .blocks
                        .into_iter()
                        .map(|sidecars| {
                            sidecars
                                .into_iter()
                                .filter_map(|sidecar| match sidecar {
                                    BeaconBlobSidecar::Eip4844(sidecar) => Some(sidecar),
                                    BeaconBlobSidecar::Eip7594(_) => None,
                                })
                                .collect()
                        })
                        .collect(),
                },
            ),
            BeaconVersion::V2 => encode_frame(
                BeaconMessageId::BatchBlobs,
                &VersionedBatchBlobs {
                    request_id: self.request_id,
                    blocks: self
                        .blocks
                        .into_iter()
                        .map(|sidecars| {
                            sidecars.into_iter().map(VersionedBlobSidecar::from).collect()
                        })
                        .collect(),
                },
            ),
        }
    }
}

/// Beacon/2 transaction request.
pub type GetTransactions = RequestPair<GetPooledTransactions>;

/// Beacon/2 transaction response. Blob transactions retain their full sidecars, matching Geth's
/// pooled transaction RLP rather than the sidecar-less block-body encoding.
pub type TransactionsPacket = RequestPair<PooledTransactions<PooledTransactionVariant>>;

/// Creates a beacon/2 transaction request with its correlation identifier.
pub const fn transactions_request(request_id: u64, hashes: Vec<B256>) -> GetTransactions {
    RequestPair { request_id, message: GetPooledTransactions(hashes) }
}

/// Creates a Neo X block-hash announcement packet.
pub fn block_hash_announcement(hash: B256, number: u64) -> NewBlockHashes {
    NewBlockHashes(vec![BlockHashNumber { hash, number }])
}

/// Creates a beacon/2 transaction response with the request identifier preserved.
pub const fn transactions_response(
    request_id: u64,
    transactions: Vec<PooledTransactionVariant>,
) -> TransactionsPacket {
    RequestPair { request_id, message: PooledTransactions(transactions) }
}

/// Encodes a message identifier followed by one RLP value.
pub fn encode_frame<T: Encodable>(
    message_id: BeaconMessageId,
    value: &T,
) -> alloy_primitives::bytes::BytesMut {
    let mut frame = alloy_primitives::bytes::BytesMut::with_capacity(value.length() + 1);
    frame.put_u8(message_id as u8);
    value.encode(&mut frame);
    frame
}

/// Decodes one RLP value and rejects trailing bytes.
pub(crate) fn decode_exact<T: Decodable>(payload: &[u8]) -> alloy_rlp::Result<T> {
    let mut payload = payload;
    let value = T::decode(&mut payload)?;
    if payload.is_empty() {
        Ok(value)
    } else {
        Err(alloy_rlp::Error::UnexpectedLength)
    }
}

/// Decoded non-status message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodedMessage {
    NewBlockHashes(NewBlockHashes),
    NewBlock(Box<NewBlockPacket>),
    NewBlobsRoot(NewBlobsRoot),
    GetBlobs(GetBlobs),
    Blobs(Blobs),
    GetBatchBlobs(GetBatchBlobs),
    BatchBlobs(BatchBlobs),
    GetTransactions(GetTransactions),
    Transactions(TransactionsPacket),
}

impl DecodedMessage {
    pub(crate) fn decode(
        version: BeaconVersion,
        message_id: BeaconMessageId,
        payload: &[u8],
    ) -> alloy_rlp::Result<Self> {
        if message_id as u8 >= version.message_count() {
            return Err(alloy_rlp::Error::Custom("message is not supported by beacon version"));
        }

        match message_id {
            BeaconMessageId::Status => Err(alloy_rlp::Error::Custom("duplicate status message")),
            BeaconMessageId::NewBlockHashes => decode_exact(payload).map(Self::NewBlockHashes),
            BeaconMessageId::NewBlock => {
                decode_exact(payload).map(|packet| Self::NewBlock(Box::new(packet)))
            }
            BeaconMessageId::NewBlobsRoot => decode_exact(payload).map(Self::NewBlobsRoot),
            BeaconMessageId::GetTransactions => decode_exact(payload).map(Self::GetTransactions),
            BeaconMessageId::Transactions => decode_exact(payload).map(Self::Transactions),
            BeaconMessageId::GetBlobs => decode_exact(payload).map(Self::GetBlobs),
            BeaconMessageId::Blobs => Blobs::decode(version, payload).map(Self::Blobs),
            BeaconMessageId::GetBatchBlobs => decode_exact(payload).map(Self::GetBatchBlobs),
            BeaconMessageId::BatchBlobs => {
                BatchBlobs::decode(version, payload).map(Self::BatchBlobs)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxEip4844, TxEip4844WithSidecar};
    use alloy_eips::eip2124::ForkHash;
    use alloy_primitives::{b256, hex, Signature};

    #[test]
    fn protocol_versions_reserve_geth_message_counts() {
        assert_eq!(BeaconVersion::V1.protocol().messages(), 8);
        assert_eq!(BeaconVersion::V2.protocol().messages(), 10);
        assert_eq!(BeaconVersion::V2.capability().name, "beacon");
    }

    #[test]
    fn beacon2_status_matches_geth_rlp_vector() {
        let status = BeaconStatusV2 {
            protocol_version: 2,
            network_id: 47_763,
            total_difficulty: U256::from(123_456),
            head: B256::repeat_byte(0x11),
            head_number: 61_728,
            genesis: B256::repeat_byte(0x22),
            fork_id: ForkId { hash: ForkHash([0xaa, 0xbb, 0xcc, 0xdd]), next: 3_749_760 },
            blob_sync: true,
        };
        let encoded = encode_frame(BeaconMessageId::Status, &status);
        let expected = hex!(
            "00f8580282ba938301e240a0111111111111111111111111111111111111111111111111111111111111111182f120a02222222222222222222222222222222222222222222222222222222222222222c984aabbccdd8339378001"
        );
        assert_eq!(&encoded[..], &expected[..]);

        let decoded = BeaconStatusV2::decode(&mut &encoded[1..]).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn block_hash_announcements_roundtrip() {
        let announcement = block_hash_announcement(
            b256!("2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7"),
            42,
        );
        let frame = encode_frame(BeaconMessageId::NewBlockHashes, &announcement);
        let decoded =
            DecodedMessage::decode(BeaconVersion::V2, BeaconMessageId::NewBlockHashes, &frame[1..])
                .unwrap();
        assert_eq!(decoded, DecodedMessage::NewBlockHashes(announcement));
    }

    #[test]
    fn beacon1_rejects_beacon2_messages() {
        let error =
            DecodedMessage::decode(BeaconVersion::V1, BeaconMessageId::GetTransactions, &[])
                .unwrap_err();
        assert!(error.to_string().contains("not supported"));
    }

    #[test]
    fn beacon2_transactions_preserve_blob_sidecars() {
        let blob = TxEip4844WithSidecar::from_tx_and_sidecar(
            TxEip4844::default(),
            BlobTransactionSidecarVariant::Eip4844(BlobTransactionSidecar::default()),
        );
        let transaction = PooledTransactionVariant::Eip4844(Signed::new_unhashed(
            blob,
            Signature::test_signature(),
        ));
        let packet = transactions_response(42, vec![transaction]);
        let frame = encode_frame(BeaconMessageId::Transactions, &packet);
        let decoded =
            DecodedMessage::decode(BeaconVersion::V2, BeaconMessageId::Transactions, &frame[1..])
                .unwrap();
        let DecodedMessage::Transactions(decoded) = decoded else {
            panic!("expected transactions packet")
        };
        assert!(decoded.message.0[0].as_eip4844().unwrap().tx().sidecar.is_eip4844());
    }

    #[test]
    fn blob_packets_match_geth_versioned_rlp_layout() {
        let legacy = BeaconBlobSidecar::Eip4844(BlobTransactionSidecar::default());
        let versioned = BeaconBlobSidecar::Eip7594(BlobTransactionSidecarEip7594::default());

        let beacon1 =
            Blobs { request_id: 7, sidecars: vec![legacy.clone()] }.encoded(BeaconVersion::V1);
        assert_eq!(&beacon1[..], &hex!("05c607c4c3c0c0c0")[..]);
        assert_eq!(
            Blobs::decode(BeaconVersion::V1, &beacon1[1..]).unwrap(),
            Blobs { request_id: 7, sidecars: vec![legacy.clone()] }
        );

        let beacon2_legacy =
            Blobs { request_id: 7, sidecars: vec![legacy.clone()] }.encoded(BeaconVersion::V2);
        assert_eq!(&beacon2_legacy[..], &hex!("05c707c5c480c0c0c0")[..]);
        assert_eq!(
            Blobs::decode(BeaconVersion::V2, &beacon2_legacy[1..]).unwrap(),
            Blobs { request_id: 7, sidecars: vec![legacy] }
        );

        let beacon2_versioned =
            Blobs { request_id: 7, sidecars: vec![versioned.clone()] }.encoded(BeaconVersion::V2);
        assert_eq!(&beacon2_versioned[..], &hex!("05c707c5c401c0c0c0")[..]);
        assert_eq!(
            Blobs::decode(BeaconVersion::V2, &beacon2_versioned[1..]).unwrap(),
            Blobs { request_id: 7, sidecars: vec![versioned] }
        );
    }

    #[test]
    fn get_blobs_roundtrips_geth_fields() {
        let request = GetBlobs {
            request_id: 42,
            block_hash: B256::repeat_byte(0x33),
            ttl: MAX_BLOB_REQUEST_TTL,
        };
        let frame = encode_frame(BeaconMessageId::GetBlobs, &request);

        assert_eq!(
            DecodedMessage::decode(BeaconVersion::V2, BeaconMessageId::GetBlobs, &frame[1..])
                .unwrap(),
            DecodedMessage::GetBlobs(request)
        );
    }
}
