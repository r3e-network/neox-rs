//! Neo X `beacon` devp2p subprotocol support.
//!
//! Lock-poison policy: every shared-network-state lock (`dbft.rs` and `handler.rs` admission,
//! cache, peer, status, budget, and event-queue locks) fails fast with `expect` when poisoned.
//! These fields carry consensus-relevant invariants — admission sets, message dedup caches,
//! peer capabilities — and a panic mid-mutation means those invariants can no longer be
//! trusted; continuing silently could admit unauthorized validators or replay messages. This
//! is the opposite of the recover-and-continue policy for the availability-oriented DKG share
//! holder in `reth-neox-node`'s `signer.rs`.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod dbft;
mod dbft_payload;
mod handler;
mod protocol;
mod store;

pub use dbft::{
    DbftCommand, DbftConsensusData, DbftEvent, DbftEventReceiver, DbftMessage, DbftMessageType,
    DbftProtocol, DbftProtocolHandler, DbftProtocolViolation, DBFT_COMMAND_QUEUE_BYTE_CAPACITY,
    DBFT_EVENT_QUEUE_BYTE_CAPACITY, DBFT_EVENT_QUEUE_CAPACITY, DBFT_MAX_MESSAGE_SIZE,
    DBFT_MESSAGE_CACHE_BYTE_CAPACITY, DBFT_MESSAGE_CACHE_CAPACITY, DBFT_PEER_EVENT_BYTE_CAPACITY,
    DBFT_PEER_EVENT_QUEUE_CAPACITY,
};
pub use dbft_payload::{
    DbftChangeView, DbftChangeViewReason, DbftCommit, DbftCommitSignature, DbftDecodedPayload,
    DbftPayloadError, DbftPreCommit, DbftPrepareRequest, DbftPrepareResponse, DbftRecoveryMessage,
    DbftRecoveryRequest,
};
pub use handler::{
    BeaconCommand, BeaconEvent, BeaconEventReceiver, BeaconProtocol, BeaconProtocolHandler,
    BeaconProtocolViolation, BEACON_EVENT_QUEUE_BYTE_CAPACITY, BEACON_EVENT_QUEUE_CAPACITY,
    BEACON_PEER_EVENT_BYTE_CAPACITY, BEACON_PEER_EVENT_QUEUE_CAPACITY,
};
pub use protocol::{
    block_hash_announcement, encode_frame, transactions_request, transactions_response, BatchBlobs,
    BeaconBlobSidecar, BeaconLocalStatus, BeaconMessageId, BeaconStatus, BeaconStatusV1,
    BeaconStatusV2, BeaconVersion, Blobs, GetBatchBlobs, GetBlobs, GetTransactions, NewBlobsRoot,
    NewBlockPacket, TransactionsPacket, MAX_BLOB_REQUEST_TTL, MAX_MESSAGE_SIZE,
};
pub use store::{NeoXSidecarStore, SidecarStoreError};
