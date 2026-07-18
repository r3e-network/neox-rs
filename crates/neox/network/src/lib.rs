//! Neo X `beacon` devp2p subprotocol support.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod dbft;
mod dbft_payload;
mod handler;
mod protocol;
mod store;

pub use dbft::{
    DbftCommand, DbftConsensusData, DbftEvent, DbftMessage, DbftMessageType, DbftProtocol,
    DbftProtocolHandler, DbftProtocolViolation, DBFT_MAX_MESSAGE_SIZE,
};
pub use dbft_payload::{
    DbftChangeView, DbftChangeViewReason, DbftCommit, DbftCommitSignature, DbftDecodedPayload,
    DbftPayloadError, DbftPreCommit, DbftPrepareRequest, DbftPrepareResponse, DbftRecoveryMessage,
    DbftRecoveryRequest,
};
pub use handler::{
    BeaconCommand, BeaconEvent, BeaconProtocol, BeaconProtocolHandler, BeaconProtocolViolation,
};
pub use protocol::{
    block_hash_announcement, encode_frame, transactions_response, BatchBlobs, BeaconBlobSidecar,
    BeaconLocalStatus, BeaconMessageId, BeaconStatus, BeaconStatusV1, BeaconStatusV2,
    BeaconVersion, Blobs, GetBatchBlobs, GetBlobs, GetTransactions, NewBlobsRoot, NewBlockPacket,
    TransactionsPacket, MAX_BLOB_REQUEST_TTL, MAX_MESSAGE_SIZE,
};
pub use store::{NeoXSidecarStore, SidecarStoreError};
