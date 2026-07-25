//! Type-specific Neo X dBFT consensus payloads.

use crate::{protocol::decode_exact, DbftConsensusData, DbftMessage, DbftMessageType};
use alloy_consensus::Header as EthereumHeader;
use alloy_primitives::{bytes::BufMut, Address, Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable, RlpEncodable};
use reth_neox_antimev::{DecryptionShare, SignatureShare, DECRYPTION_SHARE_LEN};
use std::{collections::HashSet, fmt};
use thiserror::Error;

const PRECOMMIT_COUNT_PREFIX_LEN: usize = 8;
const MAX_DECRYPTION_SHARES_PER_BLOCK: usize = 1_000;
const MAX_RECOVERY_PAYLOADS: usize = 256;

/// Reason carried by a dBFT change-view request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DbftChangeViewReason {
    /// Consensus timer expired.
    Timeout = 0,
    /// Validator agreed with an already proposed view change.
    ChangeAgreement = 1,
    /// One or more proposal transactions could not be obtained.
    TransactionNotFound = 2,
    /// A transaction was rejected by local policy.
    TransactionRejectedByPolicy = 3,
    /// A transaction failed consensus validation.
    TransactionInvalid = 4,
    /// The proposed block failed policy validation.
    BlockRejectedByPolicy = 5,
    /// Unspecified reason used for recovered legacy messages.
    Unknown = 0xff,
}

impl TryFrom<u8> for DbftChangeViewReason {
    type Error = DbftPayloadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Timeout),
            1 => Ok(Self::ChangeAgreement),
            2 => Ok(Self::TransactionNotFound),
            3 => Ok(Self::TransactionRejectedByPolicy),
            4 => Ok(Self::TransactionInvalid),
            5 => Ok(Self::BlockRejectedByPolicy),
            0xff => Ok(Self::Unknown),
            value => Err(DbftPayloadError::InvalidChangeViewReason(value)),
        }
    }
}

/// Decoded change-view body. The new view is the outer message view plus one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DbftChangeView {
    /// Nanosecond timestamp of the local view-change decision.
    pub timestamp_ns: u64,
    /// Raw Geth reason byte, validated by [`DbftChangeViewReason`].
    reason: u8,
}

impl DbftChangeView {
    /// Constructs a change-view payload with a canonical reason byte.
    pub const fn new(timestamp_ns: u64, reason: DbftChangeViewReason) -> Self {
        Self { timestamp_ns, reason: reason as u8 }
    }

    /// Returns the validated view-change reason.
    pub fn reason(&self) -> Result<DbftChangeViewReason, DbftPayloadError> {
        self.reason.try_into()
    }
}

/// Primary block proposal and its ordered transaction hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbftPrepareRequest {
    /// Header template that will be executed and sealed after Anti-MEV processing.
    pub sealing_proposal: EthereumHeader,
    /// Ordered transaction hashes committed by the primary.
    pub transaction_hashes: Vec<B256>,
    /// Legacy parent seal hash used before the Anti-MEV signature transition.
    pub parent_seal_hash_v0: Option<B256>,
    /// Legacy parent dBFT extra used before the Anti-MEV signature transition.
    pub parent_extra: Option<Bytes>,
}

impl Decodable for DbftPrepareRequest {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let sealing_proposal = EthereumHeader::decode(&mut payload)?;
        let transaction_hashes = Vec::<B256>::decode(&mut payload)?;
        let parent_seal_hash_v0 =
            (!payload.is_empty()).then(|| B256::decode(&mut payload)).transpose()?;
        let parent_extra =
            (!payload.is_empty()).then(|| Bytes::decode(&mut payload)).transpose()?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch { expected: 4, got: 5 });
        }
        Ok(Self { sealing_proposal, transaction_hashes, parent_seal_hash_v0, parent_extra })
    }
}

impl Encodable for DbftPrepareRequest {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.payload_length();
        Header { list: true, payload_length }.encode(out);
        self.sealing_proposal.encode(out);
        self.transaction_hashes.encode(out);
        if let Some(parent_seal_hash_v0) = self.effective_parent_seal_hash() {
            parent_seal_hash_v0.encode(out);
        }
        if let Some(parent_extra) = &self.parent_extra {
            parent_extra.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl DbftPrepareRequest {
    /// The V0 parent seal hash actually written to the wire: the explicit value when present, or
    /// `B256::ZERO` as a placeholder whenever a parent extra witness is attached.
    fn effective_parent_seal_hash(&self) -> Option<B256> {
        self.parent_seal_hash_v0.or_else(|| self.parent_extra.as_ref().map(|_| B256::ZERO))
    }

    fn payload_length(&self) -> usize {
        self.sealing_proposal.length() +
            self.transaction_hashes.length() +
            self.effective_parent_seal_hash().map_or(0, |hash| hash.length()) +
            self.parent_extra.as_ref().map_or(0, Encodable::length)
    }
}

/// Backup acknowledgement of one exact primary proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DbftPrepareResponse {
    /// Hash of the signed outer `PrepareRequest` message.
    pub preparation_hash: B256,
}

/// Anti-MEV decryption shares contributed by one validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbftPreCommit {
    /// Shares for Envelopes encrypted with the current DKG round.
    pub current_round: Vec<DecryptionShare>,
    /// Shares for Envelopes encrypted with the preceding DKG round.
    pub previous_round: Vec<DecryptionShare>,
    /// Exact little-endian share packet wrapped by the RLP list.
    pub data: Bytes,
}

impl Decodable for DbftPreCommit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let data = Bytes::decode(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch { expected: 1, got: 2 });
        }
        Self::from_data(data).map_err(|_| alloy_rlp::Error::Custom("invalid dBFT PreCommit shares"))
    }
}

impl Encodable for DbftPreCommit {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.data.length();
        Header { list: true, payload_length }.encode(out);
        self.data.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.data.length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl DbftPreCommit {
    /// Validates and decodes Geth's fixed-width little-endian share packet.
    pub fn from_data(data: Bytes) -> Result<Self, DbftPayloadError> {
        if data.len() < PRECOMMIT_COUNT_PREFIX_LEN {
            return Err(DbftPayloadError::SharesTooShort(data.len()));
        }
        let current_count =
            u32::from_le_bytes(data[..4].try_into().expect("four-byte current share count"));
        let previous_count =
            u32::from_le_bytes(data[4..8].try_into().expect("four-byte previous share count"));
        let total = current_count
            .checked_add(previous_count)
            .ok_or(DbftPayloadError::TooManyShares(usize::MAX))? as usize;
        if total > MAX_DECRYPTION_SHARES_PER_BLOCK {
            return Err(DbftPayloadError::TooManyShares(total));
        }
        let expected = PRECOMMIT_COUNT_PREFIX_LEN
            .checked_add(total.saturating_mul(DECRYPTION_SHARE_LEN))
            .ok_or(DbftPayloadError::TooManyShares(total))?;
        if data.len() != expected {
            return Err(DbftPayloadError::InvalidSharesLength { expected, actual: data.len() });
        }
        let current_count = current_count as usize;
        let (shares, remainder) =
            data[PRECOMMIT_COUNT_PREFIX_LEN..].as_chunks::<DECRYPTION_SHARE_LEN>();
        debug_assert!(remainder.is_empty());
        let mut shares = shares.iter();
        let current_round = shares
            .by_ref()
            .take(current_count)
            .map(|share| {
                DecryptionShare::decode(share)
                    .map_err(|error| DbftPayloadError::InvalidDecryptionShare(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let previous_round = shares
            .map(|share| {
                DecryptionShare::decode(share)
                    .map_err(|error| DbftPayloadError::InvalidDecryptionShare(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { current_round, previous_round, data })
    }

    /// Returns the total number of current- and previous-round shares carried by this validator.
    pub const fn share_count(&self) -> usize {
        self.current_round.len() + self.previous_round.len()
    }
}

/// ECDSA block signature or BLS threshold-signature share.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DbftCommit {
    /// Signature bytes whose interpretation is selected by the block extra version and scheme.
    pub signature: Bytes,
}

/// Validated interpretation of one dBFT commit contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbftCommitSignature {
    /// Legacy recoverable secp256k1 block signature.
    Ecdsa([u8; 65]),
    /// DKG-indexed BLS12-381 G2 threshold-signature contribution.
    Threshold(SignatureShare),
}

impl DbftCommit {
    /// Validates the two commit encodings accepted by Neo X across dBFT extra versions.
    pub fn validated_signature(&self) -> Result<DbftCommitSignature, DbftPayloadError> {
        match self.signature.len() {
            65 => {
                let signature: [u8; 65] =
                    self.signature.as_ref().try_into().expect("checked ECDSA signature length");
                if !matches!(signature[64], 0 | 1) {
                    return Err(DbftPayloadError::InvalidCommitRecoveryId(signature[64]));
                }
                Ok(DbftCommitSignature::Ecdsa(signature))
            }
            96 => SignatureShare::decode(&self.signature)
                .map(DbftCommitSignature::Threshold)
                .map_err(|error| DbftPayloadError::InvalidCommitSignatureShare(error.to_string())),
            actual => Err(DbftPayloadError::InvalidCommitLength(actual)),
        }
    }
}

/// Request for the current validator's accumulated consensus state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DbftRecoveryRequest {
    /// Nanosecond timestamp of the request.
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct PreparationCompact {
    validator_index: u8,
    invocation_script: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct CommitCompact {
    view_number: u8,
    validator_index: u8,
    signature: Bytes,
    invocation_script: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct ChangeViewCompact {
    validator_index: u8,
    original_view_number: u8,
    timestamp_ns: u64,
    invocation_script: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
struct PreCommitCompact {
    view_number: u8,
    validator_index: u8,
    data: Bytes,
    invocation_script: Bytes,
}

/// Aggregated recovery state. Compact entries retain their original witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbftRecoveryMessage {
    preparations: Vec<PreparationCompact>,
    commits: Vec<CommitCompact>,
    change_views: Vec<ChangeViewCompact>,
    /// Proposal hash, when the recovery payload includes preparation state.
    pub preparation_hash: Option<B256>,
    /// Embedded primary request header, when known by the recovering validator.
    pub prepare_request: Option<DbftConsensusData>,
    pre_commits: Vec<PreCommitCompact>,
}

impl Default for DbftRecoveryMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl Encodable for DbftRecoveryMessage {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.encoded_payload_length();
        Header { list: true, payload_length }.encode(out);
        self.preparations.encode(out);
        self.commits.encode(out);
        self.change_views.encode(out);
        if self.includes_preparation_hash() {
            if let Some(hash) = self.preparation_hash {
                hash.encode(out);
            } else {
                Bytes::new().encode(out);
            }
        }
        if self.includes_prepare_request() {
            if let Some(request) = &self.prepare_request {
                request.encode(out);
            } else {
                Header { list: true, payload_length: 0 }.encode(out);
            }
        }
        if !self.pre_commits.is_empty() {
            self.pre_commits.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.encoded_payload_length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl Decodable for DbftRecoveryMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut payload = Header::decode_bytes(buf, true)?;
        let preparations = decode_capped(&mut payload, MAX_RECOVERY_PAYLOADS)?;
        let commits = decode_capped(&mut payload, MAX_RECOVERY_PAYLOADS)?;
        let change_views = decode_capped(&mut payload, MAX_RECOVERY_PAYLOADS)?;
        let preparation_hash =
            (!payload.is_empty()).then(|| decode_optional(&mut payload)).transpose()?.flatten();
        let prepare_request =
            (!payload.is_empty()).then(|| decode_optional(&mut payload)).transpose()?.flatten();
        let pre_commits = if payload.is_empty() {
            Vec::new()
        } else {
            decode_capped(&mut payload, MAX_RECOVERY_PAYLOADS)?
        };
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::ListLengthMismatch { expected: 6, got: 7 });
        }
        let message = Self {
            preparations,
            commits,
            change_views,
            preparation_hash,
            prepare_request,
            pre_commits,
        };
        message.validate_limits()?;
        Ok(message)
    }
}

impl DbftRecoveryMessage {
    /// Creates an empty recovery accumulator.
    pub const fn new() -> Self {
        Self {
            preparations: Vec::new(),
            commits: Vec::new(),
            change_views: Vec::new(),
            preparation_hash: None,
            prepare_request: None,
            pre_commits: Vec::new(),
        }
    }

    /// Adds one authenticated consensus message to the compact recovery accumulator.
    pub fn add_message(&mut self, message: &DbftMessage) -> Result<(), DbftPayloadError> {
        message.verify_witness().map_err(|error| {
            DbftPayloadError::InvalidRecoveredMessage(format!(
                "cannot compact an unauthenticated dBFT message: {error:?}"
            ))
        })?;
        let data = message
            .consensus_data()
            .map_err(|error| DbftPayloadError::InvalidRecoveredMessage(error.to_string()))?;
        let payload = data.decoded_payload()?;
        match payload {
            DbftDecodedPayload::PrepareRequest(_) => {
                self.reject_duplicate_preparation(data.validator_index)?;
                // Matches Neo X Geth `recoveryMessage.AddPayload`: a PrepareRequest's own hash is
                // authoritative for the round and overwrites any hash previously inferred from a
                // PrepareResponse. The compact form stores a single shared preparation hash, so
                // reconstruction (`expand`) stamps every response with this value and the request's
                // hash is the canonical one whenever a request is present. Do not reject a
                // differing accumulated hash here — Geth tolerates it, and erroring
                // stalls recovery entirely.
                self.preparation_hash = Some(message.hash());
                // Neo X Geth only retains type, view, and body in the embedded request. The
                // outer recovery height and calculated primary restore the other two fields.
                self.prepare_request = Some(DbftConsensusData {
                    message_type: DbftMessageType::PrepareRequest,
                    block_index: 0,
                    validator_index: 0,
                    view_number: data.view_number,
                    payload: data.payload,
                });
                self.preparations.push(PreparationCompact {
                    validator_index: data.validator_index,
                    invocation_script: message.witness.clone(),
                });
            }
            DbftDecodedPayload::PrepareResponse(response) => {
                self.reject_duplicate_preparation(data.validator_index)?;
                self.preparations.push(PreparationCompact {
                    validator_index: data.validator_index,
                    invocation_script: message.witness.clone(),
                });
                // Matches Neo X Geth `recoveryMessage.AddPayload`: a PrepareResponse only supplies
                // the shared preparation hash when none is known yet; it never overrides a
                // PrepareRequest's hash and never rejects a differing one.
                if self.preparation_hash.is_none() {
                    self.preparation_hash = Some(response.preparation_hash);
                }
            }
            DbftDecodedPayload::ChangeView(change_view) => {
                reject_duplicate_index(
                    self.change_views.iter().map(|entry| entry.validator_index),
                    data.validator_index,
                    "change-view",
                )?;
                self.change_views.push(ChangeViewCompact {
                    validator_index: data.validator_index,
                    original_view_number: data.view_number,
                    timestamp_ns: change_view.timestamp_ns,
                    invocation_script: message.witness.clone(),
                });
            }
            DbftDecodedPayload::PreCommit(pre_commit) => {
                reject_duplicate_index(
                    self.pre_commits.iter().map(|entry| entry.validator_index),
                    data.validator_index,
                    "pre-commit",
                )?;
                self.pre_commits.push(PreCommitCompact {
                    view_number: data.view_number,
                    validator_index: data.validator_index,
                    data: pre_commit.data,
                    invocation_script: message.witness.clone(),
                });
            }
            DbftDecodedPayload::Commit(commit) => {
                reject_duplicate_index(
                    self.commits.iter().map(|entry| entry.validator_index),
                    data.validator_index,
                    "commit",
                )?;
                self.commits.push(CommitCompact {
                    view_number: data.view_number,
                    validator_index: data.validator_index,
                    signature: commit.signature,
                    invocation_script: message.witness.clone(),
                });
            }
            DbftDecodedPayload::RecoveryRequest(_) | DbftDecodedPayload::RecoveryMessage(_) => {
                return Err(DbftPayloadError::InvalidRecoveredMessage(
                    "recovery control messages cannot be nested".to_owned(),
                ))
            }
        }
        Ok(())
    }

    fn reject_duplicate_preparation(&self, index: u8) -> Result<(), DbftPayloadError> {
        reject_duplicate_index(
            self.preparations.iter().map(|entry| entry.validator_index),
            index,
            "preparation",
        )
    }

    /// Whether the optional preparation-hash slot is written. It is present whenever any later
    /// optional field follows it, so trailing fields keep their fixed RLP positions.
    const fn includes_preparation_hash(&self) -> bool {
        self.preparation_hash.is_some() || self.includes_prepare_request()
    }

    /// Whether the optional embedded prepare-request slot is written.
    const fn includes_prepare_request(&self) -> bool {
        self.prepare_request.is_some() || !self.pre_commits.is_empty()
    }

    fn encoded_payload_length(&self) -> usize {
        let mut length =
            self.preparations.length() + self.commits.length() + self.change_views.length();
        if self.includes_preparation_hash() {
            length +=
                self.preparation_hash.map_or_else(|| Bytes::new().length(), |hash| hash.length());
        }
        if self.includes_prepare_request() {
            length += self.prepare_request.as_ref().map_or_else(
                || Header { list: true, payload_length: 0 }.length(),
                Encodable::length,
            );
        }
        if !self.pre_commits.is_empty() {
            length += self.pre_commits.length();
        }
        length
    }

    fn validate_limits(&self) -> alloy_rlp::Result<()> {
        if self.preparations.len() > MAX_RECOVERY_PAYLOADS ||
            self.commits.len() > MAX_RECOVERY_PAYLOADS ||
            self.change_views.len() > MAX_RECOVERY_PAYLOADS ||
            self.pre_commits.len() > MAX_RECOVERY_PAYLOADS
        {
            return Err(alloy_rlp::Error::Custom("too many compact dBFT recovery payloads"));
        }
        if self
            .prepare_request
            .as_ref()
            .is_some_and(|request| request.message_type != DbftMessageType::PrepareRequest)
        {
            return Err(alloy_rlp::Error::Custom("recovery payload embeds wrong message type"));
        }
        for pre_commit in &self.pre_commits {
            DbftPreCommit::from_data(pre_commit.data.clone())
                .map_err(|_| alloy_rlp::Error::Custom("invalid recovered PreCommit shares"))?;
        }
        Ok(())
    }

    /// Reconstructs and authenticates the original messages represented by this compact recovery
    /// payload.
    ///
    /// Neo X Geth retains each original outer witness in the compact entries. This method rebuilds
    /// the exact signed message and verifies that witness before exposing it to the round state
    /// machine. Change-view reasons are not carried explicitly by the compact wire format, so the
    /// seven protocol-defined values are tried deterministically to recover the signed value.
    pub fn expand(
        &self,
        recovery: &DbftMessage,
        validators: &[Address],
    ) -> Result<Vec<DbftMessage>, DbftPayloadError> {
        let recovery_data = recovery
            .consensus_data()
            .map_err(|error| DbftPayloadError::InvalidRecoveredMessage(error.to_string()))?;
        if recovery_data.message_type != DbftMessageType::RecoveryMessage {
            return Err(DbftPayloadError::InvalidRecoveredMessage(
                "recovery expansion requires a RecoveryMessage outer payload".to_owned(),
            ));
        }
        if validators.is_empty() || validators.len() > usize::from(u8::MAX) + 1 {
            return Err(DbftPayloadError::InvalidRecoveredMessage(format!(
                "invalid recovery validator count {}",
                validators.len()
            )));
        }

        validate_unique_indices(
            self.preparations.iter().map(|compact| compact.validator_index),
            validators.len(),
            "preparation",
        )?;
        validate_unique_indices(
            self.pre_commits.iter().map(|compact| compact.validator_index),
            validators.len(),
            "pre-commit",
        )?;
        validate_unique_indices(
            self.commits.iter().map(|compact| compact.validator_index),
            validators.len(),
            "commit",
        )?;
        validate_unique_indices(
            self.change_views.iter().map(|compact| compact.validator_index),
            validators.len(),
            "change-view",
        )?;

        let height = recovery_data.block_index;
        let recovery_view = recovery_data.view_number;
        let validator_count = validators.len() as u64;
        // Truncated to 32 bits to match the reference client's dBFT context, which stores the block
        // index as a `uint32`. Primary selection must agree across clients, so the truncation is
        // reproduced rather than corrected.
        let primary_index = ((u64::from(height as u32) + validator_count -
            u64::from(recovery_view) % validator_count) %
            validator_count) as u8;
        let mut expanded = Vec::with_capacity(
            self.preparations.len() +
                self.pre_commits.len() +
                self.commits.len() +
                self.change_views.len() +
                usize::from(self.prepare_request.is_some()),
        );

        // The compact ChangeView omits the reason. Recover it from the original signed witness.
        for compact in &self.change_views {
            let sender = validators[usize::from(compact.validator_index)];
            let mut authenticated = None;
            for reason in [
                DbftChangeViewReason::Timeout,
                DbftChangeViewReason::ChangeAgreement,
                DbftChangeViewReason::TransactionNotFound,
                DbftChangeViewReason::TransactionRejectedByPolicy,
                DbftChangeViewReason::TransactionInvalid,
                DbftChangeViewReason::BlockRejectedByPolicy,
                DbftChangeViewReason::Unknown,
            ] {
                let payload = DbftChangeView::new(compact.timestamp_ns, reason);
                let candidate = recovered_message(
                    height,
                    sender,
                    compact.validator_index,
                    compact.original_view_number,
                    DbftMessageType::ChangeView,
                    alloy_rlp::encode(payload).into(),
                    compact.invocation_script.clone(),
                );
                if candidate.verify_witness().is_ok() && authenticated.replace(candidate).is_some()
                {
                    return Err(DbftPayloadError::InvalidRecoveredMessage(format!(
                        "ambiguous recovered ChangeView witness for validator {}",
                        compact.validator_index
                    )));
                }
            }
            expanded.push(authenticated.ok_or_else(|| {
                DbftPayloadError::InvalidRecoveredMessage(format!(
                    "invalid recovered ChangeView witness for validator {}",
                    compact.validator_index
                ))
            })?);
        }

        let primary_compact =
            self.preparations.iter().find(|compact| compact.validator_index == primary_index);
        if let (Some(request), Some(compact)) = (&self.prepare_request, primary_compact) {
            let message = recovered_message(
                height,
                validators[usize::from(primary_index)],
                primary_index,
                recovery_view,
                DbftMessageType::PrepareRequest,
                request.payload.clone(),
                compact.invocation_script.clone(),
            );
            verify_recovered(&message, "PrepareRequest", primary_index)?;
            expanded.push(message);
        }

        if let Some(preparation_hash) = self.preparation_hash {
            for compact in
                self.preparations.iter().filter(|compact| compact.validator_index != primary_index)
            {
                let response = DbftPrepareResponse { preparation_hash };
                let message = recovered_message(
                    height,
                    validators[usize::from(compact.validator_index)],
                    compact.validator_index,
                    recovery_view,
                    DbftMessageType::PrepareResponse,
                    alloy_rlp::encode(response).into(),
                    compact.invocation_script.clone(),
                );
                verify_recovered(&message, "PrepareResponse", compact.validator_index)?;
                expanded.push(message);
            }
        }

        for compact in &self.pre_commits {
            let payload = DbftPreCommit::from_data(compact.data.clone())?;
            let message = recovered_message(
                height,
                validators[usize::from(compact.validator_index)],
                compact.validator_index,
                compact.view_number,
                DbftMessageType::PreCommit,
                alloy_rlp::encode(payload).into(),
                compact.invocation_script.clone(),
            );
            verify_recovered(&message, "PreCommit", compact.validator_index)?;
            expanded.push(message);
        }

        for compact in &self.commits {
            let payload = DbftCommit { signature: compact.signature.clone() };
            let message = recovered_message(
                height,
                validators[usize::from(compact.validator_index)],
                compact.validator_index,
                compact.view_number,
                DbftMessageType::Commit,
                alloy_rlp::encode(payload).into(),
                compact.invocation_script.clone(),
            );
            verify_recovered(&message, "Commit", compact.validator_index)?;
            expanded.push(message);
        }

        Ok(expanded)
    }
}

fn reject_duplicate_index(
    indices: impl Iterator<Item = u8>,
    index: u8,
    kind: &'static str,
) -> Result<(), DbftPayloadError> {
    if indices.into_iter().any(|existing| existing == index) {
        return Err(DbftPayloadError::InvalidRecoveredMessage(format!(
            "duplicate recovered {kind} for validator {index}"
        )));
    }
    Ok(())
}

fn validate_unique_indices(
    indices: impl Iterator<Item = u8>,
    validator_count: usize,
    kind: &'static str,
) -> Result<(), DbftPayloadError> {
    let mut seen = HashSet::new();
    for index in indices {
        if usize::from(index) >= validator_count {
            return Err(DbftPayloadError::InvalidRecoveredMessage(format!(
                "recovered {kind} validator index {index} is outside set of {validator_count}"
            )));
        }
        if !seen.insert(index) {
            return Err(DbftPayloadError::InvalidRecoveredMessage(format!(
                "duplicate recovered {kind} for validator {index}"
            )));
        }
    }
    Ok(())
}

fn recovered_message(
    height: u64,
    sender: Address,
    validator_index: u8,
    view_number: u8,
    message_type: DbftMessageType,
    payload: Bytes,
    witness: Bytes,
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
    DbftMessage {
        valid_block_start: 0,
        valid_block_end: height,
        sender,
        data: encoded_data.into(),
        witness,
    }
}

fn verify_recovered(
    message: &DbftMessage,
    kind: &'static str,
    validator_index: u8,
) -> Result<(), DbftPayloadError> {
    message.verify_witness().map_err(|error| {
        DbftPayloadError::InvalidRecoveredMessage(format!(
            "invalid recovered {kind} witness for validator {validator_index}: {error:?}"
        ))
    })
}

/// Fully decoded type-specific dBFT body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbftDecodedPayload {
    /// Change-view request.
    ChangeView(DbftChangeView),
    /// Primary block proposal.
    PrepareRequest(Box<DbftPrepareRequest>),
    /// Backup proposal acknowledgement.
    PrepareResponse(DbftPrepareResponse),
    /// Anti-MEV share contribution.
    PreCommit(DbftPreCommit),
    /// Block signature contribution.
    Commit(DbftCommit),
    /// Recovery request.
    RecoveryRequest(DbftRecoveryRequest),
    /// Aggregated recovery state.
    RecoveryMessage(Box<DbftRecoveryMessage>),
}

impl DbftConsensusData {
    /// Decodes and validates the payload selected by the outer dBFT message type.
    pub fn decoded_payload(&self) -> Result<DbftDecodedPayload, DbftPayloadError> {
        let decoded = match self.message_type {
            DbftMessageType::ChangeView => {
                let payload: DbftChangeView = decode_payload(&self.payload)?;
                payload.reason()?;
                DbftDecodedPayload::ChangeView(payload)
            }
            DbftMessageType::PrepareRequest => {
                DbftDecodedPayload::PrepareRequest(Box::new(decode_payload(&self.payload)?))
            }
            DbftMessageType::PrepareResponse => {
                DbftDecodedPayload::PrepareResponse(decode_payload(&self.payload)?)
            }
            DbftMessageType::PreCommit => {
                DbftDecodedPayload::PreCommit(decode_payload(&self.payload)?)
            }
            DbftMessageType::Commit => {
                let payload: DbftCommit = decode_payload(&self.payload)?;
                payload.validated_signature()?;
                DbftDecodedPayload::Commit(payload)
            }
            DbftMessageType::RecoveryRequest => {
                DbftDecodedPayload::RecoveryRequest(decode_payload(&self.payload)?)
            }
            DbftMessageType::RecoveryMessage => {
                DbftDecodedPayload::RecoveryMessage(Box::new(decode_payload(&self.payload)?))
            }
        };
        Ok(decoded)
    }
}

/// Type-specific dBFT payload error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DbftPayloadError {
    /// RLP payload is malformed or has trailing bytes.
    #[error("invalid dBFT payload RLP: {0}")]
    InvalidRlp(String),
    /// Change-view reason is not recognized by the Neo X dBFT library.
    #[error("invalid dBFT change-view reason {0:#x}")]
    InvalidChangeViewReason(u8),
    /// `PreCommit` is shorter than its two little-endian counters.
    #[error("dBFT PreCommit share packet is too short: {0}")]
    SharesTooShort(usize),
    /// `PreCommit` carries more shares than Neo X Geth permits.
    #[error("dBFT PreCommit carries too many shares: {0}")]
    TooManyShares(usize),
    /// `PreCommit` share bytes do not match its counters.
    #[error("invalid dBFT share packet length: expected {expected}, got {actual}")]
    InvalidSharesLength {
        /// Expected packet length.
        expected: usize,
        /// Actual packet length.
        actual: usize,
    },
    /// One compressed BLS12-381 share is malformed or outside the subgroup.
    #[error("invalid dBFT decryption share: {0}")]
    InvalidDecryptionShare(String),
    /// A compact recovery entry could not be reconstructed as an authenticated original message.
    #[error("invalid dBFT recovery entry: {0}")]
    InvalidRecoveredMessage(String),
    /// Commit signatures are either 65-byte ECDSA values or 96-byte BLS G2 shares.
    #[error("invalid dBFT Commit signature length {0}")]
    InvalidCommitLength(usize),
    /// Recoverable ECDSA signatures only permit parity values zero and one.
    #[error("invalid dBFT Commit ECDSA recovery ID {0}")]
    InvalidCommitRecoveryId(u8),
    /// A threshold Commit contribution is not a subgroup-valid compressed G2 point.
    #[error("invalid dBFT Commit threshold share: {0}")]
    InvalidCommitSignatureShare(String),
}

fn decode_payload<T: Decodable>(payload: &[u8]) -> Result<T, DbftPayloadError> {
    decode_exact(payload).map_err(|error| DbftPayloadError::InvalidRlp(error.to_string()))
}

fn decode_optional<T: Decodable>(buf: &mut &[u8]) -> alloy_rlp::Result<Option<T>> {
    if matches!(buf.first(), Some(0x80 | 0xc0)) {
        *buf = &buf[1..];
        Ok(None)
    } else {
        T::decode(buf).map(Some)
    }
}

/// Decodes an RLP list of at most `max` items, erroring as soon as the cap is exceeded.
///
/// Unlike `decode_exact::<Vec<T>>`, this stops before materializing an over-cap vector, so an
/// adversarial `dbft/0` frame cannot force allocation of ~10^6 compact entries within the 4 MiB
/// message before `validate_limits` rejects it. Accept/reject behavior is identical for in-limit
/// inputs, and the over-limit error matches `validate_limits`'s.
fn decode_capped<T: Decodable>(buf: &mut &[u8], max: usize) -> alloy_rlp::Result<Vec<T>> {
    let mut payload = Header::decode_bytes(buf, true)?;
    let mut out = Vec::new();
    while !payload.is_empty() {
        if out.len() == max {
            return Err(alloy_rlp::Error::Custom("too many compact dBFT recovery payloads"));
        }
        out.push(T::decode(&mut payload)?);
    }
    Ok(out)
}

impl fmt::Display for DbftDecodedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ChangeView(_) => "ChangeView",
            Self::PrepareRequest(_) => "PrepareRequest",
            Self::PrepareResponse(_) => "PrepareResponse",
            Self::PreCommit(_) => "PreCommit",
            Self::Commit(_) => "Commit",
            Self::RecoveryRequest(_) => "RecoveryRequest",
            Self::RecoveryMessage(_) => "RecoveryMessage",
        };
        formatter.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use reth_neox_antimev::sign_share;

    struct TestValidator {
        address: Address,
        key: k256::ecdsa::SigningKey,
    }

    fn test_validators() -> Vec<TestValidator> {
        let mut validators = (1_u8..=7)
            .map(|byte| {
                let key = k256::ecdsa::SigningKey::from_slice(B256::repeat_byte(byte).as_slice())
                    .unwrap();
                TestValidator { address: Address::from_public_key(key.verifying_key()), key }
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|validator| validator.address);
        validators
    }

    fn signed_message<T: Encodable>(
        validator: &TestValidator,
        height: u64,
        index: u8,
        view: u8,
        message_type: DbftMessageType,
        payload: &T,
    ) -> DbftMessage {
        let mut message = recovered_message(
            height,
            validator.address,
            index,
            view,
            message_type,
            alloy_rlp::encode(payload).into(),
            Bytes::new(),
        );
        let (signature, recovery_id) =
            validator.key.sign_prehash_recoverable(message.hash().as_slice()).unwrap();
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();
        message
    }

    fn threshold_commit() -> DbftCommit {
        let mut private_key = [0_u8; 32];
        private_key[31] = 1;
        let share = sign_share(b"Neo X dBFT network test", &private_key, false).unwrap();
        DbftCommit { signature: Bytes::copy_from_slice(share.as_bytes()) }
    }

    fn list_with_empty_tail(mut payload: Vec<u8>) -> Vec<u8> {
        payload.extend(std::iter::repeat_n(0x80, 250_000));
        let mut encoded = Vec::new();
        Header { list: true, payload_length: payload.len() }.encode(&mut encoded);
        encoded.extend_from_slice(&payload);
        encoded
    }

    #[test]
    fn decodes_geth_prepare_response_vector() {
        let payload =
            hex::decode("e1a02222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        assert_eq!(
            decode_payload::<DbftPrepareResponse>(&payload).unwrap().preparation_hash,
            B256::repeat_byte(0x22)
        );
    }

    #[test]
    fn decodes_geth_change_commit_and_recovery_vectors() {
        let change =
            decode_payload::<DbftChangeView>(&hex::decode("c684075bcd1504").unwrap()).unwrap();
        assert_eq!(change.timestamp_ns, 123_456_789);
        assert_eq!(change.reason().unwrap(), DbftChangeViewReason::TransactionInvalid);

        let commit = decode_payload::<DbftCommit>(
            &hex::decode(concat!(
                "f843b8413333333333333333333333333333333333333333333333333333333333333333",
                "333333333333333333333333333333333333333333333333333333333333333301"
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(commit.signature.len(), 65);

        // Geth encodes a nil optional embedded PrepareRequest as an empty RLP list when the
        // following optional PreCommit vector is present.
        let recovery_bytes = hex::decode(concat!(
            "f845c4c30181aac7c6020381bb81ccc6c504014d81dda022222222222222222222222222",
            "22222222222222222222222222222222222222c0cecd020588000000000000000081ee"
        ))
        .unwrap();
        let recovery = decode_payload::<DbftRecoveryMessage>(&recovery_bytes).unwrap();
        assert_eq!(recovery.preparations.len(), 1);
        assert_eq!(recovery.commits.len(), 1);
        assert_eq!(recovery.change_views.len(), 1);
        assert_eq!(recovery.preparation_hash, Some(B256::repeat_byte(0x22)));
        assert!(recovery.prepare_request.is_none());
        assert_eq!(recovery.pre_commits.len(), 1);
        assert_eq!(alloy_rlp::encode(&recovery), recovery_bytes);
    }

    #[test]
    fn decodes_geth_prepare_request_header_vector() {
        let encoded = hex::decode(concat!(
            "f90246f901ffa000000000000000000000000000000000000000000000000000",
            "00000000000001a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413",
            "f0a142fd40d49347941212000000000000000000000000000000000003a00000",
            "000000000000000000000000000000000000000000000000000000000002a056",
            "e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0",
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "b901000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000022a8401c9c380825208846b49d200820201a000000000000000000000",
            "0000000000000000000000000000000000000000000388000000000000000085",
            "09502f9000f842a0000000000000000000000000000000000000000000000000",
            "0000000000000011a00000000000000000000000000000000000000000000000",
            "000000000000000012"
        ))
        .unwrap();
        let request = decode_payload::<DbftPrepareRequest>(&encoded).unwrap();
        assert_eq!(request.sealing_proposal.number, 42);
        assert_eq!(request.sealing_proposal.gas_limit, 30_000_000);
        assert_eq!(request.transaction_hashes.len(), 2);
        assert_eq!(request.transaction_hashes[0], B256::with_last_byte(0x11));
        assert_eq!(request.transaction_hashes[1], B256::with_last_byte(0x12));
        assert!(request.parent_seal_hash_v0.is_none());
        assert!(request.parent_extra.is_none());
    }

    #[test]
    fn fixed_arity_payloads_reject_many_extra_items_without_materializing_them() {
        let mut prepare = Vec::new();
        EthereumHeader::default().encode(&mut prepare);
        Vec::<B256>::new().encode(&mut prepare);
        B256::ZERO.encode(&mut prepare);
        Bytes::new().encode(&mut prepare);
        assert!(decode_payload::<DbftPrepareRequest>(&list_with_empty_tail(prepare)).is_err());

        let mut pre_commit = Vec::new();
        Bytes::from(vec![0_u8; PRECOMMIT_COUNT_PREFIX_LEN]).encode(&mut pre_commit);
        assert!(decode_payload::<DbftPreCommit>(&list_with_empty_tail(pre_commit)).is_err());

        // Three required compact vectors followed by all three optional slots.
        let recovery = vec![0xc0, 0xc0, 0xc0, 0x80, 0xc0, 0xc0];
        assert!(decode_payload::<DbftRecoveryMessage>(&list_with_empty_tail(recovery)).is_err());
    }

    #[test]
    fn precommit_accepts_empty_share_sets() {
        let data = Bytes::from(vec![0_u8; PRECOMMIT_COUNT_PREFIX_LEN]);
        let decoded = DbftPreCommit::from_data(data.clone()).unwrap();
        assert!(decoded.current_round.is_empty());
        assert!(decoded.previous_round.is_empty());
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn precommit_rejects_counter_length_mismatch() {
        let mut data = vec![0_u8; PRECOMMIT_COUNT_PREFIX_LEN];
        data[0] = 1;
        assert!(matches!(
            DbftPreCommit::from_data(data.into()),
            Err(DbftPayloadError::InvalidSharesLength { expected: 56, actual: 8 })
        ));
    }

    #[test]
    fn recovery_expansion_reauthenticates_original_messages() {
        let validators = test_validators();
        let accounts = validators.iter().map(|validator| validator.address).collect::<Vec<_>>();
        let height = 42;
        let view = 0;
        // `(42 - 0) mod 7 == 0`.
        let primary_index = 0;
        let proposal = DbftPrepareRequest {
            sealing_proposal: EthereumHeader { number: height, ..Default::default() },
            transaction_hashes: vec![B256::repeat_byte(0x11)],
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let request = signed_message(
            &validators[primary_index],
            height,
            primary_index as u8,
            view,
            DbftMessageType::PrepareRequest,
            &proposal,
        );
        let response_payload = DbftPrepareResponse { preparation_hash: request.hash() };
        let response = signed_message(
            &validators[1],
            height,
            1,
            view,
            DbftMessageType::PrepareResponse,
            &response_payload,
        );
        let change_payload =
            DbftChangeView::new(123_456_789, DbftChangeViewReason::TransactionInvalid);
        let change = signed_message(
            &validators[2],
            height,
            2,
            view,
            DbftMessageType::ChangeView,
            &change_payload,
        );
        let pre_commit_payload = DbftPreCommit::from_data(Bytes::from(vec![0_u8; 8])).unwrap();
        let pre_commit = signed_message(
            &validators[3],
            height,
            3,
            view,
            DbftMessageType::PreCommit,
            &pre_commit_payload,
        );
        let commit_payload = threshold_commit();
        let commit = signed_message(
            &validators[4],
            height,
            4,
            view,
            DbftMessageType::Commit,
            &commit_payload,
        );

        let mut recovery = DbftRecoveryMessage::new();
        for message in [&request, &response, &change, &pre_commit, &commit] {
            recovery.add_message(message).unwrap();
        }
        let recovery =
            decode_payload::<DbftRecoveryMessage>(&alloy_rlp::encode(&recovery)).unwrap();
        let recovery_outer = recovered_message(
            height,
            validators[5].address,
            5,
            view,
            DbftMessageType::RecoveryMessage,
            Bytes::from_static(&[0xc0]),
            Bytes::new(),
        );

        let expanded = recovery.expand(&recovery_outer, &accounts).unwrap();
        assert_eq!(expanded.len(), 5);
        for expected in [change, request, response, pre_commit, commit] {
            assert!(expanded.contains(&expected));
        }
    }

    #[test]
    fn recovery_build_tolerates_prepare_response_hash_mismatch() {
        // Reproduces the all-Reth validator stall: a node accumulates a PrepareResponse whose
        // claimed preparation hash differs from the round's PrepareRequest hash. Neo X Geth's
        // `recoveryMessage.AddPayload` tolerates this — the PrepareRequest hash is authoritative
        // and the compact form keeps only a single shared preparation hash. An earlier
        // strict conflict check here returned `InvalidRecoveredMessage` while building the
        // recovery message, which aborted `ConsensusState::recovery_message` and stalled
        // block production.
        let validators = test_validators();
        let height = 43;
        let view = 0;
        // `(43 - 0) mod 7 == 1`.
        let primary_index = 1_u8;
        let proposal = DbftPrepareRequest {
            sealing_proposal: EthereumHeader { number: height, ..Default::default() },
            transaction_hashes: vec![B256::repeat_byte(0x11)],
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let request = signed_message(
            &validators[usize::from(primary_index)],
            height,
            primary_index,
            view,
            DbftMessageType::PrepareRequest,
            &proposal,
        );
        // A backup response that points at a different preparation hash than the request produces.
        let stale_hash = B256::repeat_byte(0xAB);
        assert_ne!(stale_hash, request.hash());
        let response = signed_message(
            &validators[0],
            height,
            0,
            view,
            DbftMessageType::PrepareResponse,
            &DbftPrepareResponse { preparation_hash: stale_hash },
        );

        // Response accumulated before the request (lower validator index sorts first) must not
        // abort, and the PrepareRequest hash wins.
        let mut recovery = DbftRecoveryMessage::new();
        recovery.add_message(&response).expect("stale response must not abort recovery build");
        recovery.add_message(&request).expect("request must not conflict with a stale response");
        assert_eq!(recovery.preparation_hash, Some(request.hash()));

        // Reverse order (request first, then a stale response) is equally tolerant.
        let mut reverse = DbftRecoveryMessage::new();
        reverse.add_message(&request).unwrap();
        reverse.add_message(&response).unwrap();
        assert_eq!(reverse.preparation_hash, Some(request.hash()));
    }

    #[test]
    fn recovery_decode_caps_compact_vectors_at_the_limit() {
        // A compact vector with exactly MAX_RECOVERY_PAYLOADS entries decodes; one more is rejected
        // during decode (before the over-cap vector is materialized) with the same error
        // `validate_limits` used to raise afterward.
        let preparation = |index: u8| PreparationCompact {
            validator_index: index,
            invocation_script: Bytes::new(),
        };
        let mut at_cap = DbftRecoveryMessage::new();
        at_cap.preparations = (0..MAX_RECOVERY_PAYLOADS).map(|i| preparation(i as u8)).collect();
        at_cap.preparation_hash = Some(B256::repeat_byte(0x11));
        let decoded =
            decode_payload::<DbftRecoveryMessage>(&alloy_rlp::encode(&at_cap)).expect("at cap");
        assert_eq!(decoded.preparations.len(), MAX_RECOVERY_PAYLOADS);

        let mut over_cap = at_cap;
        over_cap.preparations.push(preparation(0));
        let error =
            decode_payload::<DbftRecoveryMessage>(&alloy_rlp::encode(&over_cap)).unwrap_err();
        assert!(
            matches!(&error, DbftPayloadError::InvalidRlp(message) if message.contains("too many")),
            "{error:?}"
        );
    }
}
