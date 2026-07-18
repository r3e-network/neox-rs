//! Governance validator discovery and the Neo X dBFT round state machine.

use alloy_primitives::{Address, B256, U256};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use reth_neox_consensus::bft_honest_node_count;
use reth_neox_evm::{
    governance_current_consensus_storage_key, GOVERNANCE_CURRENT_CONSENSUS_SLOT,
    GOVERNANCE_PROXY_ADDRESS,
};
use reth_neox_network::{DbftDecodedPayload, DbftMessage, DbftMessageType, DbftProtocolViolation};
use reth_provider::StateProvider;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

/// Maximum Governance array length accepted before allocating validator storage.
const MAX_VALIDATOR_COUNT: usize = 256;

/// Reads and sorts the active `Governance.currentConsensus` array exactly as Neo X Geth does.
pub fn read_governance_validators(
    state: &dyn StateProvider,
) -> Result<Vec<Address>, DbftStateError> {
    read_governance_validators_from_storage(|key| {
        state
            .storage(GOVERNANCE_PROXY_ADDRESS, key)
            .map_err(|error| DbftStateError::Provider(error.to_string()))
    })
}

fn read_governance_validators_from_storage(
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DbftStateError>,
) -> Result<Vec<Address>, DbftStateError> {
    let raw_length =
        storage(U256::from(GOVERNANCE_CURRENT_CONSENSUS_SLOT).into())?.unwrap_or_default();
    let length = usize::try_from(raw_length)
        .map_err(|_| DbftStateError::InvalidValidatorCount(MAX_VALIDATOR_COUNT + 1))?;
    if length != NEOX_VALIDATOR_COUNT || length > MAX_VALIDATOR_COUNT {
        return Err(DbftStateError::InvalidValidatorCount(length))
    }

    let mut validators = Vec::with_capacity(length);
    for index in 0..length {
        let value = storage(governance_current_consensus_storage_key(index as u64).into())?
            .ok_or(DbftStateError::MissingValidator(index))?;
        let encoded = value.to_be_bytes::<32>();
        let validator = Address::from_slice(&encoded[12..]);
        if validator.is_zero() {
            return Err(DbftStateError::MissingValidator(index))
        }
        validators.push(validator);
    }
    validators.sort_unstable();
    if validators.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DbftStateError::DuplicateValidator)
    }
    Ok(validators)
}

/// Observable progress of one dBFT message through the current round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbftRoundProgress {
    /// Identical already-processed message.
    Duplicate,
    /// Message was accepted but no quorum boundary was crossed.
    Accepted,
    /// A primary proposal and `M` matching preparation votes are present.
    Prepared {
        /// dBFT view.
        view: u8,
        /// Signed `PrepareRequest` message hash.
        proposal_hash: B256,
        /// Matching primary plus backup votes.
        votes: usize,
    },
    /// Anti-MEV decryption shares reached the dBFT quorum.
    PreCommitted {
        /// dBFT view.
        view: u8,
        /// Number of distinct validator share messages.
        votes: usize,
    },
    /// Block-signature contributions reached the dBFT quorum.
    Committed {
        /// dBFT view.
        view: u8,
        /// Number of distinct validator signature messages.
        votes: usize,
    },
    /// A dBFT quorum advanced the round to a new view.
    ViewChanged {
        /// Newly active view.
        view: u8,
        /// Validators requesting this view.
        votes: usize,
    },
}

#[derive(Debug, Clone, Default)]
struct ViewState {
    proposal: Option<Arc<DbftMessage>>,
    responses: HashMap<u8, B256>,
    pre_commits: HashMap<u8, B256>,
    commits: HashMap<u8, B256>,
}

/// Deterministic watch-only state machine for one Neo X block height.
#[derive(Debug, Clone)]
pub struct DbftRoundState {
    height: u64,
    validators: Vec<Address>,
    quorum: usize,
    anti_mev: bool,
    current_view: u8,
    views: HashMap<u8, ViewState>,
    change_views: HashMap<u8, HashMap<u8, B256>>,
    seen: HashMap<(u8, DbftMessageType, u8), B256>,
}

impl DbftRoundState {
    /// Starts one round using the byte-sorted active Governance validator set.
    pub fn new(
        height: u64,
        mut validators: Vec<Address>,
        anti_mev: bool,
    ) -> Result<Self, DbftStateError> {
        if validators.len() != NEOX_VALIDATOR_COUNT {
            return Err(DbftStateError::InvalidValidatorCount(validators.len()))
        }
        validators.sort_unstable();
        if validators.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DbftStateError::DuplicateValidator)
        }
        let quorum = bft_honest_node_count(validators.len());
        let mut views = HashMap::new();
        views.insert(0, ViewState::default());
        Ok(Self {
            height,
            validators,
            quorum,
            anti_mev,
            current_view: 0,
            views,
            change_views: HashMap::new(),
            seen: HashMap::new(),
        })
    }

    /// Current proposed block height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Active view after all processed change-view messages.
    pub const fn current_view(&self) -> u8 {
        self.current_view
    }

    /// Number of honest validator messages needed for a decision.
    pub const fn quorum(&self) -> usize {
        self.quorum
    }

    /// Returns the accepted proposal for a view.
    pub fn proposal(&self, view: u8) -> Option<&Arc<DbftMessage>> {
        self.views.get(&view)?.proposal.as_ref()
    }

    /// Authenticates and applies one dBFT message.
    pub fn process(
        &mut self,
        message: Arc<DbftMessage>,
    ) -> Result<DbftRoundProgress, DbftStateError> {
        message.verify_witness().map_err(|error| DbftStateError::Protocol(format!("{error:?}")))?;
        if message.valid_block_end != self.height || message.valid_block_start > self.height {
            return Err(DbftStateError::WrongHeight {
                expected: self.height,
                start: message.valid_block_start,
                end: message.valid_block_end,
            })
        }
        let data = message
            .consensus_data()
            .map_err(|error| DbftStateError::InvalidPayload(error.to_string()))?;
        let payload = data.decoded_payload()?;
        let index = usize::from(data.validator_index);
        let expected = self.validators.get(index).copied().ok_or(
            DbftStateError::ValidatorIndexOutOfBounds {
                index: data.validator_index,
                validator_count: self.validators.len(),
            },
        )?;
        if expected != message.sender {
            return Err(DbftStateError::UnauthorizedValidator {
                index: data.validator_index,
                expected,
                actual: message.sender,
            })
        }

        match data.message_type {
            DbftMessageType::PrepareRequest | DbftMessageType::PrepareResponse
                if data.view_number != self.current_view =>
            {
                return Err(DbftStateError::WrongView {
                    expected: self.current_view,
                    actual: data.view_number,
                })
            }
            DbftMessageType::PreCommit | DbftMessageType::Commit
                if data.view_number > self.current_view =>
            {
                return Err(DbftStateError::WrongView {
                    expected: self.current_view,
                    actual: data.view_number,
                })
            }
            _ => {}
        }

        let hash = message.hash();
        let seen_key = (data.view_number, data.message_type, data.validator_index);
        if let Some(prior) = self.seen.get(&seen_key) {
            return if *prior == hash {
                Ok(DbftRoundProgress::Duplicate)
            } else {
                Err(DbftStateError::Equivocation {
                    view: data.view_number,
                    message_type: data.message_type,
                    validator_index: data.validator_index,
                    first: *prior,
                    second: hash,
                })
            }
        }
        if let DbftDecodedPayload::RecoveryMessage(recovery) = &payload {
            let expanded = recovery.expand(&message, &self.validators)?;
            let recovery_view = data.view_number;
            let recover_change_views = recovery_view > self.current_view;
            let mut next = self.clone();
            next.seen.insert(seen_key, hash);
            let mut result = DbftRoundProgress::Accepted;
            for recovered in expanded {
                let recovered_data = recovered
                    .consensus_data()
                    .map_err(|error| DbftStateError::InvalidPayload(error.to_string()))?;
                let should_process = match recovered_data.message_type {
                    DbftMessageType::ChangeView => recover_change_views,
                    DbftMessageType::PrepareRequest | DbftMessageType::PrepareResponse => {
                        recovery_view == next.current_view
                    }
                    DbftMessageType::PreCommit | DbftMessageType::Commit => {
                        recovery_view <= next.current_view
                    }
                    DbftMessageType::RecoveryRequest | DbftMessageType::RecoveryMessage => false,
                };
                if !should_process {
                    continue
                }
                let progress = next.process(Arc::new(recovered))?;
                if !matches!(progress, DbftRoundProgress::Accepted | DbftRoundProgress::Duplicate) {
                    result = progress;
                }
            }
            *self = next;
            return Ok(result)
        }

        self.seen.insert(seen_key, hash);

        match payload {
            DbftDecodedPayload::ChangeView(_) => {
                let target_view =
                    data.view_number.checked_add(1).ok_or(DbftStateError::ViewOverflow)?;
                if target_view <= self.current_view {
                    return Ok(DbftRoundProgress::Accepted)
                }
                let votes = self.change_views.entry(target_view).or_default();
                votes.insert(data.validator_index, hash);
                if votes.len() >= self.quorum {
                    self.current_view = target_view;
                    self.views.entry(target_view).or_default();
                    return Ok(DbftRoundProgress::ViewChanged {
                        view: target_view,
                        votes: votes.len(),
                    })
                }
                Ok(DbftRoundProgress::Accepted)
            }
            DbftDecodedPayload::PrepareRequest(request) => {
                let primary = self.primary_index(data.view_number);
                if index != primary {
                    return Err(DbftStateError::WrongPrimary {
                        expected: primary as u8,
                        actual: data.validator_index,
                    })
                }
                if request.sealing_proposal.number != self.height {
                    return Err(DbftStateError::ProposalHeight {
                        expected: self.height,
                        actual: request.sealing_proposal.number,
                    })
                }
                self.views.entry(data.view_number).or_default().proposal = Some(message);
                Ok(self.progress(data.view_number))
            }
            DbftDecodedPayload::PrepareResponse(response) => {
                let primary = self.primary_index(data.view_number);
                if index == primary {
                    return Err(DbftStateError::PrimarySentPrepareResponse(data.validator_index))
                }
                self.views
                    .entry(data.view_number)
                    .or_default()
                    .responses
                    .insert(data.validator_index, response.preparation_hash);
                Ok(self.progress(data.view_number))
            }
            DbftDecodedPayload::PreCommit(_) => {
                if !self.anti_mev {
                    return Err(DbftStateError::PreCommitBeforeAntiMev)
                }
                self.views
                    .entry(data.view_number)
                    .or_default()
                    .pre_commits
                    .insert(data.validator_index, hash);
                Ok(self.progress(data.view_number))
            }
            DbftDecodedPayload::Commit(_) => {
                self.views
                    .entry(data.view_number)
                    .or_default()
                    .commits
                    .insert(data.validator_index, hash);
                Ok(self.progress(data.view_number))
            }
            DbftDecodedPayload::RecoveryRequest(_) => Ok(DbftRoundProgress::Accepted),
            DbftDecodedPayload::RecoveryMessage(_) => unreachable!("handled before state mutation"),
        }
    }

    fn primary_index(&self, view: u8) -> usize {
        let validator_count = self.validators.len() as u64;
        ((self.height + validator_count - u64::from(view) % validator_count) % validator_count)
            as usize
    }

    fn progress(&self, view: u8) -> DbftRoundProgress {
        let Some(state) = self.views.get(&view) else { return DbftRoundProgress::Accepted };
        let Some(proposal) = &state.proposal else { return DbftRoundProgress::Accepted };
        let proposal_hash = proposal.hash();
        let prepared_votes =
            1 + state.responses.values().filter(|response| **response == proposal_hash).count();
        if prepared_votes < self.quorum {
            return DbftRoundProgress::Accepted
        }
        if self.anti_mev && state.pre_commits.len() < self.quorum {
            return DbftRoundProgress::Prepared { view, proposal_hash, votes: prepared_votes }
        }
        if state.commits.len() >= self.quorum {
            return DbftRoundProgress::Committed { view, votes: state.commits.len() }
        }
        if self.anti_mev {
            DbftRoundProgress::PreCommitted { view, votes: state.pre_commits.len() }
        } else {
            DbftRoundProgress::Prepared { view, proposal_hash, votes: prepared_votes }
        }
    }
}

/// dBFT state discovery or message-transition error.
#[derive(Debug, Error)]
pub enum DbftStateError {
    /// Canonical state could not be read.
    #[error("failed to read Neo X canonical state: {0}")]
    Provider(String),
    /// Governance did not contain exactly the configured validator count.
    #[error("invalid Neo X Governance validator count: {0}")]
    InvalidValidatorCount(usize),
    /// A dynamic-array validator slot was absent or zero.
    #[error("missing Neo X Governance validator at index {0}")]
    MissingValidator(usize),
    /// Governance returned the same validator account more than once.
    #[error("Neo X Governance validator set contains duplicates")]
    DuplicateValidator,
    /// Network signature or validity checks failed.
    #[error("invalid dBFT protocol message: {0}")]
    Protocol(String),
    /// Type-specific message decoding failed.
    #[error("invalid dBFT payload: {0}")]
    InvalidPayload(String),
    /// Type-specific decoder rejected the payload.
    #[error(transparent)]
    Payload(#[from] reth_neox_network::DbftPayloadError),
    /// Message validity interval does not select this round.
    #[error("wrong dBFT height: expected {expected}, validity is [{start}, {end}]")]
    WrongHeight {
        /// Round height.
        expected: u64,
        /// Message validity start.
        start: u64,
        /// Message validity end.
        end: u64,
    },
    /// Validator index is outside the active Governance set.
    #[error("dBFT validator index {index} is outside set of {validator_count}")]
    ValidatorIndexOutOfBounds {
        /// Received validator index.
        index: u8,
        /// Active validator count.
        validator_count: usize,
    },
    /// Signed sender does not match its index.
    #[error("dBFT validator {index} must be {expected}, got {actual}")]
    UnauthorizedValidator {
        /// Declared validator index.
        index: u8,
        /// Validator selected by Governance.
        expected: Address,
        /// Recovered outer-message signer.
        actual: Address,
    },
    /// Message belongs to a view that is not active.
    #[error("wrong dBFT view: expected {expected}, got {actual}")]
    WrongView {
        /// Active view.
        expected: u8,
        /// Message view.
        actual: u8,
    },
    /// Validator signed two different messages in the same consensus slot.
    #[error("dBFT equivocation in view {view} for {message_type:?} from validator {validator_index}: {first} and {second}")]
    Equivocation {
        /// Consensus view.
        view: u8,
        /// Consensus slot kind.
        message_type: DbftMessageType,
        /// Equivocating validator.
        validator_index: u8,
        /// First message hash.
        first: B256,
        /// Conflicting message hash.
        second: B256,
    },
    /// Change-view target overflowed the single-byte protocol field.
    #[error("dBFT view number overflow")]
    ViewOverflow,
    /// Change-view request targets an already completed view.
    #[error("stale dBFT target view {0}")]
    StaleView(u8),
    /// `PrepareRequest` did not come from the view's calculated primary.
    #[error("wrong dBFT primary: expected validator {expected}, got {actual}")]
    WrongPrimary {
        /// Calculated primary index.
        expected: u8,
        /// Actual sender index.
        actual: u8,
    },
    /// Primary is not allowed to acknowledge its own proposal as a backup.
    #[error("dBFT primary validator {0} sent PrepareResponse")]
    PrimarySentPrepareResponse(u8),
    /// Proposal header does not target the message height.
    #[error("dBFT proposal height mismatch: expected {expected}, got {actual}")]
    ProposalHeight {
        /// Round height.
        expected: u64,
        /// Header-template height.
        actual: u64,
    },
    /// `PreCommit` is only legal once Anti-MEV is active.
    #[error("dBFT PreCommit received before the Anti-MEV fork")]
    PreCommitBeforeAntiMev,
}

impl From<DbftProtocolViolation> for DbftStateError {
    fn from(error: DbftProtocolViolation) -> Self {
        Self::Protocol(format!("{error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{b256, Bytes};
    use alloy_rlp::Encodable;
    use reth_neox_antimev::sign_share;
    use reth_neox_chainspec::NeoXChainSpec;
    use reth_neox_network::{
        DbftCommit, DbftConsensusData, DbftPreCommit, DbftPrepareRequest, DbftPrepareResponse,
        DbftRecoveryMessage,
    };

    struct Validator {
        account: Address,
        key: k256::ecdsa::SigningKey,
    }

    fn validators() -> Vec<Validator> {
        let mut validators = (1_u8..=NEOX_VALIDATOR_COUNT as u8)
            .map(|byte| {
                let key = k256::ecdsa::SigningKey::from_slice(B256::repeat_byte(byte).as_slice())
                    .unwrap();
                Validator { account: Address::from_public_key(key.verifying_key()), key }
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|validator| validator.account);
        validators
    }

    #[test]
    fn reads_canonical_mainnet_governance_validator_storage() {
        let spec = NeoXChainSpec::mainnet().unwrap();
        let storage = spec
            .inner
            .genesis
            .alloc
            .get(&GOVERNANCE_PROXY_ADDRESS)
            .and_then(|account| account.storage.as_ref())
            .expect("canonical Governance genesis storage");
        let validators = read_governance_validators_from_storage(|key| {
            Ok(storage.get(&key).map(|value| U256::from_be_slice(value.as_slice())))
        })
        .unwrap();
        let mut expected = spec.neox.dbft.standby_validators.clone();
        expected.sort_unstable();
        assert_eq!(validators, expected);
        assert_eq!(
            B256::from(governance_current_consensus_storage_key(0)),
            b256!("1b6847dc741a1b0cd08d278845f9d819d87b734759afb55fe2de5cb82a9ae672")
        );
    }

    fn signed_message<T: Encodable>(
        validator: &Validator,
        height: u64,
        validator_index: u8,
        view: u8,
        message_type: DbftMessageType,
        payload: &T,
    ) -> Arc<DbftMessage> {
        let data = DbftConsensusData {
            message_type,
            block_index: height,
            validator_index,
            view_number: view,
            payload: alloy_rlp::encode(payload).into(),
        };
        let mut encoded_data = Vec::new();
        data.encode(&mut encoded_data);
        let mut message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: height,
            sender: validator.account,
            data: encoded_data.into(),
            witness: Bytes::new(),
        };
        let (signature, recovery_id) =
            validator.key.sign_prehash_recoverable(message.hash().as_slice()).unwrap();
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();
        Arc::new(message)
    }

    fn threshold_commit() -> DbftCommit {
        let mut private_key = [0_u8; 32];
        private_key[31] = 1;
        let share = sign_share(b"Neo X dBFT state test", &private_key, false).unwrap();
        DbftCommit { signature: Bytes::copy_from_slice(share.as_bytes()) }
    }

    #[test]
    fn reaches_prepare_precommit_and_commit_quorums() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect();
        let mut round = DbftRoundState::new(42, accounts, true).unwrap();
        assert_eq!(round.quorum(), 5);
        let proposal = DbftPrepareRequest {
            sealing_proposal: Header { number: 42, ..Default::default() },
            transaction_hashes: Vec::new(),
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let request =
            signed_message(&validators[0], 42, 0, 0, DbftMessageType::PrepareRequest, &proposal);
        let proposal_hash = request.hash();
        assert_eq!(round.process(request).unwrap(), DbftRoundProgress::Accepted);

        for (index, validator) in validators.iter().enumerate().take(5).skip(1) {
            let response = signed_message(
                validator,
                42,
                index as u8,
                0,
                DbftMessageType::PrepareResponse,
                &DbftPrepareResponse { preparation_hash: proposal_hash },
            );
            let progress = round.process(response).unwrap();
            if index == 4 {
                assert!(matches!(progress, DbftRoundProgress::Prepared { votes: 5, .. }));
            }
        }

        let pre_commit = DbftPreCommit::from_data(Bytes::from(vec![0_u8; 8])).unwrap();
        for (index, validator) in validators.iter().enumerate().take(5) {
            let message = signed_message(
                validator,
                42,
                index as u8,
                0,
                DbftMessageType::PreCommit,
                &pre_commit,
            );
            let progress = round.process(message).unwrap();
            if index == 4 {
                assert_eq!(progress, DbftRoundProgress::PreCommitted { view: 0, votes: 5 });
            }
        }

        let commit = threshold_commit();
        for (index, validator) in validators.iter().enumerate().take(5) {
            let message =
                signed_message(validator, 42, index as u8, 0, DbftMessageType::Commit, &commit);
            let progress = round.process(message).unwrap();
            if index == 4 {
                assert_eq!(progress, DbftRoundProgress::Committed { view: 0, votes: 5 });
            }
        }
    }

    #[test]
    fn detects_validator_equivocation() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect();
        let mut round = DbftRoundState::new(42, accounts, true).unwrap();
        for preparation_hash in [B256::repeat_byte(1), B256::repeat_byte(2)] {
            let response = signed_message(
                &validators[1],
                42,
                1,
                0,
                DbftMessageType::PrepareResponse,
                &DbftPrepareResponse { preparation_hash },
            );
            let result = round.process(response);
            if preparation_hash == B256::repeat_byte(2) {
                assert!(matches!(result, Err(DbftStateError::Equivocation { .. })));
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn authenticated_recovery_message_restores_committed_round() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect();
        let mut round = DbftRoundState::new(42, accounts, true).unwrap();
        let proposal = DbftPrepareRequest {
            sealing_proposal: Header { number: 42, ..Default::default() },
            transaction_hashes: Vec::new(),
            parent_seal_hash_v0: None,
            parent_extra: None,
        };
        let request =
            signed_message(&validators[0], 42, 0, 0, DbftMessageType::PrepareRequest, &proposal);
        let proposal_hash = request.hash();
        let mut messages = vec![Arc::clone(&request)];
        for (index, validator) in validators.iter().enumerate().take(5).skip(1) {
            messages.push(signed_message(
                validator,
                42,
                index as u8,
                0,
                DbftMessageType::PrepareResponse,
                &DbftPrepareResponse { preparation_hash: proposal_hash },
            ));
        }
        let pre_commit = DbftPreCommit::from_data(Bytes::from(vec![0_u8; 8])).unwrap();
        let commit = threshold_commit();
        for (index, validator) in validators.iter().enumerate().take(5) {
            messages.push(signed_message(
                validator,
                42,
                index as u8,
                0,
                DbftMessageType::PreCommit,
                &pre_commit,
            ));
            messages.push(signed_message(
                validator,
                42,
                index as u8,
                0,
                DbftMessageType::Commit,
                &commit,
            ));
        }

        let mut recovery = DbftRecoveryMessage::new();
        for message in &messages {
            recovery.add_message(message).unwrap();
        }
        let recovery_message =
            signed_message(&validators[6], 42, 6, 0, DbftMessageType::RecoveryMessage, &recovery);
        assert_eq!(
            round.process(recovery_message).unwrap(),
            DbftRoundProgress::Committed { view: 0, votes: 5 }
        );
        assert_eq!(round.proposal(0).unwrap().hash(), proposal_hash);
    }
}
