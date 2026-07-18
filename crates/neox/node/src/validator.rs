//! Governance validator discovery and the Neo X dBFT round state machine.

use crate::dkg::DkgState;
use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, Signature, B256, U256};
use reth_neox_antimev::{
    aggregate_and_verify_signature_shares, SignatureShare, TpkeError, NEOX_DKG_SCALER,
};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use reth_neox_consensus::{
    bft_honest_node_count, ecdsa_seal_hash, threshold_seal_message, verify_ecdsa_signatures,
    verify_threshold_signature, DbftExtra, DbftExtraPrefix, ExtraVersion, SignatureScheme,
};
use reth_neox_evm::{
    governance_current_consensus_storage_key, GOVERNANCE_CURRENT_CONSENSUS_SLOT,
    GOVERNANCE_PROXY_ADDRESS,
};
use reth_neox_network::{
    DbftCommit, DbftCommitSignature, DbftDecodedPayload, DbftMessage, DbftMessageType,
    DbftProtocolViolation,
};
use reth_provider::StateProvider;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

/// Maximum Governance array length accepted before allocating validator storage.
const MAX_VALIDATOR_COUNT: usize = 256;

/// Governance's native ordering together with the byte-sorted dBFT order and DKG indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceValidatorSet {
    /// Exact array order returned by `Governance.getCurrentConsensus()`.
    pub original: Vec<Address>,
    /// Byte-sorted order used for dBFT validator indexes.
    pub sorted: Vec<Address>,
    /// One-based Governance/DKG index corresponding to each byte-sorted validator.
    pub dkg_indices: Vec<u32>,
}

/// Reads and sorts the active `Governance.currentConsensus` array exactly as Neo X Geth does.
pub fn read_governance_validators(
    state: &dyn StateProvider,
) -> Result<Vec<Address>, DbftStateError> {
    read_governance_validator_set(state).map(|set| set.sorted)
}

/// Reads both Governance order and dBFT order, preserving the DKG index mapping used by Geth.
pub fn read_governance_validator_set(
    state: &dyn StateProvider,
) -> Result<GovernanceValidatorSet, DbftStateError> {
    read_governance_validator_set_from_storage(|key| {
        state
            .storage(GOVERNANCE_PROXY_ADDRESS, key)
            .map_err(|error| DbftStateError::Provider(error.to_string()))
    })
}

pub(crate) fn read_governance_validator_set_from_storage(
    mut storage: impl FnMut(B256) -> Result<Option<U256>, DbftStateError>,
) -> Result<GovernanceValidatorSet, DbftStateError> {
    let raw_length =
        storage(U256::from(GOVERNANCE_CURRENT_CONSENSUS_SLOT).into())?.unwrap_or_default();
    let length = usize::try_from(raw_length)
        .map_err(|_| DbftStateError::InvalidValidatorCount(MAX_VALIDATOR_COUNT + 1))?;
    if length != NEOX_VALIDATOR_COUNT || length > MAX_VALIDATOR_COUNT {
        return Err(DbftStateError::InvalidValidatorCount(length))
    }

    let mut original = Vec::with_capacity(length);
    for index in 0..length {
        let value = storage(governance_current_consensus_storage_key(index as u64).into())?
            .ok_or(DbftStateError::MissingValidator(index))?;
        let encoded = value.to_be_bytes::<32>();
        let validator = Address::from_slice(&encoded[12..]);
        if validator.is_zero() {
            return Err(DbftStateError::MissingValidator(index))
        }
        original.push(validator);
    }
    let mut original_sorted = original.clone();
    original_sorted.sort_unstable();
    if original_sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DbftStateError::DuplicateValidator)
    }
    let mut original_indices = (0..length).collect::<Vec<_>>();
    original_indices.sort_unstable_by_key(|index| original[*index]);
    let sorted = original_indices.iter().map(|index| original[*index]).collect();
    let dkg_indices = original_indices.iter().map(|index| *index as u32 + 1).collect();
    Ok(GovernanceValidatorSet { original, sorted, dkg_indices })
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

/// A commit quorum whose contributions have been verified against the finalized proposal header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbftVerifiedCommitSeal {
    /// Recoverable ECDSA signatures ordered by their byte-sorted validator index.
    Ecdsa(Vec<[u8; 65]>),
    /// Aggregated BLS12-381 threshold signature in the wire representation selected by the fork.
    Threshold([u8; 96]),
}

#[derive(Debug, Clone, Default)]
struct ViewState {
    proposal: Option<Arc<DbftMessage>>,
    responses: HashMap<u8, B256>,
    pre_commits: HashMap<u8, B256>,
    commits: HashMap<u8, DbftCommit>,
    final_header: Option<Header>,
    verified_seal: Option<DbftVerifiedCommitSeal>,
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
    dkg_indices: Option<Vec<u32>>,
    dkg_state: Option<DkgState>,
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
            dkg_indices: None,
            dkg_state: None,
        })
    }

    /// Installs the canonical one-based DKG index map and current `KeyManagement` public keys.
    pub fn install_dkg_state(
        &mut self,
        dkg_indices: Vec<u32>,
        dkg_state: DkgState,
    ) -> Result<(), DbftStateError> {
        if dkg_indices.len() != self.validators.len() {
            return Err(DbftStateError::InvalidDkgIndexMap(dkg_indices))
        }
        let mut ordered = dkg_indices.clone();
        ordered.sort_unstable();
        if ordered != (1..=self.validators.len() as u32).collect::<Vec<_>>() {
            return Err(DbftStateError::InvalidDkgIndexMap(dkg_indices))
        }
        self.dkg_indices = Some(dkg_indices);
        self.dkg_state = Some(dkg_state);
        Ok(())
    }

    /// Returns the one-based DKG index for one byte-sorted validator index.
    pub fn dkg_index(&self, validator_index: u8) -> Option<u32> {
        self.dkg_indices.as_ref()?.get(usize::from(validator_index)).copied()
    }

    /// Returns the current and preceding `KeyManagement` public-key state.
    pub const fn dkg_state(&self) -> Option<&DkgState> {
        self.dkg_state.as_ref()
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

    /// Byte-sorted Governance validator accounts active for this height.
    pub fn validators(&self) -> &[Address] {
        &self.validators
    }

    /// Calculates the primary validator index for one view at this height.
    pub fn primary_index(&self, view: u8) -> usize {
        let validator_count = self.validators.len() as u64;
        ((self.height + validator_count - u64::from(view) % validator_count) % validator_count)
            as usize
    }

    /// Returns the accepted proposal for a view.
    pub fn proposal(&self, view: u8) -> Option<&Arc<DbftMessage>> {
        self.views.get(&view)?.proposal.as_ref()
    }

    /// Installs the executed proposal header and verifies any commit contributions already seen.
    pub fn finalize_proposal(
        &mut self,
        view: u8,
        header: Header,
    ) -> Result<DbftRoundProgress, DbftStateError> {
        if header.number != self.height {
            return Err(DbftStateError::ProposalHeight {
                expected: self.height,
                actual: header.number,
            })
        }
        let proposal = self
            .views
            .get(&view)
            .and_then(|state| state.proposal.as_ref())
            .ok_or(DbftStateError::MissingProposal(view))?;
        let data = proposal
            .consensus_data()
            .map_err(|error| DbftStateError::InvalidPayload(error.to_string()))?;
        let DbftDecodedPayload::PrepareRequest(request) = data.decoded_payload()? else {
            return Err(DbftStateError::MissingProposal(view))
        };
        if !proposal_header_matches(&request.sealing_proposal, &header)? {
            return Err(DbftStateError::FinalHeaderMismatch { view })
        }
        self.views.entry(view).or_default().final_header = Some(header);
        self.refresh_verified_seal(view)?;
        Ok(self.progress(view))
    }

    /// Returns the verified commit seal that may safely be installed in the finalized header.
    pub fn verified_commit_seal(&self, view: u8) -> Option<&DbftVerifiedCommitSeal> {
        self.views.get(&view)?.verified_seal.as_ref()
    }

    /// Installs the verified quorum into the finalized header and revalidates the complete seal.
    pub fn sealed_header(&self, view: u8) -> Result<Header, DbftStateError> {
        let state = self.views.get(&view).ok_or(DbftStateError::MissingProposal(view))?;
        let mut header =
            state.final_header.clone().ok_or(DbftStateError::MissingFinalHeader(view))?;
        let seal =
            state.verified_seal.as_ref().ok_or(DbftStateError::MissingVerifiedCommitSeal(view))?;
        let extra = DbftExtraPrefix::decode(&header.extra_data)
            .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
        let sealed_extra = match (extra.signature_scheme(), seal) {
            (SignatureScheme::Ecdsa, DbftVerifiedCommitSeal::Ecdsa(signatures)) => {
                DbftExtra::Ecdsa {
                    version: extra.version(),
                    fallback_next_consensus: extra.fallback_next_consensus(),
                    validators: self.validators.clone(),
                    signatures: signatures.clone(),
                }
            }
            (SignatureScheme::Threshold, DbftVerifiedCommitSeal::Threshold(signature)) => {
                let dkg_state = self.dkg_state.as_ref().ok_or(DbftStateError::MissingDkgState)?;
                DbftExtra::Threshold {
                    version: extra.version(),
                    fallback_next_consensus: extra.fallback_next_consensus().ok_or_else(|| {
                        DbftStateError::InvalidFinalHeader(
                            "missing V1/V2 fallback next consensus".to_string(),
                        )
                    })?,
                    public_key: dkg_state.current.global_public_key,
                    signature: *signature,
                }
            }
            _ => return Err(DbftStateError::CommitSealSchemeMismatch),
        };
        header.extra_data = sealed_extra.encode();
        match seal {
            DbftVerifiedCommitSeal::Ecdsa(_) => {
                verify_ecdsa_signatures(
                    ecdsa_seal_hash(&header)
                        .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?,
                    &sealed_extra,
                )
                .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
            }
            DbftVerifiedCommitSeal::Threshold(_) => {
                verify_threshold_signature(&header, &sealed_extra)
                    .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
            }
        }
        Ok(header)
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
            DbftDecodedPayload::Commit(commit) => {
                self.views
                    .entry(data.view_number)
                    .or_default()
                    .commits
                    .insert(data.validator_index, commit);
                self.refresh_verified_seal(data.view_number)?;
                Ok(self.progress(data.view_number))
            }
            DbftDecodedPayload::RecoveryRequest(_) => Ok(DbftRoundProgress::Accepted),
            DbftDecodedPayload::RecoveryMessage(_) => unreachable!("handled before state mutation"),
        }
    }

    fn refresh_verified_seal(&mut self, view: u8) -> Result<(), DbftStateError> {
        let verified_seal = self.verify_commit_quorum(view)?;
        if let Some(state) = self.views.get_mut(&view) {
            state.verified_seal = verified_seal;
        }
        Ok(())
    }

    fn verify_commit_quorum(
        &self,
        view: u8,
    ) -> Result<Option<DbftVerifiedCommitSeal>, DbftStateError> {
        let Some(state) = self.views.get(&view) else { return Ok(None) };
        let Some(header) = state.final_header.as_ref() else { return Ok(None) };
        if state.commits.len() < self.quorum {
            return Ok(None)
        }
        let extra = DbftExtraPrefix::decode(&header.extra_data)
            .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
        let mut commits = state.commits.iter().collect::<Vec<_>>();
        commits.sort_unstable_by_key(|(validator_index, _)| **validator_index);

        match extra.signature_scheme() {
            SignatureScheme::Ecdsa => {
                let seal_hash = ecdsa_seal_hash(header)
                    .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
                let mut signatures = Vec::with_capacity(self.quorum);
                for (validator_index, commit) in commits {
                    let Ok(DbftCommitSignature::Ecdsa(raw)) = commit.validated_signature() else {
                        continue
                    };
                    let signature = Signature::from_bytes_and_parity(&raw, raw[64] == 1);
                    let Ok(recovered) = signature.recover_address_from_prehash(&seal_hash) else {
                        continue
                    };
                    if self.validators.get(usize::from(*validator_index)) == Some(&recovered) {
                        signatures.push(raw);
                    }
                    if signatures.len() == self.quorum {
                        return Ok(Some(DbftVerifiedCommitSeal::Ecdsa(signatures)))
                    }
                }
                Ok(None)
            }
            SignatureScheme::Threshold => {
                let dkg_state = self.dkg_state.as_ref().ok_or(DbftStateError::MissingDkgState)?;
                let dkg_indices =
                    self.dkg_indices.as_ref().ok_or(DbftStateError::MissingDkgState)?;
                let public_key = dkg_state.current.global_public_key;
                let shares = commits
                    .into_iter()
                    .filter_map(|(validator_index, commit)| {
                        let DbftCommitSignature::Threshold(share) =
                            commit.validated_signature().ok()?
                        else {
                            return None
                        };
                        Some((dkg_indices[usize::from(*validator_index)], share))
                    })
                    .collect::<Vec<(u32, SignatureShare)>>();
                if shares.len() < self.quorum {
                    return Ok(None)
                }
                let message = threshold_seal_message(header)
                    .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?;
                match aggregate_and_verify_signature_shares(
                    &message,
                    &public_key,
                    &shares,
                    self.quorum,
                    NEOX_DKG_SCALER,
                    matches!(extra.version(), ExtraVersion::V1),
                ) {
                    Ok(signature) => {
                        Ok(Some(DbftVerifiedCommitSeal::Threshold(*signature.as_bytes())))
                    }
                    Err(
                        TpkeError::NotEnoughSignatureShares { .. } |
                        TpkeError::SignatureAggregationFailed,
                    ) => Ok(None),
                    Err(error) => Err(DbftStateError::Tpke(error.to_string())),
                }
            }
        }
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
        if state.verified_seal.is_some() {
            return DbftRoundProgress::Committed { view, votes: state.commits.len() }
        }
        if self.anti_mev {
            DbftRoundProgress::PreCommitted { view, votes: state.pre_commits.len() }
        } else {
            DbftRoundProgress::Prepared { view, proposal_hash, votes: prepared_votes }
        }
    }
}

fn proposal_header_matches(
    proposal: &Header,
    final_header: &Header,
) -> Result<bool, DbftStateError> {
    let mut proposal = proposal.clone();
    let mut final_header = final_header.clone();

    // These values are produced by executing the proposal's transaction list. Every other header
    // field is consensus input and must still match the primary's signed template exactly.
    proposal.state_root = final_header.state_root;
    proposal.transactions_root = final_header.transactions_root;
    proposal.receipts_root = final_header.receipts_root;
    proposal.logs_bloom = final_header.logs_bloom;
    proposal.gas_used = final_header.gas_used;
    proposal.extra_data = Bytes::copy_from_slice(
        DbftExtra::hashable_prefix(&proposal.extra_data)
            .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?,
    );
    final_header.extra_data = Bytes::copy_from_slice(
        DbftExtra::hashable_prefix(&final_header.extra_data)
            .map_err(|error| DbftStateError::InvalidFinalHeader(error.to_string()))?,
    );
    Ok(proposal == final_header)
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
    /// No primary proposal exists for the requested view.
    #[error("dBFT view {0} has no accepted proposal")]
    MissingProposal(u8),
    /// The executed header changed a field signed by the primary proposal.
    #[error("final dBFT header does not match the signed proposal template in view {view}")]
    FinalHeaderMismatch {
        /// View containing the proposal.
        view: u8,
    },
    /// Final header extra data is not a valid dBFT seal container.
    #[error("invalid finalized dBFT header: {0}")]
    InvalidFinalHeader(String),
    /// Proposal execution completed but its final header was not installed yet.
    #[error("dBFT view {0} has no finalized proposal header")]
    MissingFinalHeader(u8),
    /// The round has not collected a cryptographically valid commit quorum yet.
    #[error("dBFT view {0} has no verified commit seal")]
    MissingVerifiedCommitSeal(u8),
    /// A verified quorum cannot be installed into a header using another signature scheme.
    #[error("verified dBFT commit seal scheme does not match finalized header")]
    CommitSealSchemeMismatch,
    /// Threshold commit verification requires the active `KeyManagement` round and DKG index map.
    #[error("threshold dBFT commit quorum is missing canonical DKG state")]
    MissingDkgState,
    /// TPKE contribution aggregation failed structurally.
    #[error("invalid dBFT threshold-signature contributions: {0}")]
    Tpke(String),
    /// `PreCommit` is only legal once Anti-MEV is active.
    #[error("dBFT PreCommit received before the Anti-MEV fork")]
    PreCommitBeforeAntiMev,
    /// DKG indexes must be a permutation of `1..=N` in byte-sorted validator order.
    #[error("invalid Neo X dBFT DKG index map: {0:?}")]
    InvalidDkgIndexMap(Vec<u32>),
}

impl From<DbftProtocolViolation> for DbftStateError {
    fn from(error: DbftProtocolViolation) -> Self {
        Self::Protocol(format!("{error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DkgPublicKey;
    use alloy_consensus::Header;
    use alloy_primitives::{b256, Bytes};
    use alloy_rlp::Encodable;
    use reth_neox_antimev::{public_key_from_private_key, sign_share};
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
        let validator_set = read_governance_validator_set_from_storage(|key| {
            Ok(storage.get(&key).map(|value| U256::from_be_slice(value.as_slice())))
        })
        .unwrap();
        assert_eq!(validator_set.original, spec.neox.dbft.standby_validators);
        let mut expected = spec.neox.dbft.standby_validators.clone();
        expected.sort_unstable();
        assert_eq!(validator_set.sorted, expected);
        for (sorted_index, validator) in validator_set.sorted.iter().enumerate() {
            let original_index = validator_set.original.iter().position(|item| item == validator);
            assert_eq!(validator_set.dkg_indices[sorted_index], original_index.unwrap() as u32 + 1);
        }
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

    fn scalar_bytes(value: u64) -> [u8; 32] {
        let mut encoded = [0_u8; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    fn polynomial(index: u64) -> u64 {
        3 + 5 * index + 7 * index.pow(2) + 11 * index.pow(3) + 13 * index.pow(4)
    }

    fn prepare_round(round: &mut DbftRoundState, validators: &[Validator], header: Header) -> B256 {
        let proposal = DbftPrepareRequest {
            sealing_proposal: header,
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
            round.process(response).unwrap();
        }
        proposal_hash
    }

    #[test]
    fn does_not_commit_unverified_contributions() {
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
                assert_eq!(progress, DbftRoundProgress::PreCommitted { view: 0, votes: 5 });
            }
        }
        assert!(round.verified_commit_seal(0).is_none());
    }

    #[test]
    fn verifies_threshold_commit_quorum_against_final_header() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect::<Vec<_>>();
        let global_private_key = scalar_bytes(3 * NEOX_DKG_SCALER);
        let global_public_key = public_key_from_private_key(&global_private_key).unwrap();
        let mut round = DbftRoundState::new(42, accounts, true).unwrap();
        round
            .install_dkg_state(
                (1..=NEOX_VALIDATOR_COUNT as u32).collect(),
                DkgState {
                    current: DkgPublicKey { round: 1, commitment: [0_u8; 128], global_public_key },
                    previous: None,
                },
            )
            .unwrap();
        let extra = DbftExtra::Threshold {
            version: ExtraVersion::V2,
            fallback_next_consensus: B256::repeat_byte(0x42),
            public_key: global_public_key,
            signature: [0_u8; 96],
        }
        .encode();
        let header = Header {
            number: 42,
            extra_data: Bytes::copy_from_slice(DbftExtra::hashable_prefix(&extra).unwrap()),
            ..Default::default()
        };
        prepare_round(&mut round, &validators, header.clone());

        let pre_commit = DbftPreCommit::from_data(Bytes::from(vec![0_u8; 8])).unwrap();
        for (index, validator) in validators.iter().enumerate().take(5) {
            round
                .process(signed_message(
                    validator,
                    42,
                    index as u8,
                    0,
                    DbftMessageType::PreCommit,
                    &pre_commit,
                ))
                .unwrap();
        }
        assert_eq!(
            round.finalize_proposal(0, header.clone()).unwrap(),
            DbftRoundProgress::PreCommitted { view: 0, votes: 5 }
        );

        let seal_message = threshold_seal_message(&header).unwrap();
        for (index, validator) in validators.iter().enumerate().take(5) {
            let private_key = scalar_bytes(polynomial(index as u64 + 1));
            let share = sign_share(&seal_message, &private_key, false).unwrap();
            let commit = DbftCommit { signature: Bytes::copy_from_slice(share.as_bytes()) };
            let progress = round
                .process(signed_message(
                    validator,
                    42,
                    index as u8,
                    0,
                    DbftMessageType::Commit,
                    &commit,
                ))
                .unwrap();
            if index == 4 {
                assert_eq!(progress, DbftRoundProgress::Committed { view: 0, votes: 5 });
            }
        }
        let expected = sign_share(&seal_message, &global_private_key, false).unwrap();
        assert_eq!(
            round.verified_commit_seal(0),
            Some(&DbftVerifiedCommitSeal::Threshold(*expected.as_bytes()))
        );
        let sealed = round.sealed_header(0).unwrap();
        let sealed_extra = DbftExtra::decode(&sealed.extra_data, NEOX_VALIDATOR_COUNT).unwrap();
        assert_eq!(sealed_extra.threshold_signature(), Some(expected.as_bytes()));
        verify_threshold_signature(&sealed, &sealed_extra).unwrap();
    }

    #[test]
    fn verifies_ecdsa_commit_quorum_against_final_header() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect::<Vec<_>>();
        let mut round = DbftRoundState::new(42, accounts, false).unwrap();
        let header = Header {
            number: 42,
            extra_data: Bytes::from_static(&[ExtraVersion::V0 as u8]),
            ..Default::default()
        };
        prepare_round(&mut round, &validators, header.clone());
        assert!(matches!(
            round.finalize_proposal(0, header.clone()).unwrap(),
            DbftRoundProgress::Prepared { votes: 5, .. }
        ));

        let seal_hash = ecdsa_seal_hash(&header).unwrap();
        let mut expected = Vec::new();
        for (index, validator) in validators.iter().enumerate().take(5) {
            let (signature, recovery_id) =
                validator.key.sign_prehash_recoverable(seal_hash.as_slice()).unwrap();
            let mut raw = [0_u8; 65];
            raw[..64].copy_from_slice(&signature.to_bytes());
            raw[64] = recovery_id.to_byte();
            expected.push(raw);
            let commit = DbftCommit { signature: Bytes::copy_from_slice(&raw) };
            let progress = round
                .process(signed_message(
                    validator,
                    42,
                    index as u8,
                    0,
                    DbftMessageType::Commit,
                    &commit,
                ))
                .unwrap();
            if index == 4 {
                assert_eq!(progress, DbftRoundProgress::Committed { view: 0, votes: 5 });
            }
        }
        assert_eq!(
            round.verified_commit_seal(0),
            Some(&DbftVerifiedCommitSeal::Ecdsa(expected.clone()))
        );
        let sealed = round.sealed_header(0).unwrap();
        let sealed_extra = DbftExtra::decode(&sealed.extra_data, NEOX_VALIDATOR_COUNT).unwrap();
        assert_eq!(sealed_extra.signatures(), Some(expected.as_slice()));
        verify_ecdsa_signatures(ecdsa_seal_hash(&sealed).unwrap(), &sealed_extra).unwrap();
    }

    #[test]
    fn rejects_final_header_that_changes_signed_proposal_fields() {
        let validators = validators();
        let accounts = validators.iter().map(|validator| validator.account).collect::<Vec<_>>();
        let mut round = DbftRoundState::new(42, accounts, false).unwrap();
        let header = Header {
            number: 42,
            timestamp: 1_000,
            extra_data: Bytes::from_static(&[ExtraVersion::V0 as u8]),
            ..Default::default()
        };
        prepare_round(&mut round, &validators, header.clone());
        let mut mutated = header;
        mutated.timestamp += 1;
        assert!(matches!(
            round.finalize_proposal(0, mutated),
            Err(DbftStateError::FinalHeaderMismatch { view: 0 })
        ));
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
            DbftRoundProgress::PreCommitted { view: 0, votes: 5 }
        );
        assert_eq!(round.proposal(0).unwrap().hash(), proposal_hash);
    }
}
