//! Idempotent application of canonical DKG storage to the encrypted local keystore.

use crate::{
    read_dkg_aggregated_commitment, read_dkg_recovery_messages, read_dkg_reshare_contribution,
    read_dkg_share_contribution, DkgStorageError, DkgStoredContribution, DkgStoredRecovery,
};
use alloy_primitives::{Bytes, U256};
use reth_neox_antimev::{
    DkgEpochChange, DkgKeyStore, DkgStateError as DkgKeyStoreError, G1_EIP2537_LEN,
};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use reth_provider::StateProvider;
use std::collections::HashSet;
use thiserror::Error;

/// Canonical share and reshare contributions currently accepted for one DKG round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgCanonicalRound {
    /// Implicit `KeyManagement` round.
    pub round: u64,
    /// Accepted fresh-share contributions in sender order.
    pub shares: Vec<DkgStoredContribution>,
    /// Accepted old-key reshare contributions in sender order.
    pub reshares: Vec<DkgStoredContribution>,
}

/// Canonical recovery inputs for one missing pending validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgCanonicalRecovery {
    /// Active recovery round.
    pub round: u64,
    /// One-based missing pending-validator position.
    pub recipient_index: u64,
    /// Prior-round fresh-share PVSS whose evaluations are being recovered.
    pub source_share: DkgStoredContribution,
    /// Accepted recovery messages in current-validator sender order.
    pub messages: Vec<DkgStoredRecovery>,
}

/// Canonical aggregate commitments and this validator's selected PVSS at an epoch boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgCanonicalEpoch {
    /// DKG round being settled or reverted.
    pub round: u64,
    /// This pending member's accepted fresh-share PVSS, absent for a nonmember.
    pub self_pvss: Option<Bytes>,
    /// New round aggregate, absent when the contract rejected the round.
    pub aggregated_commitment: Option<[u8; G1_EIP2537_LEN]>,
    /// Prior round aggregate required for cross-epoch old-key decryption.
    pub previous_commitment: Option<[u8; G1_EIP2537_LEN]>,
}

/// Counts newly decrypted secrets applied during one canonical replay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DkgReplayOutcome {
    /// Fresh-share secrets not already present in the active group.
    pub shares_received: usize,
    /// Reshare secrets not already present in the active group.
    pub reshares_received: usize,
    /// Recovery secrets not already present in the active group.
    pub recoveries_received: usize,
    /// Whether encrypted keystore persistence is required.
    pub store_changed: bool,
}

/// Reads every currently accepted share and reshare contribution from one canonical state.
pub fn read_dkg_canonical_round(
    state: &dyn StateProvider,
    round: u64,
) -> Result<DkgCanonicalRound, DkgReplayError> {
    let mut shares = Vec::with_capacity(NEOX_VALIDATOR_COUNT);
    let mut reshares = Vec::with_capacity(NEOX_VALIDATOR_COUNT);
    for sender_index in 1..=NEOX_VALIDATOR_COUNT as u64 {
        if let Some(contribution) = read_dkg_share_contribution(state, round, sender_index)? {
            shares.push(contribution);
        }
        if let Some(contribution) = read_dkg_reshare_contribution(state, round, sender_index)? {
            reshares.push(contribution);
        }
    }
    Ok(DkgCanonicalRound { round, shares, reshares })
}

/// Reads recovery messages plus the prior-round PVSS needed to verify them.
pub fn read_dkg_canonical_recovery(
    state: &dyn StateProvider,
    round: u64,
    recipient_index: u64,
) -> Result<DkgCanonicalRecovery, DkgReplayError> {
    if round <= 1 {
        return Err(DkgReplayError::RecoveryBeforeSecondRound(round))
    }
    validate_index(recipient_index)?;
    let source_share = read_dkg_share_contribution(state, round - 1, recipient_index)?.ok_or(
        DkgReplayError::MissingRecoverySource { round: round - 1, sender_index: recipient_index },
    )?;
    let messages = read_dkg_recovery_messages(state, round, recipient_index)?;
    Ok(DkgCanonicalRecovery { round, recipient_index, source_share, messages })
}

/// Reads all epoch-boundary data from the same canonical state snapshot.
pub fn read_dkg_canonical_epoch(
    state: &dyn StateProvider,
    round: u64,
    pending_index: Option<u64>,
) -> Result<DkgCanonicalEpoch, DkgReplayError> {
    if round == 0 {
        return Err(DkgReplayError::RoundMismatch { store_round: 0, canonical_round: 0 })
    }
    if let Some(index) = pending_index {
        validate_index(index)?;
    }
    let self_pvss = pending_index
        .map(|index| read_dkg_share_contribution(state, round, index))
        .transpose()?
        .flatten()
        .map(|contribution| contribution.pvss);
    let aggregated_commitment = read_dkg_aggregated_commitment(state, round)?;
    let previous_commitment =
        if round > 1 { read_dkg_aggregated_commitment(state, round - 1)? } else { None };
    Ok(DkgCanonicalEpoch { round, self_pvss, aggregated_commitment, previous_commitment })
}

/// Applies newly accepted share and reshare contributions without resetting active local state.
pub fn apply_dkg_canonical_round(
    store: &mut DkgKeyStore,
    pending_index: Option<u64>,
    canonical: &DkgCanonicalRound,
) -> Result<DkgReplayOutcome, DkgReplayError> {
    validate_store_round(store, canonical.round)?;
    validate_round_contributions(canonical)?;
    let Some(pending_index) = pending_index else { return Ok(DkgReplayOutcome::default()) };
    validate_index(pending_index)?;
    if !store.is_sharing() {
        return Err(DkgReplayError::InactiveGroup("sharing"))
    }
    if !canonical.reshares.is_empty() && !store.is_resharing() {
        return Err(DkgReplayError::InactiveGroup("resharing"))
    }

    let mut outcome = DkgReplayOutcome::default();
    for contribution in &canonical.shares {
        if store.receive_share(
            pending_index,
            contribution.sender_index,
            &contribution.messages,
            &contribution.pvss,
        )? {
            outcome.shares_received += 1;
        }
    }
    for contribution in &canonical.reshares {
        if store.receive_reshare(
            pending_index,
            contribution.sender_index,
            &contribution.messages,
            &contribution.pvss,
        )? {
            outcome.reshares_received += 1;
        }
    }
    outcome.store_changed = outcome.shares_received > 0 || outcome.reshares_received > 0;
    Ok(outcome)
}

/// Reinitializes only the unfinished round and rebuilds it from canonical storage.
///
/// This is the startup and reorg path. A pending validator's deterministic fresh polynomial is
/// regenerated before replay so its eventually selected self PVSS can still confirm the local
/// secret after a crash.
pub fn rebuild_dkg_canonical_round(
    store: &mut DkgKeyStore,
    chain_id: U256,
    pending_index: Option<u64>,
    canonical: &DkgCanonicalRound,
) -> Result<DkgReplayOutcome, DkgReplayError> {
    validate_store_round(store, canonical.round)?;
    if let Some(index) = pending_index {
        validate_index(index)?;
    }
    store.on_share_period_start(false);
    if pending_index.is_some() {
        drop(store.prepare_share(chain_id)?);
    }
    let mut outcome = apply_dkg_canonical_round(store, pending_index, canonical)?;
    outcome.store_changed = true;
    Ok(outcome)
}

/// Applies newly accepted recovery messages to an initialized recovery group.
pub fn apply_dkg_canonical_recovery(
    store: &mut DkgKeyStore,
    canonical: &DkgCanonicalRecovery,
) -> Result<DkgReplayOutcome, DkgReplayError> {
    validate_store_round(store, canonical.round)?;
    validate_recovery(canonical)?;
    if !store.is_recovering() {
        return Err(DkgReplayError::InactiveGroup("recovering"))
    }
    let mut outcome = DkgReplayOutcome::default();
    for recovery in &canonical.messages {
        if store.receive_recovery(
            recovery.sender_index,
            &recovery.message,
            &canonical.source_share.pvss,
        )? {
            outcome.recoveries_received += 1;
        }
    }
    outcome.store_changed = outcome.recoveries_received > 0;
    Ok(outcome)
}

/// Atomically advances or reverts the local keystore using canonical epoch-boundary material.
pub fn apply_dkg_canonical_epoch(
    store: &mut DkgKeyStore,
    is_member_of_new_group: bool,
    canonical: &DkgCanonicalEpoch,
) -> Result<DkgEpochChange, DkgReplayError> {
    validate_store_round(store, canonical.round)?;
    if canonical.aggregated_commitment.is_some() &&
        canonical.self_pvss.is_some() != is_member_of_new_group
    {
        return Err(DkgReplayError::SelfPvssMembershipMismatch)
    }
    let self_pvss = canonical.self_pvss.as_ref().map_or(&[][..], |value| value.as_ref());
    let aggregated_commitment =
        canonical.aggregated_commitment.as_ref().map_or(&[][..], |value| value.as_slice());
    let previous_commitment =
        canonical.previous_commitment.as_ref().map_or(&[][..], |value| value.as_slice());
    Ok(store.on_epoch_change(
        self_pvss,
        aggregated_commitment,
        previous_commitment,
        is_member_of_new_group,
    )?)
}

fn validate_store_round(store: &DkgKeyStore, canonical_round: u64) -> Result<(), DkgReplayError> {
    let expected = store.round().checked_add(1).ok_or(DkgReplayError::RoundOverflow)?;
    if canonical_round != expected {
        return Err(DkgReplayError::RoundMismatch { store_round: store.round(), canonical_round })
    }
    Ok(())
}

fn validate_round_contributions(canonical: &DkgCanonicalRound) -> Result<(), DkgReplayError> {
    validate_contributions(canonical.round, "share", &canonical.shares)?;
    validate_contributions(canonical.round, "reshare", &canonical.reshares)
}

fn validate_contributions(
    round: u64,
    kind: &'static str,
    contributions: &[DkgStoredContribution],
) -> Result<(), DkgReplayError> {
    let mut senders = HashSet::with_capacity(contributions.len());
    for contribution in contributions {
        validate_index(contribution.sender_index)?;
        if contribution.round != round {
            return Err(DkgReplayError::ContributionRoundMismatch {
                kind,
                expected: round,
                actual: contribution.round,
            })
        }
        if !senders.insert(contribution.sender_index) {
            return Err(DkgReplayError::DuplicateSender {
                kind,
                sender_index: contribution.sender_index,
            })
        }
    }
    Ok(())
}

fn validate_recovery(canonical: &DkgCanonicalRecovery) -> Result<(), DkgReplayError> {
    if canonical.round <= 1 {
        return Err(DkgReplayError::RecoveryBeforeSecondRound(canonical.round))
    }
    validate_index(canonical.recipient_index)?;
    if canonical.source_share.round != canonical.round - 1 ||
        canonical.source_share.sender_index != canonical.recipient_index
    {
        return Err(DkgReplayError::RecoverySourceMismatch)
    }
    let mut senders = HashSet::with_capacity(canonical.messages.len());
    for recovery in &canonical.messages {
        validate_index(recovery.sender_index)?;
        if recovery.round != canonical.round ||
            recovery.recipient_index != canonical.recipient_index
        {
            return Err(DkgReplayError::RecoveryMessageMismatch {
                sender_index: recovery.sender_index,
            })
        }
        if !senders.insert(recovery.sender_index) {
            return Err(DkgReplayError::DuplicateSender {
                kind: "recovery",
                sender_index: recovery.sender_index,
            })
        }
    }
    Ok(())
}

fn validate_index(index: u64) -> Result<(), DkgReplayError> {
    if (1..=NEOX_VALIDATOR_COUNT as u64).contains(&index) {
        Ok(())
    } else {
        Err(DkgReplayError::InvalidParticipantIndex(index))
    }
}

/// Invalid canonical replay inputs or a rejected local DKG state transition.
#[derive(Debug, Error)]
pub enum DkgReplayError {
    /// Canonical contract storage was unavailable or malformed.
    #[error(transparent)]
    Storage(#[from] DkgStorageError),
    /// A canonical contribution failed cryptographic verification or state application.
    #[error(transparent)]
    KeyStore(#[from] DkgKeyStoreError),
    /// A local round counter cannot advance further.
    #[error("Neo X DKG replay round overflow")]
    RoundOverflow,
    /// Canonical data must describe exactly the next local DKG round.
    #[error(
        "Neo X DKG canonical round {canonical_round} does not follow local round {store_round}"
    )]
    RoundMismatch {
        /// Last settled local round.
        store_round: u64,
        /// Canonical round being replayed.
        canonical_round: u64,
    },
    /// Recovery is impossible before a prior round exists.
    #[error("Neo X DKG recovery is invalid in round {0}")]
    RecoveryBeforeSecondRound(u64),
    /// Validator positions are one-based and bounded by the deployed committee.
    #[error("invalid Neo X DKG replay participant index {0}")]
    InvalidParticipantIndex(u64),
    /// The caller must initialize the appropriate checkpoint group before incremental replay.
    #[error("Neo X DKG {0} group is not active for canonical replay")]
    InactiveGroup(&'static str),
    /// All contributions in one replay batch must belong to the batch round.
    #[error("Neo X DKG {kind} contribution round mismatch: expected {expected}, got {actual}")]
    ContributionRoundMismatch {
        /// Contribution type.
        kind: &'static str,
        /// Batch round.
        expected: u64,
        /// Contribution round.
        actual: u64,
    },
    /// A sender may contribute at most once per method and round.
    #[error("duplicate Neo X DKG {kind} sender index {sender_index}")]
    DuplicateSender {
        /// Contribution type.
        kind: &'static str,
        /// Repeated one-based sender position.
        sender_index: u64,
    },
    /// Recovery verification must use the missing position's prior-round fresh-share PVSS.
    #[error("Neo X DKG recovery source does not match the prior round and missing index")]
    RecoverySourceMismatch,
    /// Every recovery message must match the bundle round and recipient.
    #[error("Neo X DKG recovery message from sender {sender_index} has mismatched metadata")]
    RecoveryMessageMismatch {
        /// One-based current-validator sender position.
        sender_index: u64,
    },
    /// Canonical storage did not contain the PVSS required to verify recovery messages.
    #[error("missing Neo X DKG recovery source for round {round}, sender {sender_index}")]
    MissingRecoverySource {
        /// Prior round.
        round: u64,
        /// Missing share sender position.
        sender_index: u64,
    },
    /// A successful epoch must include self PVSS exactly when this validator is a new member.
    #[error("Neo X DKG canonical self PVSS does not match pending-set membership")]
    SelfPvssMembershipMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use alloy_primitives::Address;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, Scalar};
    use reth_neox_antimev::{
        DkgMessagePrivateKey, DkgPolynomial, DkgSecretScalar, NEOX_DKG_PARTICIPANTS,
    };
    use sha3::{Digest, Sha3_256};

    fn message_key(value: u8) -> DkgMessagePrivateKey {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        DkgMessagePrivateKey::new(encoded).unwrap()
    }

    fn polynomial(value: u8, round: u64) -> DkgPolynomial {
        let mut source = [0_u8; 32];
        source[31] = value;
        DkgPolynomial::deterministic(&source, U256::from(47_763), round).unwrap()
    }

    fn encrypt_share(
        recipient: &[u8; 65],
        share: &DkgSecretScalar,
        ephemeral_scalar: u64,
    ) -> Bytes {
        let recipient = PublicKey::from_sec1_bytes(recipient).unwrap();
        let ephemeral_scalar = Scalar::from(ephemeral_scalar);
        let ephemeral = ProjectivePoint::GENERATOR * ephemeral_scalar;
        let shared = ProjectivePoint::from(*recipient.as_affine()) * ephemeral_scalar;
        let ephemeral = ephemeral.to_affine().to_encoded_point(false);
        let shared = shared.to_affine().to_encoded_point(false);
        let raw_ephemeral = &ephemeral.as_bytes()[1..];
        let mut hasher = Sha3_256::new();
        hasher.update(shared.x().unwrap());
        hasher.update(raw_ephemeral);
        let cipher = Aes256Gcm::new_from_slice(&hasher.finalize()).unwrap();
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&ephemeral_scalar.to_bytes()[24..]);
        let ciphertext =
            cipher.encrypt(Nonce::from_slice(&nonce), share.as_bytes().as_slice()).unwrap();
        let mut message = Vec::with_capacity(crate::NEOX_DKG_MESSAGE_LEN);
        message.extend_from_slice(raw_ephemeral);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&ciphertext);
        message.into()
    }

    fn contribution(
        store: &DkgKeyStore,
        round: u64,
        sender_index: u64,
        self_index: u64,
    ) -> DkgStoredContribution {
        let material = polynomial(sender_index as u8 + 20, round).generate_pvss().unwrap();
        let message = encrypt_share(
            &store.message_public_key(),
            &material.shares()[self_index as usize - 1],
            sender_index + round * 10,
        );
        DkgStoredContribution {
            round,
            sender_index,
            pvss: material.encoded().to_vec().into(),
            messages: vec![message; NEOX_DKG_PARTICIPANTS],
        }
    }

    #[test]
    fn applies_canonical_round_idempotently_and_detects_conflicts() {
        let mut store = DkgKeyStore::new(message_key(3));
        store.bind_validator_address(Address::repeat_byte(0x11)).unwrap();
        store.on_share_period_start(false);
        let canonical = DkgCanonicalRound {
            round: 1,
            shares: (1..=7).map(|index| contribution(&store, 1, index, 3)).collect(),
            reshares: Vec::new(),
        };
        let first = apply_dkg_canonical_round(&mut store, Some(3), &canonical).unwrap();
        assert_eq!(first.shares_received, 7);
        assert!(first.store_changed);
        assert_eq!(
            apply_dkg_canonical_round(&mut store, Some(3), &canonical).unwrap(),
            DkgReplayOutcome::default()
        );

        let mut conflicting = canonical.clone();
        conflicting.shares[0] = contribution(&store, 1, 7, 3);
        conflicting.shares[0].sender_index = 1;
        assert!(matches!(
            apply_dkg_canonical_round(&mut store, Some(3), &conflicting),
            Err(DkgReplayError::KeyStore(DkgKeyStoreError::ConflictingReceivedShare(1)))
        ));
    }

    #[test]
    fn rebuilds_unfinished_round_and_regenerates_pending_secret() {
        let mut store = DkgKeyStore::new(message_key(4));
        store.bind_validator_address(Address::repeat_byte(0x22)).unwrap();
        let canonical = DkgCanonicalRound { round: 1, shares: Vec::new(), reshares: Vec::new() };
        let outcome =
            rebuild_dkg_canonical_round(&mut store, U256::from(47_763), Some(2), &canonical)
                .unwrap();
        assert!(store.is_sharing());
        assert!(outcome.store_changed);
    }

    #[test]
    fn applies_five_recovery_messages_and_reconstructs_reshare() {
        let mut store = DkgKeyStore::new(message_key(8));
        store.bind_validator_address(Address::repeat_byte(0x33)).unwrap();
        store.on_share_period_start(false);
        let first_round = polynomial(54, 1).generate_pvss().unwrap();
        store.on_epoch_change(&[], &first_round.encoded()[..G1_EIP2537_LEN], &[], false).unwrap();
        let recipient_index = 2;
        let material = polynomial(55, 1).generate_pvss().unwrap();
        let messages = (1..=5)
            .map(|sender_index| DkgStoredRecovery {
                round: 2,
                sender_index,
                recipient_index,
                message: encrypt_share(
                    &store.message_public_key(),
                    &material.shares()[sender_index as usize - 1],
                    sender_index + 80,
                ),
            })
            .collect();
        let canonical = DkgCanonicalRecovery {
            round: 2,
            recipient_index,
            source_share: DkgStoredContribution {
                round: 1,
                sender_index: recipient_index,
                pvss: material.encoded().to_vec().into(),
                messages: Vec::new(),
            },
            messages,
        };
        store.on_share_period_start(false);
        store.on_recover_period_start();
        let outcome = apply_dkg_canonical_recovery(&mut store, &canonical).unwrap();
        assert_eq!(outcome.recoveries_received, 5);
        assert!(outcome.store_changed);
        assert!(store.prepare_recovered_reshare().is_ok());
    }

    #[test]
    fn advances_and_reverts_from_canonical_epoch_material() {
        let mut store = DkgKeyStore::new(message_key(9));
        store.bind_validator_address(Address::repeat_byte(0x44)).unwrap();
        store.on_share_period_start(false);
        let own = store.prepare_share(U256::from(47_763)).unwrap();
        let canonical = DkgCanonicalRound {
            round: 1,
            shares: (1..=7).map(|index| contribution(&store, 1, index, 4)).collect(),
            reshares: Vec::new(),
        };
        apply_dkg_canonical_round(&mut store, Some(4), &canonical).unwrap();
        let mut commitment = [0_u8; G1_EIP2537_LEN];
        commitment.copy_from_slice(&own.encoded()[..G1_EIP2537_LEN]);
        let epoch = DkgCanonicalEpoch {
            round: 1,
            self_pvss: Some(own.encoded().to_vec().into()),
            aggregated_commitment: Some(commitment),
            previous_commitment: None,
        };
        assert_eq!(
            apply_dkg_canonical_epoch(&mut store, true, &epoch).unwrap(),
            DkgEpochChange::Advanced { round: 1 }
        );

        store.on_share_period_start(false);
        let failed = DkgCanonicalEpoch {
            round: 2,
            self_pvss: None,
            aggregated_commitment: None,
            previous_commitment: Some(commitment),
        };
        assert_eq!(
            apply_dkg_canonical_epoch(&mut store, false, &failed).unwrap(),
            DkgEpochChange::Reverted
        );
        assert_eq!(store.round(), 1);
    }
}
