//! Recoverable Neo X DKG key-group state transitions.

use crate::{
    decrypt_dkg_share_message, global_public_key_from_commitment, DkgMaterialError, DkgPolynomial,
    DkgPvss, DkgPvssMaterial, DkgSecretScalar, G1_COMPRESSED_LEN, NEOX_DKG_PARTICIPANTS,
    NEOX_DKG_SCALER, NEOX_DKG_THRESHOLD,
};
use alloc::vec::Vec;
use alloy_primitives::U256;
use core::fmt;
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rand::{rngs::OsRng, TryRngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Password-protected-at-rest secp256k1 key used only for DKG share-message encryption.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DkgMessagePrivateKey(pub(crate) [u8; 32]);

impl DkgMessagePrivateKey {
    /// Validates a canonical nonzero secp256k1 scalar.
    pub fn new(encoded: [u8; 32]) -> Result<Self, DkgStateError> {
        SecretKey::from_slice(&encoded).map_err(|_| DkgStateError::InvalidMessagePrivateKey)?;
        Ok(Self(encoded))
    }

    /// Generates an independent message-encryption key from operating-system entropy.
    pub fn generate() -> Result<Self, DkgStateError> {
        loop {
            let mut encoded = [0_u8; 32];
            OsRng
                .try_fill_bytes(&mut encoded)
                .map_err(|error| DkgStateError::Entropy(error.to_string()))?;
            if let Ok(key) = Self::new(encoded) {
                return Ok(key)
            }
        }
    }

    /// Returns the secret scalar for deterministic sharing and encrypted persistence.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the exact uncompressed SEC1 public key registered in `KeyManagement`.
    pub fn public_key(&self) -> [u8; 65] {
        let key = SecretKey::from_slice(&self.0).expect("validated DKG message private key");
        key.public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed secp256k1 public key has fixed length")
    }
}

impl fmt::Debug for DkgMessagePrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DkgMessagePrivateKey([REDACTED])")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct DkgKeyGroup {
    pub(crate) local_secret: Option<DkgPolynomial>,
    pub(crate) pending_secrets: Vec<DkgPolynomial>,
    pub(crate) received_secrets: [Option<DkgSecretScalar>; NEOX_DKG_PARTICIPANTS],
    pub(crate) global_public_key: Option<[u8; G1_COMPRESSED_LEN]>,
    pub(crate) local_private_key: Option<DkgSecretScalar>,
}

impl DkgKeyGroup {
    fn new() -> Self {
        Self {
            local_secret: None,
            pending_secrets: Vec::new(),
            received_secrets: core::array::from_fn(|_| None),
            global_public_key: None,
            local_private_key: None,
        }
    }

    fn reshare_template(previous: &Self) -> Self {
        Self {
            local_secret: None,
            pending_secrets: Vec::new(),
            received_secrets: core::array::from_fn(|_| None),
            global_public_key: previous.global_public_key,
            local_private_key: None,
        }
    }

    fn store_received(
        &mut self,
        from_index: u64,
        share: DkgSecretScalar,
    ) -> Result<(), DkgStateError> {
        validate_index(from_index)?;
        let slot = &mut self.received_secrets[from_index as usize - 1];
        if let Some(existing) = slot {
            if existing == &share {
                return Ok(())
            }
            return Err(DkgStateError::ConflictingReceivedShare(from_index))
        }
        *slot = Some(share);
        Ok(())
    }

    fn confirm_local_secret(&mut self, pvss: &DkgPvss) -> Result<(), DkgStateError> {
        let commitment = pvss.commitment();
        let secret = self
            .pending_secrets
            .iter()
            .find(|secret| secret.commitment() == commitment)
            .cloned()
            .ok_or(DkgStateError::PendingSecretNotConfirmed)?;
        self.local_secret = Some(secret);
        Ok(())
    }

    fn settle(
        &mut self,
        aggregated_commitment: &[u8],
        is_receiver: bool,
    ) -> Result<(), DkgStateError> {
        let global_public_key =
            global_public_key_from_commitment(aggregated_commitment, NEOX_DKG_SCALER)
                .map_err(|error| DkgStateError::InvalidAggregatedCommitment(error.to_string()))?;
        let local_private_key = if is_receiver {
            let mut shares = Vec::with_capacity(NEOX_DKG_PARTICIPANTS);
            for (position, share) in self.received_secrets.iter().enumerate() {
                shares.push(
                    share
                        .as_ref()
                        .ok_or(DkgStateError::MissingReceivedShare((position + 1) as u64))?,
                );
            }
            Some(DkgSecretScalar::aggregate(&shares)?)
        } else {
            None
        };
        self.global_public_key = Some(global_public_key);
        self.local_private_key = local_private_key;
        Ok(())
    }
}

impl fmt::Debug for DkgKeyGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DkgKeyGroup")
            .field("has_local_secret", &self.local_secret.is_some())
            .field("pending_secret_count", &self.pending_secrets.len())
            .field(
                "received_secret_count",
                &self.received_secrets.iter().filter(|secret| secret.is_some()).count(),
            )
            .field("has_global_public_key", &self.global_public_key.is_some())
            .field("has_local_private_key", &self.local_private_key.is_some())
            .finish()
    }
}

/// In-memory Neo X DKG state for current, previous, sharing, resharing, and recovery groups.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DkgKeyStore {
    pub(crate) round: u64,
    pub(crate) message_private_key: DkgMessagePrivateKey,
    pub(crate) recovering: Option<DkgKeyGroup>,
    pub(crate) resharing: Option<DkgKeyGroup>,
    pub(crate) reshared: Option<DkgKeyGroup>,
    pub(crate) sharing: Option<DkgKeyGroup>,
    pub(crate) shared: Option<DkgKeyGroup>,
}

impl DkgKeyStore {
    /// Creates an empty round-zero state around an independent message-encryption key.
    pub const fn new(message_private_key: DkgMessagePrivateKey) -> Self {
        Self {
            round: 0,
            message_private_key,
            recovering: None,
            resharing: None,
            reshared: None,
            sharing: None,
            shared: None,
        }
    }

    /// Returns the last successfully settled on-chain DKG round.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the exact public message key registered for this validator.
    pub fn message_public_key(&self) -> [u8; 65] {
        self.message_private_key.public_key()
    }

    /// Returns whether a fresh sharing group is active.
    pub const fn is_sharing(&self) -> bool {
        self.sharing.is_some()
    }

    /// Returns whether an old-key resharing group is active.
    pub const fn is_resharing(&self) -> bool {
        self.resharing.is_some()
    }

    /// Returns whether missing-validator recovery is active.
    pub const fn is_recovering(&self) -> bool {
        self.recovering.is_some()
    }

    /// Returns the current epoch's local TPKE share, if this node is a member.
    pub fn current_private_share(&self) -> Option<&DkgSecretScalar> {
        self.shared.as_ref()?.local_private_key.as_ref()
    }

    /// Returns the prior epoch's local TPKE share for old-envelope decryption.
    pub fn previous_private_share(&self) -> Option<&DkgSecretScalar> {
        self.reshared.as_ref()?.local_private_key.as_ref()
    }

    /// Returns the scaled current global key read from the contract commitment.
    pub fn current_global_public_key(&self) -> Option<&[u8; G1_COMPRESSED_LEN]> {
        self.shared.as_ref()?.global_public_key.as_ref()
    }

    /// Initializes the share and optional reshare groups at a Governance share checkpoint.
    pub fn on_share_period_start(&mut self, force_reshare: bool) {
        self.resharing = self.shared.as_ref().map(DkgKeyGroup::reshare_template);
        if self.resharing.is_none() && force_reshare {
            self.resharing = Some(DkgKeyGroup::new());
        }
        self.sharing = Some(DkgKeyGroup::new());
        self.recovering = None;
    }

    /// Initializes recovery collection at the Governance recovery checkpoint.
    pub fn on_recover_period_start(&mut self) {
        self.recovering = Some(DkgKeyGroup::new());
    }

    /// Clears only the unfinished round after the contract reports no aggregate commitment.
    pub fn revert_round(&mut self) {
        self.resharing = None;
        self.sharing = None;
        self.recovering = None;
    }

    /// Prepares deterministic fresh sharing material and records its pending polynomial.
    pub fn prepare_share(&mut self, chain_id: U256) -> Result<DkgPvssMaterial, DkgStateError> {
        let next_round = self.round.checked_add(1).ok_or(DkgStateError::RoundOverflow)?;
        let polynomial = DkgPolynomial::deterministic(
            self.message_private_key.as_bytes(),
            chain_id,
            next_round,
        )?;
        let material = polynomial.generate_pvss()?;
        let sharing = self.sharing.as_mut().ok_or(DkgStateError::GroupUnavailable("sharing"))?;
        if !sharing.pending_secrets.contains(&polynomial) {
            sharing.pending_secrets.push(polynomial);
        }
        Ok(material)
    }

    /// Renovates the settled local secret for transfer to the pending validator set.
    pub fn prepare_reshare(&self) -> Result<DkgPvssMaterial, DkgStateError> {
        if self.resharing.is_none() {
            return Err(DkgStateError::GroupUnavailable("resharing"))
        }
        let local_secret = self
            .shared
            .as_ref()
            .and_then(|group| group.local_secret.as_ref())
            .ok_or(DkgStateError::SettledLocalSecretUnavailable)?;
        Ok(local_secret.renovate()?.generate_pvss()?)
    }

    /// Returns prior-round shares addressed to one or two missing pending validators.
    pub fn prepare_recovery(
        &self,
        recovery_indices: &[u64],
    ) -> Result<Vec<DkgSecretScalar>, DkgStateError> {
        validate_recovery_indices(recovery_indices)?;
        let shared = self.shared.as_ref().ok_or(DkgStateError::GroupUnavailable("shared"))?;
        recovery_indices
            .iter()
            .map(|index| {
                shared.received_secrets[*index as usize - 1]
                    .clone()
                    .ok_or(DkgStateError::MissingRecoverySource(*index))
            })
            .collect()
    }

    /// Reconstructs a missing validator's constant from five recovery messages and renovates it.
    pub fn prepare_recovered_reshare(&mut self) -> Result<DkgPvssMaterial, DkgStateError> {
        let recovering =
            self.recovering.as_mut().ok_or(DkgStateError::GroupUnavailable("recovering"))?;
        let shares = recovering
            .received_secrets
            .iter()
            .enumerate()
            .filter_map(|(position, share)| {
                share.clone().map(|share| ((position + 1) as u64, share))
            })
            .collect::<Vec<_>>();
        if shares.len() < NEOX_DKG_THRESHOLD {
            return Err(DkgStateError::InsufficientRecoveryShares { actual: shares.len() })
        }
        let polynomial = DkgPolynomial::recover_and_renovate(&shares)?;
        let material = polynomial.generate_pvss()?;
        recovering.local_secret = Some(polynomial);
        Ok(material)
    }

    /// Decrypts and records one sender's fresh sharing message for this validator.
    pub fn receive_share<B: AsRef<[u8]>>(
        &mut self,
        self_index: u64,
        from_index: u64,
        messages: &[B],
        pvss: &[u8],
    ) -> Result<(), DkgStateError> {
        if self.sharing.is_none() {
            return Err(DkgStateError::GroupUnavailable("sharing"))
        }
        let share = self.decrypt_received_share(self_index, messages, pvss)?;
        self.sharing
            .as_mut()
            .expect("sharing group checked above")
            .store_received(from_index, share)
    }

    /// Decrypts and records one current validator's reshare for this pending validator.
    pub fn receive_reshare<B: AsRef<[u8]>>(
        &mut self,
        self_index: u64,
        from_index: u64,
        messages: &[B],
        pvss: &[u8],
    ) -> Result<(), DkgStateError> {
        if self.resharing.is_none() {
            return Err(DkgStateError::GroupUnavailable("resharing"))
        }
        let share = self.decrypt_received_share(self_index, messages, pvss)?;
        self.resharing
            .as_mut()
            .expect("resharing group checked above")
            .store_received(from_index, share)
    }

    /// Decrypts a recovery message and verifies it at the sending current-validator index.
    pub fn receive_recovery(
        &mut self,
        from_index: u64,
        message: &[u8],
        pvss: &[u8],
    ) -> Result<(), DkgStateError> {
        if self.recovering.is_none() {
            return Err(DkgStateError::GroupUnavailable("recovering"))
        }
        validate_index(from_index)?;
        let pvss = DkgPvss::decode(pvss)?;
        let share = decrypt_dkg_share_message(self.message_private_key.as_bytes(), message)?;
        pvss.verify_share(from_index, &share)?;
        self.recovering
            .as_mut()
            .expect("recovering group checked above")
            .store_received(from_index, share)
    }

    /// Atomically settles a successful DKG epoch or reverts an on-chain failed round.
    pub fn on_epoch_change(
        &mut self,
        self_pvss: &[u8],
        aggregated_commitment: &[u8],
        previous_commitment: &[u8],
        is_member_of_new_group: bool,
    ) -> Result<DkgEpochChange, DkgStateError> {
        if aggregated_commitment.is_empty() {
            self.revert_round();
            return Ok(DkgEpochChange::Reverted)
        }
        if self_pvss.is_empty() == is_member_of_new_group {
            return Err(DkgStateError::SelfPvssMembershipMismatch)
        }

        let mut next_shared =
            self.sharing.as_ref().ok_or(DkgStateError::GroupUnavailable("sharing"))?.clone();
        if is_member_of_new_group {
            let self_pvss = DkgPvss::decode(self_pvss)?;
            next_shared.confirm_local_secret(&self_pvss)?;
        }
        next_shared.settle(aggregated_commitment, is_member_of_new_group)?;

        let next_reshared = if let Some(resharing) = &self.resharing {
            if previous_commitment.is_empty() {
                return Err(DkgStateError::MissingPreviousCommitment)
            }
            let mut reshared = resharing.clone();
            reshared.settle(previous_commitment, is_member_of_new_group)?;
            Some(reshared)
        } else {
            None
        };
        let next_round = self.round.checked_add(1).ok_or(DkgStateError::RoundOverflow)?;

        self.reshared = next_reshared;
        self.resharing = None;
        self.shared = Some(next_shared);
        self.sharing = None;
        self.recovering = None;
        self.round = next_round;
        Ok(DkgEpochChange::Advanced { round: next_round })
    }

    fn decrypt_received_share<B: AsRef<[u8]>>(
        &self,
        self_index: u64,
        messages: &[B],
        pvss: &[u8],
    ) -> Result<DkgSecretScalar, DkgStateError> {
        validate_index(self_index)?;
        if messages.len() != NEOX_DKG_PARTICIPANTS {
            return Err(DkgStateError::InvalidMessageCount { actual: messages.len() })
        }
        let pvss = DkgPvss::decode(pvss)?;
        let share = decrypt_dkg_share_message(
            self.message_private_key.as_bytes(),
            messages[self_index as usize - 1].as_ref(),
        )?;
        pvss.verify_share(self_index, &share)?;
        Ok(share)
    }
}

impl fmt::Debug for DkgKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DkgKeyStore")
            .field("round", &self.round)
            .field("message_private_key", &"[REDACTED]")
            .field("recovering", &self.recovering)
            .field("resharing", &self.resharing)
            .field("reshared", &self.reshared)
            .field("sharing", &self.sharing)
            .field("shared", &self.shared)
            .finish()
    }
}

/// Result of applying an on-chain epoch-change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgEpochChange {
    /// The contract omitted an aggregate commitment, so unfinished state was discarded.
    Reverted,
    /// The new round was fully settled.
    Advanced {
        /// Newly settled DKG round.
        round: u64,
    },
}

fn validate_index(index: u64) -> Result<(), DkgStateError> {
    if (1..=NEOX_DKG_PARTICIPANTS as u64).contains(&index) {
        Ok(())
    } else {
        Err(DkgStateError::InvalidParticipantIndex(index))
    }
}

fn validate_recovery_indices(indices: &[u64]) -> Result<(), DkgStateError> {
    if !(1..=NEOX_DKG_PARTICIPANTS - NEOX_DKG_THRESHOLD).contains(&indices.len()) {
        return Err(DkgStateError::InvalidRecoveryCount(indices.len()))
    }
    for (position, index) in indices.iter().enumerate() {
        validate_index(*index)?;
        if indices[..position].contains(index) {
            return Err(DkgStateError::DuplicateRecoveryIndex(*index))
        }
    }
    Ok(())
}

/// Invalid DKG state transition or contract/event material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgStateError {
    /// The message key must be a canonical nonzero secp256k1 scalar.
    #[error("invalid Neo X DKG message private key")]
    InvalidMessagePrivateKey,
    /// Operating-system entropy failed.
    #[error("failed to obtain Neo X DKG entropy: {0}")]
    Entropy(String),
    /// Cryptographic DKG material was invalid.
    #[error(transparent)]
    Material(#[from] DkgMaterialError),
    /// The requested phase or settled group is absent.
    #[error("Neo X DKG {0} key group is unavailable")]
    GroupUnavailable(&'static str),
    /// Validator positions are one-based within the fixed committee.
    #[error("invalid Neo X DKG participant index {0}")]
    InvalidParticipantIndex(u64),
    /// Sharing and resharing calls carry exactly seven encrypted messages.
    #[error(
        "invalid Neo X DKG encrypted message count {actual}, expected {NEOX_DKG_PARTICIPANTS}"
    )]
    InvalidMessageCount {
        /// Observed message count.
        actual: usize,
    },
    /// Replaying an identical event is safe, but a sender cannot replace its accepted share.
    #[error("conflicting Neo X DKG share from participant {0}")]
    ConflictingReceivedShare(u64),
    /// Resharing requires a locally generated secret confirmed in the prior round.
    #[error("settled Neo X DKG local secret is unavailable")]
    SettledLocalSecretUnavailable,
    /// Recovery supports the deployed one- or two-missing-validator cases.
    #[error("invalid Neo X DKG recovery index count {0}, expected one or two")]
    InvalidRecoveryCount(usize),
    /// A missing validator may be requested only once.
    #[error("duplicate Neo X DKG recovery index {0}")]
    DuplicateRecoveryIndex(u64),
    /// The current node never received the prior share needed for this missing validator.
    #[error("missing prior Neo X DKG share for recovery index {0}")]
    MissingRecoverySource(u64),
    /// Five recovery messages are required to reconstruct a polynomial constant.
    #[error(
        "insufficient Neo X DKG recovery shares: got {actual}, expected at least {NEOX_DKG_THRESHOLD}"
    )]
    InsufficientRecoveryShares {
        /// Number of accepted recovery shares.
        actual: usize,
    },
    /// A participant's contract-selected PVSS did not match any locally pending polynomial.
    #[error("contract-selected Neo X DKG PVSS does not match a pending local secret")]
    PendingSecretNotConfirmed,
    /// Epoch membership and the presence of a self PVSS must agree.
    #[error("Neo X DKG self PVSS does not match pending-set membership")]
    SelfPvssMembershipMismatch,
    /// Every sender's share is needed before deriving a member's local threshold key.
    #[error("missing Neo X DKG received share from participant {0}")]
    MissingReceivedShare(u64),
    /// A reshare group requires the contract's previous-round aggregate commitment.
    #[error("Neo X DKG previous-round aggregate commitment is missing")]
    MissingPreviousCommitment,
    /// The contract commitment failed EIP-2537 or subgroup validation.
    #[error("invalid Neo X DKG aggregate commitment: {0}")]
    InvalidAggregatedCommitment(String),
    /// A persisted round counter cannot wrap.
    #[error("Neo X DKG round overflow")]
    RoundOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, Scalar};
    use sha3::{Digest, Sha3_256};

    fn message_key(value: u8) -> DkgMessagePrivateKey {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        DkgMessagePrivateKey::new(encoded).unwrap()
    }

    fn polynomial(value: u8) -> DkgPolynomial {
        let mut source = [0_u8; 32];
        source[31] = value;
        DkgPolynomial::deterministic(&source, U256::from(47_763), 1).unwrap()
    }

    fn encrypt_share(
        recipient: &[u8; 65],
        share: &DkgSecretScalar,
        ephemeral_scalar: u64,
    ) -> Vec<u8> {
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
        let key = hasher.finalize();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&ephemeral_scalar.to_bytes()[24..]);
        let ciphertext =
            cipher.encrypt(Nonce::from_slice(&nonce), share.as_bytes().as_slice()).unwrap();
        let mut message = Vec::with_capacity(crate::NEOX_DKG_ECIES_MESSAGE_LEN);
        message.extend_from_slice(raw_ephemeral);
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&ciphertext);
        message
    }

    fn receive_sender(
        store: &mut DkgKeyStore,
        self_index: u64,
        from_index: u64,
        polynomial: &DkgPolynomial,
    ) -> DkgSecretScalar {
        let material = polynomial.generate_pvss().unwrap();
        let share = material.shares()[self_index as usize - 1].clone();
        let message = encrypt_share(&store.message_public_key(), &share, from_index + 1);
        let messages = vec![message; NEOX_DKG_PARTICIPANTS];
        store.receive_share(self_index, from_index, &messages, material.encoded()).unwrap();
        share
    }

    fn receive_reshare_sender(
        store: &mut DkgKeyStore,
        self_index: u64,
        from_index: u64,
        polynomial: &DkgPolynomial,
    ) -> DkgSecretScalar {
        let material = polynomial.generate_pvss().unwrap();
        let share = material.shares()[self_index as usize - 1].clone();
        let message = encrypt_share(&store.message_public_key(), &share, from_index + 30);
        let messages = vec![message; NEOX_DKG_PARTICIPANTS];
        store.receive_reshare(self_index, from_index, &messages, material.encoded()).unwrap();
        share
    }

    #[test]
    fn settles_first_round_and_prepares_recovery_and_reshare() {
        let mut store = DkgKeyStore::new(message_key(3));
        store.on_share_period_start(false);
        let own_material = store.prepare_share(U256::from(47_763)).unwrap();
        let mut received = Vec::new();
        for from_index in 1..=NEOX_DKG_PARTICIPANTS as u64 {
            received.push(receive_sender(
                &mut store,
                2,
                from_index,
                &polynomial(from_index as u8 + 10),
            ));
        }
        let expected = DkgSecretScalar::aggregate(&received.iter().collect::<Vec<_>>()).unwrap();
        let outcome = store
            .on_epoch_change(
                own_material.encoded(),
                &own_material.encoded()[..crate::NEOX_DKG_G1_LEN],
                &[],
                true,
            )
            .unwrap();
        assert_eq!(outcome, DkgEpochChange::Advanced { round: 1 });
        assert_eq!(store.round(), 1);
        assert_eq!(store.current_private_share(), Some(&expected));
        assert!(store.current_global_public_key().is_some());
        assert!(!store.is_sharing());

        let recovery = store.prepare_recovery(&[1, 2]).unwrap();
        assert_eq!(recovery, received[..2]);
        store.on_share_period_start(false);
        assert!(store.is_resharing());
        let reshared = store.prepare_reshare().unwrap();
        let original = DkgPvss::decode(own_material.encoded()).unwrap();
        let reshared = DkgPvss::decode(reshared.encoded()).unwrap();
        assert!(reshared.renovates(&original));
        assert!(!format!("{store:?}")
            .contains(&alloy_primitives::hex::encode(store.message_private_key.as_bytes())));

        let second_own_material = store.prepare_share(U256::from(47_763)).unwrap();
        let mut second_received = Vec::new();
        let mut previous_received = Vec::new();
        for from_index in 1..=NEOX_DKG_PARTICIPANTS as u64 {
            second_received.push(receive_sender(
                &mut store,
                4,
                from_index,
                &polynomial(from_index as u8 + 70),
            ));
            previous_received.push(receive_reshare_sender(
                &mut store,
                4,
                from_index,
                &polynomial(from_index as u8 + 90),
            ));
        }
        let expected_current =
            DkgSecretScalar::aggregate(&second_received.iter().collect::<Vec<_>>()).unwrap();
        let expected_previous =
            DkgSecretScalar::aggregate(&previous_received.iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(
            store
                .on_epoch_change(
                    second_own_material.encoded(),
                    &second_own_material.encoded()[..crate::NEOX_DKG_G1_LEN],
                    &own_material.encoded()[..crate::NEOX_DKG_G1_LEN],
                    true,
                )
                .unwrap(),
            DkgEpochChange::Advanced { round: 2 }
        );
        assert_eq!(store.current_private_share(), Some(&expected_current));
        assert_eq!(store.previous_private_share(), Some(&expected_previous));
    }

    #[test]
    fn reconstructs_and_renovates_after_five_recovery_messages() {
        let mut store = DkgKeyStore::new(message_key(5));
        store.on_recover_period_start();
        let missing = polynomial(41);
        let missing_material = missing.generate_pvss().unwrap();
        for from_index in 1..=NEOX_DKG_THRESHOLD as u64 {
            let share = &missing_material.shares()[from_index as usize - 1];
            let message = encrypt_share(&store.message_public_key(), share, from_index + 20);
            store.receive_recovery(from_index, &message, missing_material.encoded()).unwrap();
            if from_index < NEOX_DKG_THRESHOLD as u64 {
                assert_eq!(
                    store.prepare_recovered_reshare().unwrap_err(),
                    DkgStateError::InsufficientRecoveryShares { actual: from_index as usize }
                );
            }
        }
        let recovered = store.prepare_recovered_reshare().unwrap();
        let recovered = DkgPvss::decode(recovered.encoded()).unwrap();
        let missing = DkgPvss::decode(missing_material.encoded()).unwrap();
        assert!(recovered.renovates(&missing));
    }

    #[test]
    fn epoch_change_is_atomic_until_every_share_is_present() {
        let mut store = DkgKeyStore::new(message_key(7));
        store.on_share_period_start(false);
        let own_material = store.prepare_share(U256::from(47_763)).unwrap();
        for from_index in 1..NEOX_DKG_PARTICIPANTS as u64 {
            receive_sender(&mut store, 1, from_index, &polynomial(from_index as u8 + 50));
        }
        assert_eq!(
            store.on_epoch_change(
                own_material.encoded(),
                &own_material.encoded()[..crate::NEOX_DKG_G1_LEN],
                &[],
                true,
            ),
            Err(DkgStateError::MissingReceivedShare(7))
        );
        assert_eq!(store.round(), 0);
        assert!(store.is_sharing());

        assert_eq!(store.on_epoch_change(&[], &[], &[], false), Ok(DkgEpochChange::Reverted));
        assert!(!store.is_sharing());
    }

    #[test]
    fn rejects_conflicting_replay_and_invalid_recovery_sets() {
        let mut store = DkgKeyStore::new(message_key(9));
        store.on_share_period_start(false);
        let first = polynomial(61);
        let accepted = receive_sender(&mut store, 3, 1, &first);
        let first_material = first.generate_pvss().unwrap();
        let message = encrypt_share(&store.message_public_key(), &accepted, 2);
        let messages = vec![message; NEOX_DKG_PARTICIPANTS];
        store.receive_share(3, 1, &messages, first_material.encoded()).unwrap();

        let conflicting = polynomial(62);
        let conflicting_material = conflicting.generate_pvss().unwrap();
        let conflicting_share = conflicting_material.shares()[2].clone();
        let message = encrypt_share(&store.message_public_key(), &conflicting_share, 3);
        let messages = vec![message; NEOX_DKG_PARTICIPANTS];
        assert_eq!(
            store.receive_share(3, 1, &messages, conflicting_material.encoded()),
            Err(DkgStateError::ConflictingReceivedShare(1))
        );
        assert_eq!(store.prepare_recovery(&[1, 1]), Err(DkgStateError::DuplicateRecoveryIndex(1)));
        assert_eq!(store.prepare_recovery(&[]), Err(DkgStateError::InvalidRecoveryCount(0)));
    }
}
