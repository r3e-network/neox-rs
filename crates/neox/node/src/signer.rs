//! Local Neo X validator signing primitives.

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes};
use alloy_rlp::Encodable;
use k256::ecdsa::SigningKey;
use reth_neox_antimev::{public_key_from_private_key, sign_share, TPKE_PRIVATE_KEY_LEN};
use reth_neox_consensus::{ecdsa_seal_hash, threshold_seal_message, DbftExtra, ExtraVersion};
use reth_neox_network::{
    DbftCommit, DbftConsensusData, DbftMessage, DbftMessageType, DbftPayloadError,
};
use std::{fmt, sync::Arc};
use thiserror::Error;

#[derive(Clone)]
struct DkgPrivateShare([u8; TPKE_PRIVATE_KEY_LEN]);

impl Drop for DkgPrivateShare {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Local dBFT identity and optional private DKG contribution.
#[derive(Clone)]
pub struct DbftSigner {
    key: Arc<SigningKey>,
    account: Address,
    dkg_private_share: Option<DkgPrivateShare>,
}

impl fmt::Debug for DbftSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DbftSigner")
            .field("account", &self.account)
            .field("has_dkg_private_share", &self.dkg_private_share.is_some())
            .finish()
    }
}

impl DbftSigner {
    /// Creates a validator signer from a canonical secp256k1 private scalar.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, DbftSignerError> {
        let key = SigningKey::from_slice(secret).map_err(|_| DbftSignerError::InvalidEcdsaKey)?;
        let account = Address::from_public_key(key.verifying_key());
        Ok(Self { key: Arc::new(key), account, dkg_private_share: None })
    }

    /// Installs and validates the private share produced by the active DKG round.
    pub fn with_dkg_private_share(
        mut self,
        private_share: [u8; TPKE_PRIVATE_KEY_LEN],
    ) -> Result<Self, DbftSignerError> {
        public_key_from_private_key(&private_share)
            .map_err(|_| DbftSignerError::InvalidDkgPrivateShare)?;
        self.dkg_private_share = Some(DkgPrivateShare(private_share));
        Ok(self)
    }

    /// Validator account recovered by peers from every outer dBFT witness.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Finds this signer in the byte-sorted Governance validator set.
    pub fn validator_index(&self, validators: &[Address]) -> Option<u8> {
        validators.binary_search(&self.account).ok().and_then(|index| u8::try_from(index).ok())
    }

    /// Encodes and signs one type-specific consensus payload for the given block and view.
    pub fn sign_message<T: Encodable>(
        &self,
        block_index: u64,
        validator_index: u8,
        view_number: u8,
        message_type: DbftMessageType,
        payload: &T,
    ) -> Result<DbftMessage, DbftSignerError> {
        let data = DbftConsensusData {
            message_type,
            block_index,
            validator_index,
            view_number,
            payload: alloy_rlp::encode(payload).into(),
        };
        let mut encoded_data = Vec::new();
        data.encode(&mut encoded_data);
        let mut message = DbftMessage {
            valid_block_start: 0,
            valid_block_end: block_index,
            sender: self.account,
            data: encoded_data.into(),
            witness: Bytes::new(),
        };
        let (signature, recovery_id) = self
            .key
            .sign_prehash_recoverable(message.hash().as_slice())
            .map_err(|_| DbftSignerError::SigningFailed)?;
        let mut witness = [0_u8; 65];
        witness[..64].copy_from_slice(&signature.to_bytes());
        witness[64] = recovery_id.to_byte();
        message.witness = witness.to_vec().into();
        Ok(message)
    }

    /// Signs a finalized header using the ECDSA or threshold scheme selected by its extra data.
    pub fn commit_for_header(
        &self,
        header: &Header,
        validator_count: usize,
    ) -> Result<DbftCommit, DbftSignerError> {
        let extra = DbftExtra::decode(&header.extra_data, validator_count)
            .map_err(|error| DbftSignerError::InvalidHeader(error.to_string()))?;
        let signature = match extra {
            DbftExtra::Ecdsa { .. } => {
                let seal_hash = ecdsa_seal_hash(header)
                    .map_err(|error| DbftSignerError::InvalidHeader(error.to_string()))?;
                let (signature, recovery_id) = self
                    .key
                    .sign_prehash_recoverable(seal_hash.as_slice())
                    .map_err(|_| DbftSignerError::SigningFailed)?;
                let mut raw = [0_u8; 65];
                raw[..64].copy_from_slice(&signature.to_bytes());
                raw[64] = recovery_id.to_byte();
                Bytes::copy_from_slice(&raw)
            }
            DbftExtra::Threshold { version, .. } => {
                let private_share = self
                    .dkg_private_share
                    .as_ref()
                    .ok_or(DbftSignerError::MissingDkgPrivateShare)?;
                let message = threshold_seal_message(header)
                    .map_err(|error| DbftSignerError::InvalidHeader(error.to_string()))?;
                let share =
                    sign_share(&message, &private_share.0, matches!(version, ExtraVersion::V1))
                        .map_err(|error| DbftSignerError::ThresholdSigning(error.to_string()))?;
                Bytes::copy_from_slice(share.as_bytes())
            }
        };
        Ok(DbftCommit { signature })
    }
}

/// Local validator key or signature failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DbftSignerError {
    /// The secp256k1 scalar was zero or outside the curve order.
    #[error("invalid Neo X validator secp256k1 private key")]
    InvalidEcdsaKey,
    /// The DKG scalar was zero or outside the BLS12-381 scalar field.
    #[error("invalid Neo X validator DKG private share")]
    InvalidDkgPrivateShare,
    /// ECDSA signing failed unexpectedly.
    #[error("failed to sign Neo X dBFT message")]
    SigningFailed,
    /// The finalized header has malformed dBFT extra data.
    #[error("invalid Neo X dBFT header: {0}")]
    InvalidHeader(String),
    /// A threshold header cannot be signed without the active DKG private share.
    #[error("Neo X threshold commit requires a DKG private share")]
    MissingDkgPrivateShare,
    /// BLS threshold-share generation failed.
    #[error("failed to sign Neo X threshold commit: {0}")]
    ThresholdSigning(String),
    /// Generated payload did not satisfy the type-specific dBFT codec.
    #[error(transparent)]
    Payload(#[from] DbftPayloadError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Signature, B256};
    use reth_neox_antimev::{public_key_from_private_key, SignatureShare};
    use reth_neox_consensus::{verify_threshold_signature, SignatureScheme};
    use reth_neox_network::{DbftCommitSignature, DbftPrepareResponse};

    fn scalar(value: u8) -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar[31] = value;
        scalar
    }

    fn threshold_header(version: ExtraVersion, private_share: &[u8; 32]) -> Header {
        Header {
            number: 42,
            extra_data: DbftExtra::Threshold {
                version,
                fallback_next_consensus: B256::repeat_byte(0x42),
                public_key: public_key_from_private_key(private_share).unwrap(),
                signature: [0_u8; 96],
            }
            .encode(),
            ..Default::default()
        }
    }

    #[test]
    fn signs_authenticated_dbft_payloads() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        let payload = DbftPrepareResponse { preparation_hash: B256::repeat_byte(0x11) };
        let message =
            signer.sign_message(42, 3, 2, DbftMessageType::PrepareResponse, &payload).unwrap();
        assert_eq!(message.sender, signer.account());
        message.verify_witness().unwrap();
        let data = message.consensus_data().unwrap();
        assert_eq!(data.block_index, 42);
        assert_eq!(data.validator_index, 3);
        assert_eq!(data.view_number, 2);
        assert!(matches!(
            data.decoded_payload().unwrap(),
            reth_neox_network::DbftDecodedPayload::PrepareResponse(_)
        ));
    }

    #[test]
    fn signs_ecdsa_header_commit() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        let validators = vec![signer.account(); 7];
        let header = Header {
            extra_data: DbftExtra::Ecdsa {
                version: ExtraVersion::V0,
                fallback_next_consensus: None,
                validators,
                signatures: vec![[0_u8; 65]; 5],
            }
            .encode(),
            ..Default::default()
        };
        let commit = signer.commit_for_header(&header, 7).unwrap();
        let DbftCommitSignature::Ecdsa(raw) = commit.validated_signature().unwrap() else {
            panic!("expected ECDSA commit")
        };
        let recovered = Signature::from_bytes_and_parity(&raw, raw[64] == 1)
            .recover_address_from_prehash(&ecdsa_seal_hash(&header).unwrap())
            .unwrap();
        assert_eq!(recovered, signer.account());
    }

    #[test]
    fn selects_v1_and_v2_threshold_sign_conventions() {
        let private_share = scalar(2);
        let signer = DbftSigner::from_secret(&scalar(1))
            .unwrap()
            .with_dkg_private_share(private_share)
            .unwrap();
        let v1 = threshold_header(ExtraVersion::V1, &private_share);
        let v2 = threshold_header(ExtraVersion::V2, &private_share);
        let DbftCommitSignature::Threshold(v1_share) =
            signer.commit_for_header(&v1, 7).unwrap().validated_signature().unwrap()
        else {
            panic!("expected threshold commit")
        };
        let DbftCommitSignature::Threshold(v2_share) =
            signer.commit_for_header(&v2, 7).unwrap().validated_signature().unwrap()
        else {
            panic!("expected threshold commit")
        };
        for (header, share) in [(v1, v1_share), (v2, v2_share)] {
            let extra = DbftExtra::decode(&header.extra_data, 7).unwrap();
            assert_eq!(extra.signature_scheme(), SignatureScheme::Threshold);
            let signed_extra = DbftExtra::Threshold {
                version: extra.version(),
                fallback_next_consensus: extra.fallback_next_consensus().unwrap(),
                public_key: *extra.threshold_public_key().unwrap(),
                signature: *SignatureShare::decode(share.as_bytes()).unwrap().as_bytes(),
            };
            let mut signed_header = header;
            signed_header.extra_data = signed_extra.encode();
            verify_threshold_signature(&signed_header, &signed_extra).unwrap();
        }
    }
}
