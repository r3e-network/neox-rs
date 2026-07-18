//! Local Neo X validator signing primitives.

use alloy_consensus::{Header, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Bytes, Signature, TxKind};
use alloy_rlp::Encodable;
use k256::ecdsa::SigningKey;
use reth_ethereum_primitives::TransactionSigned;
use reth_neox_antimev::{
    public_key_from_private_key, sign_share, DecryptionShare, TpkeCiphertext, TPKE_PRIVATE_KEY_LEN,
};
use reth_neox_consensus::{
    ecdsa_seal_hash, threshold_seal_message, DbftExtraPrefix, ExtraVersion, SignatureScheme,
};
use reth_neox_network::{
    DbftCommit, DbftConsensusData, DbftMessage, DbftMessageType, DbftPayloadError,
};
use std::{
    fmt,
    sync::{Arc, RwLock},
};
use thiserror::Error;

/// Fee and nonce inputs for one validator-signed `KeyManagement` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgTransactionRequest {
    /// Neo X chain ID protecting the transaction from cross-chain replay.
    pub chain_id: u64,
    /// Validator account nonce selected from canonical state and the local pool.
    pub nonce: u64,
    /// Estimated execution-gas ceiling.
    pub gas_limit: u64,
    /// Maximum total gas price accepted by the validator.
    pub max_fee_per_gas: u128,
    /// Priority fee satisfying the live Neo X Policy contract.
    pub max_priority_fee_per_gas: u128,
    /// ABI-encoded DKG contract call.
    pub calldata: Bytes,
}

struct DkgPrivateShare([u8; TPKE_PRIVATE_KEY_LEN]);

impl Drop for DkgPrivateShare {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Default)]
struct DkgPrivateShares {
    current: Option<DkgPrivateShare>,
    previous: Option<DkgPrivateShare>,
}

/// Local dBFT identity and optional private DKG contribution.
#[derive(Clone)]
pub struct DbftSigner {
    key: Arc<SigningKey>,
    account: Address,
    dkg_private_shares: Arc<RwLock<DkgPrivateShares>>,
}

impl fmt::Debug for DbftSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shares = self.dkg_private_shares.read().unwrap_or_else(|error| error.into_inner());
        formatter
            .debug_struct("DbftSigner")
            .field("account", &self.account)
            .field("has_dkg_private_share", &shares.current.is_some())
            .field("has_previous_dkg_private_share", &shares.previous.is_some())
            .finish()
    }
}

impl DbftSigner {
    /// Creates a validator signer from a canonical secp256k1 private scalar.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, DbftSignerError> {
        let key = SigningKey::from_slice(secret).map_err(|_| DbftSignerError::InvalidEcdsaKey)?;
        let account = Address::from_public_key(key.verifying_key());
        Ok(Self {
            key: Arc::new(key),
            account,
            dkg_private_shares: Arc::new(RwLock::new(DkgPrivateShares::default())),
        })
    }

    /// Installs and validates the private share produced by the active DKG round.
    pub fn with_dkg_private_share(
        self,
        private_share: [u8; TPKE_PRIVATE_KEY_LEN],
    ) -> Result<Self, DbftSignerError> {
        public_key_from_private_key(&private_share)
            .map_err(|_| DbftSignerError::InvalidDkgPrivateShare)?;
        self.dkg_private_shares.write().unwrap_or_else(|error| error.into_inner()).current =
            Some(DkgPrivateShare(private_share));
        Ok(self)
    }

    /// Installs the reshared private contribution used to decrypt preceding-round Envelopes.
    pub fn with_previous_dkg_private_share(
        self,
        private_share: [u8; TPKE_PRIVATE_KEY_LEN],
    ) -> Result<Self, DbftSignerError> {
        public_key_from_private_key(&private_share)
            .map_err(|_| DbftSignerError::InvalidPreviousDkgPrivateShare)?;
        self.dkg_private_shares.write().unwrap_or_else(|error| error.into_inner()).previous =
            Some(DkgPrivateShare(private_share));
        Ok(self)
    }

    /// Atomically replaces the active and preceding DKG shares for a new on-chain round.
    ///
    /// Clones of this signer observe the new shares immediately. Replaced secrets are zeroed when
    /// their lock-protected values are dropped.
    pub fn replace_dkg_private_shares(
        &self,
        current: [u8; TPKE_PRIVATE_KEY_LEN],
        previous: Option<[u8; TPKE_PRIVATE_KEY_LEN]>,
    ) -> Result<(), DbftSignerError> {
        public_key_from_private_key(&current)
            .map_err(|_| DbftSignerError::InvalidDkgPrivateShare)?;
        if let Some(previous) = previous.as_ref() {
            public_key_from_private_key(previous)
                .map_err(|_| DbftSignerError::InvalidPreviousDkgPrivateShare)?;
        }
        *self.dkg_private_shares.write().unwrap_or_else(|error| error.into_inner()) =
            DkgPrivateShares {
                current: Some(DkgPrivateShare(current)),
                previous: previous.map(DkgPrivateShare),
            };
        Ok(())
    }

    /// Validator account recovered by peers from every outer dBFT witness.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Signs a dynamic-fee transaction to the fixed Neo X `KeyManagement` proxy.
    pub fn sign_dkg_transaction(
        &self,
        request: DkgTransactionRequest,
    ) -> Result<TransactionSigned, DbftSignerError> {
        if request.calldata.len() < 4 {
            return Err(DbftSignerError::InvalidDkgCalldata)
        }
        if request.gas_limit == 0 {
            return Err(DbftSignerError::InvalidDkgGasLimit)
        }
        if request.max_fee_per_gas < request.max_priority_fee_per_gas {
            return Err(DbftSignerError::InvalidDkgFeeCap)
        }
        let transaction = TxEip1559 {
            chain_id: request.chain_id,
            nonce: request.nonce,
            gas_limit: request.gas_limit,
            max_fee_per_gas: request.max_fee_per_gas,
            max_priority_fee_per_gas: request.max_priority_fee_per_gas,
            to: TxKind::Call(reth_neox_evm::KEY_MANAGEMENT_PROXY_ADDRESS),
            input: request.calldata,
            ..Default::default()
        };
        let (signature, recovery_id) = self
            .key
            .sign_prehash_recoverable(transaction.signature_hash().as_slice())
            .map_err(|_| DbftSignerError::DkgTransactionSigningFailed)?;
        let signature = Signature::from_signature_and_parity(signature, recovery_id.is_y_odd());
        Ok(TxEnvelope::Eip1559(transaction.into_signed(signature)).into())
    }

    /// Finds this signer in the byte-sorted Governance validator set.
    pub fn validator_index(&self, validators: &[Address]) -> Option<u8> {
        validators.binary_search(&self.account).ok().and_then(|index| u8::try_from(index).ok())
    }

    /// Creates ordered TPKE shares for Envelopes encrypted by the active DKG round.
    pub fn current_decryption_shares(
        &self,
        ciphertexts: &[TpkeCiphertext],
    ) -> Result<Vec<DecryptionShare>, DbftSignerError> {
        let shares = self.dkg_private_shares.read().unwrap_or_else(|error| error.into_inner());
        let private_share =
            shares.current.as_ref().ok_or(DbftSignerError::MissingDkgPrivateShare)?;
        decryption_shares(ciphertexts, private_share)
    }

    /// Creates ordered TPKE shares for Envelopes encrypted by the preceding DKG round.
    pub fn previous_decryption_shares(
        &self,
        ciphertexts: &[TpkeCiphertext],
    ) -> Result<Vec<DecryptionShare>, DbftSignerError> {
        let shares = self.dkg_private_shares.read().unwrap_or_else(|error| error.into_inner());
        let private_share =
            shares.previous.as_ref().ok_or(DbftSignerError::MissingPreviousDkgPrivateShare)?;
        decryption_shares(ciphertexts, private_share)
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
    pub fn commit_for_header(&self, header: &Header) -> Result<DbftCommit, DbftSignerError> {
        let extra = DbftExtraPrefix::decode(&header.extra_data)
            .map_err(|error| DbftSignerError::InvalidHeader(error.to_string()))?;
        let signature = match extra.signature_scheme() {
            SignatureScheme::Ecdsa => {
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
            SignatureScheme::Threshold => {
                let shares =
                    self.dkg_private_shares.read().unwrap_or_else(|error| error.into_inner());
                let private_share =
                    shares.current.as_ref().ok_or(DbftSignerError::MissingDkgPrivateShare)?;
                let message = threshold_seal_message(header)
                    .map_err(|error| DbftSignerError::InvalidHeader(error.to_string()))?;
                let share = sign_share(
                    &message,
                    &private_share.0,
                    matches!(extra.version(), ExtraVersion::V1),
                )
                .map_err(|error| DbftSignerError::ThresholdSigning(error.to_string()))?;
                Bytes::copy_from_slice(share.as_bytes())
            }
        };
        Ok(DbftCommit { signature })
    }
}

fn decryption_shares(
    ciphertexts: &[TpkeCiphertext],
    private_share: &DkgPrivateShare,
) -> Result<Vec<DecryptionShare>, DbftSignerError> {
    ciphertexts
        .iter()
        .map(|ciphertext| {
            ciphertext
                .decryption_share(&private_share.0)
                .map_err(|error| DbftSignerError::DecryptionShare(error.to_string()))
        })
        .collect()
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
    /// The preceding-round reshared scalar was zero or outside the BLS12-381 scalar field.
    #[error("invalid Neo X validator previous DKG private share")]
    InvalidPreviousDkgPrivateShare,
    /// DKG calldata must contain at least a function selector.
    #[error("Neo X DKG transaction calldata is missing its function selector")]
    InvalidDkgCalldata,
    /// Contract calls cannot use a zero gas limit.
    #[error("Neo X DKG transaction gas limit must be non-zero")]
    InvalidDkgGasLimit,
    /// EIP-1559 requires the total fee cap to cover the priority fee.
    #[error("Neo X DKG transaction fee cap is below its priority fee")]
    InvalidDkgFeeCap,
    /// ECDSA signing of a DKG transaction failed unexpectedly.
    #[error("failed to sign Neo X DKG transaction")]
    DkgTransactionSigningFailed,
    /// ECDSA signing failed unexpectedly.
    #[error("failed to sign Neo X dBFT message")]
    SigningFailed,
    /// The finalized header has malformed dBFT extra data.
    #[error("invalid Neo X dBFT header: {0}")]
    InvalidHeader(String),
    /// A threshold header cannot be signed without the active DKG private share.
    #[error("Neo X threshold commit requires a DKG private share")]
    MissingDkgPrivateShare,
    /// A previous-round Envelope cannot be opened without the reshared prior DKG contribution.
    #[error("Neo X previous-round Envelope decryption requires a reshared DKG private share")]
    MissingPreviousDkgPrivateShare,
    /// TPKE decryption-share generation failed for a proposal ciphertext.
    #[error("failed to create Neo X TPKE decryption share: {0}")]
    DecryptionShare(String),
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
    use alloy_consensus::Transaction;
    use alloy_primitives::{hex, Signature, B256};
    use reth_neox_antimev::{public_key_from_private_key, SignatureShare};
    use reth_neox_consensus::{verify_threshold_signature, DbftExtra};
    use reth_neox_network::{DbftCommitSignature, DbftPrepareResponse};
    use reth_primitives_traits::SignerRecoverable;

    fn scalar(value: u8) -> [u8; 32] {
        let mut scalar = [0_u8; 32];
        scalar[31] = value;
        scalar
    }

    fn threshold_header(version: ExtraVersion, private_share: &[u8; 32]) -> Header {
        let extra = DbftExtra::Threshold {
            version,
            fallback_next_consensus: B256::repeat_byte(0x42),
            public_key: public_key_from_private_key(private_share).unwrap(),
            signature: [0_u8; 96],
        }
        .encode();
        Header {
            number: 42,
            extra_data: Bytes::copy_from_slice(DbftExtra::hashable_prefix(&extra).unwrap()),
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
        let header = Header {
            extra_data: Bytes::from_static(&[ExtraVersion::V0 as u8]),
            ..Default::default()
        };
        let commit = signer.commit_for_header(&header).unwrap();
        let DbftCommitSignature::Ecdsa(raw) = commit.validated_signature().unwrap() else {
            panic!("expected ECDSA commit")
        };
        let recovered = Signature::from_bytes_and_parity(&raw, raw[64] == 1)
            .recover_address_from_prehash(&ecdsa_seal_hash(&header).unwrap())
            .unwrap();
        assert_eq!(recovered, signer.account());
    }

    #[test]
    fn signs_key_management_dynamic_fee_transaction() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        let calldata = Bytes::from_static(&[0xa8, 0x6e, 0x37, 0xd3, 0x01]);
        let transaction = signer
            .sign_dkg_transaction(DkgTransactionRequest {
                chain_id: 47763,
                nonce: 9,
                gas_limit: 12_000_000,
                max_fee_per_gas: 40_000_000_000,
                max_priority_fee_per_gas: 20_000_000_000,
                calldata: calldata.clone(),
            })
            .unwrap();
        assert_eq!(transaction.recover_signer().unwrap(), signer.account());
        assert_eq!(transaction.chain_id(), Some(47763));
        assert_eq!(transaction.nonce(), 9);
        assert_eq!(transaction.gas_limit(), 12_000_000);
        assert_eq!(transaction.max_fee_per_gas(), 40_000_000_000);
        assert_eq!(transaction.max_priority_fee_per_gas(), Some(20_000_000_000));
        assert_eq!(transaction.to(), Some(reth_neox_evm::KEY_MANAGEMENT_PROXY_ADDRESS));
        assert_eq!(transaction.input(), &calldata);
    }

    #[test]
    fn rejects_invalid_dkg_transaction_fees_and_shape() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        let request = DkgTransactionRequest {
            chain_id: 47763,
            nonce: 0,
            gas_limit: 1,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 2,
            calldata: Bytes::from_static(&[1, 2, 3, 4]),
        };
        assert_eq!(signer.sign_dkg_transaction(request), Err(DbftSignerError::InvalidDkgFeeCap));
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
            signer.commit_for_header(&v1).unwrap().validated_signature().unwrap()
        else {
            panic!("expected threshold commit")
        };
        let DbftCommitSignature::Threshold(v2_share) =
            signer.commit_for_header(&v2).unwrap().validated_signature().unwrap()
        else {
            panic!("expected threshold commit")
        };
        for (header, share) in [(v1, v1_share), (v2, v2_share)] {
            let extra = DbftExtraPrefix::decode(&header.extra_data).unwrap();
            assert_eq!(extra.signature_scheme(), SignatureScheme::Threshold);
            let signed_extra = DbftExtra::Threshold {
                version: extra.version(),
                fallback_next_consensus: extra.fallback_next_consensus().unwrap(),
                public_key: public_key_from_private_key(&private_share).unwrap(),
                signature: *SignatureShare::decode(share.as_bytes()).unwrap().as_bytes(),
            };
            let mut signed_header = header;
            signed_header.extra_data = signed_extra.encode();
            verify_threshold_signature(&signed_header, &signed_extra).unwrap();
        }
    }

    #[test]
    fn creates_current_and_previous_epoch_decryption_shares() {
        const CURRENT_SECRET: [u8; 32] =
            hex!("4642141848782b7edebdf6c4bbd0c0262efb3ffda85469b5b6af3c5ac471f3cd");
        const CIPHERTEXT: [u8; 192] = hex!(
            "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
             966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
             8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
             8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
             cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
             17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
        );
        const CURRENT_SHARE: [u8; 48] = hex!(
            "8dcd83e7fd7ea998b6b170354e9b87bebd4844d0dfe45d8d45650f84859adb04\
             6c8fe43ac96567e67f944915268b4d31"
        );
        let signer = DbftSigner::from_secret(&scalar(1))
            .unwrap()
            .with_dkg_private_share(CURRENT_SECRET)
            .unwrap()
            .with_previous_dkg_private_share(scalar(2))
            .unwrap();
        let ciphertext = TpkeCiphertext::decode(&CIPHERTEXT).unwrap();

        let current = signer.current_decryption_shares(&[ciphertext]).unwrap();
        let previous = signer.previous_decryption_shares(&[ciphertext]).unwrap();
        assert_eq!(current[0].as_bytes(), &CURRENT_SHARE);
        assert_ne!(previous[0], current[0]);
    }

    #[test]
    fn refuses_decryption_without_the_matching_epoch_key() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        assert_eq!(
            signer.current_decryption_shares(&[]),
            Err(DbftSignerError::MissingDkgPrivateShare)
        );
        assert_eq!(
            signer.previous_decryption_shares(&[]),
            Err(DbftSignerError::MissingPreviousDkgPrivateShare)
        );
    }

    #[test]
    fn cloned_signers_observe_atomic_dkg_share_rotation() {
        let signer = DbftSigner::from_secret(&scalar(1)).unwrap();
        let consensus_clone = signer.clone();
        signer.replace_dkg_private_shares(scalar(2), Some(scalar(3))).unwrap();
        assert_eq!(consensus_clone.current_decryption_shares(&[]), Ok(Vec::new()));
        assert_eq!(consensus_clone.previous_decryption_shares(&[]), Ok(Vec::new()));

        signer.replace_dkg_private_shares(scalar(4), None).unwrap();
        assert_eq!(consensus_clone.current_decryption_shares(&[]), Ok(Vec::new()));
        assert_eq!(
            consensus_clone.previous_decryption_shares(&[]),
            Err(DbftSignerError::MissingPreviousDkgPrivateShare)
        );
    }
}
