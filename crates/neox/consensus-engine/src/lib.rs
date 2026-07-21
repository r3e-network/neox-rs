//! Reth consensus-pipeline integration for Neo X dBFT.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{fmt::Debug, sync::Arc};
use alloy_consensus::{constants::EMPTY_ROOT_HASH, Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::{Bytes, B256, U256};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, ReceiptRootBloom, TransactionRoot,
};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_gas_limit,
    validate_against_parent_hash_number,
};
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_execution_types::BlockExecutionResult;
use reth_neox_chainspec::{NeoXChainSpec, GOVERNANCE_REWARD_ADDRESS, NEOX_VALIDATOR_COUNT};
use reth_neox_consensus::{
    bft_honest_node_count, ecdsa_seal_hash, validate_header as validate_dbft_header,
    validate_proposal_primary, DbftExtra, DbftExtraError, DbftExtraPrefix, DbftValidationError,
    ExtraVersion, SignatureScheme, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN, ECDSA_SIGNATURE_LEN,
    HASHABLE_EXTRA_V0_LEN, HASHABLE_EXTRA_V1_LEN,
};
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader};
use thiserror::Error;

/// Largest valid Neo X dBFT extraData payload (V1/V2 ECDSA fallback form).
pub const MAX_DBFT_EXTRA_DATA_SIZE: usize = HASHABLE_EXTRA_V1_LEN +
    NEOX_VALIDATOR_COUNT * 20 +
    bft_honest_node_count(NEOX_VALIDATOR_COUNT) * ECDSA_SIGNATURE_LEN;

/// Neo X dBFT consensus adapter for the Reth validation pipeline.
#[derive(Debug, Clone)]
pub struct NeoXConsensus {
    chain_spec: Arc<NeoXChainSpec>,
    ethereum: EthBeaconConsensus<NeoXChainSpec>,
}

impl NeoXConsensus {
    /// Creates a dBFT consensus adapter for a canonical or custom Neo X chain.
    pub fn new(chain_spec: Arc<NeoXChainSpec>) -> Self {
        let ethereum = EthBeaconConsensus::new(Arc::clone(&chain_spec))
            .with_max_extra_data_size(MAX_DBFT_EXTRA_DATA_SIZE);
        Self { chain_spec, ethereum }
    }

    /// Returns the active Neo X chain specification.
    pub const fn chain_spec(&self) -> &Arc<NeoXChainSpec> {
        &self.chain_spec
    }

    fn validate_neox_header(&self, header: &Header) -> Result<(), ConsensusError> {
        let extra = DbftExtra::decode(&header.extra_data, NEOX_VALIDATOR_COUNT)
            .map_err(dbft_extra_error)?;
        self.validate_extra_activation(header.number, extra.version(), extra.signature_scheme())?;
        self.validate_neox_header_fields(header, true)
    }

    fn validate_neox_proposal_header(&self, header: &Header) -> Result<(), ConsensusError> {
        let extra = DbftExtraPrefix::decode(&header.extra_data).map_err(dbft_extra_error)?;
        let expected_len = match extra.version() {
            ExtraVersion::V0 => HASHABLE_EXTRA_V0_LEN,
            ExtraVersion::V1 | ExtraVersion::V2 => HASHABLE_EXTRA_V1_LEN,
        };
        if header.extra_data.len() != expected_len {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidProposalExtraLength {
                expected: expected_len,
                actual: header.extra_data.len(),
            }))
        }
        self.validate_extra_activation(header.number, extra.version(), extra.signature_scheme())?;
        self.validate_neox_header_fields(header, false)
    }

    fn validate_extra_activation(
        &self,
        block_number: u64,
        version: ExtraVersion,
        signature_scheme: SignatureScheme,
    ) -> Result<(), ConsensusError> {
        let expected_version = self.chain_spec.extra_version_at_block(block_number);
        if version != expected_version {
            return Err(ConsensusError::other(NeoXConsensusError::UnexpectedExtraVersion {
                expected: expected_version,
                actual: version,
            }))
        }
        if !self.chain_spec.is_anti_mev_active_at_block(block_number) &&
            matches!(signature_scheme, SignatureScheme::Threshold)
        {
            return Err(ConsensusError::other(NeoXConsensusError::ThresholdBeforeAntiMev))
        }
        Ok(())
    }

    fn validate_neox_header_fields(
        &self,
        header: &Header,
        sealed: bool,
    ) -> Result<(), ConsensusError> {
        if sealed &&
            header.extra_data.first() == Some(&(ExtraVersion::V0 as u8)) &&
            header.mix_hash == B256::ZERO
        {
            return Err(ConsensusError::other(NeoXConsensusError::EmptyNextConsensus))
        }
        if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidOmmersHash(
                header.ommers_hash,
            )))
        }
        if header.number > 0 &&
            header.difficulty != U256::from(DIFFICULTY_OUT_OF_TURN) &&
            header.difficulty != U256::from(DIFFICULTY_IN_TURN)
        {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidDifficulty(
                header.difficulty,
            )))
        }
        if header.withdrawals_root != Some(EMPTY_ROOT_HASH) {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidWithdrawalsRoot(
                header.withdrawals_root,
            )))
        }
        if self.chain_spec.is_cancun_active_at_timestamp(header.timestamp) &&
            header.parent_beacon_block_root != Some(EMPTY_ROOT_HASH)
        {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidParentBeaconRoot(
                header.parent_beacon_block_root,
            )))
        }
        if self.chain_spec.is_prague_active_at_timestamp(header.timestamp) &&
            header.requests_hash != Some(EMPTY_REQUESTS_HASH)
        {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidRequestsHash(
                header.requests_hash,
            )))
        }
        Ok(())
    }

    fn validate_neox_header_against_parent_fields(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        let child = header.header();
        let parent_header = parent.header();
        validate_against_parent_hash_number(child, parent)?;
        validate_neox_parent_timestamp(child.timestamp, parent_header.timestamp)?;
        validate_against_parent_gas_limit(header, parent, self.chain_spec.as_ref())?;
        // Neo X base fee is governed by PolicyProxy storage and signed by dBFT. It intentionally
        // does not follow Ethereum's parent-gas EIP-1559 formula.
        if let Some(blob_params) = self.chain_spec.blob_params_at_timestamp(child.timestamp) {
            validate_against_parent_4844(child, parent_header, blob_params)?;
        }
        if child.beneficiary != GOVERNANCE_REWARD_ADDRESS {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidCoinbase {
                expected: GOVERNANCE_REWARD_ADDRESS,
                actual: child.beneficiary,
            }))
        }
        Ok(())
    }

    /// Validates an unsealed primary proposal against the parent selected by the round.
    pub fn validate_proposal_header(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
        expected_primary: u8,
    ) -> Result<(), ConsensusError> {
        validate_present_timestamp(header.timestamp)?;
        self.ethereum.validate_header(header)?;
        self.validate_neox_proposal_header(header.header())?;
        self.validate_neox_header_against_parent_fields(header, parent)?;
        validate_proposal_primary(
            header.header(),
            expected_primary,
            self.chain_spec.neox.dbft.standby_validators.len(),
        )
        .map_err(NeoXConsensusError::Dbft)
        .map_err(ConsensusError::other)
    }

    /// Verifies an alternative ECDSA witness for a canonical parent with the same seal hash.
    ///
    /// Before threshold signatures, honest validators can persist different quorum subsets for
    /// the same finalized header. Their block hashes differ because the full witness is hashed,
    /// while the dBFT seal hash remains identical. A `PrepareRequest` carries the primary's parent
    /// witness so backups can authenticate and adopt that exact parent hash.
    pub fn validate_parent_reseal(
        &self,
        canonical_parent: &SealedHeader<Header>,
        grandparent: &SealedHeader<Header>,
        expected_seal_hash: B256,
        parent_extra: Bytes,
        expected_parent_hash: B256,
    ) -> Result<SealedHeader<Header>, ConsensusError> {
        let canonical_extra = DbftExtra::decode(
            &canonical_parent.extra_data,
            self.chain_spec.neox.dbft.standby_validators.len(),
        )
        .map_err(dbft_extra_error)?;
        if !matches!(canonical_extra.signature_scheme(), SignatureScheme::Ecdsa) {
            return Err(ConsensusError::other(NeoXConsensusError::ThresholdParentReseal))
        }
        let actual_seal_hash =
            ecdsa_seal_hash(canonical_parent.header()).map_err(dbft_extra_error)?;
        if actual_seal_hash != expected_seal_hash {
            return Err(ConsensusError::other(NeoXConsensusError::ParentSealHashMismatch {
                expected: actual_seal_hash,
                actual: expected_seal_hash,
            }))
        }

        let mut resealed_header = canonical_parent.clone_header();
        resealed_header.extra_data = parent_extra;
        let resealed = SealedHeader::seal_slow(resealed_header);
        if resealed.hash() != expected_parent_hash {
            return Err(ConsensusError::other(NeoXConsensusError::ParentResealHashMismatch {
                expected: expected_parent_hash,
                actual: resealed.hash(),
            }))
        }
        self.validate_header(&resealed)?;
        self.validate_header_against_parent(&resealed, grandparent)?;
        Ok(resealed)
    }
}

impl HeaderValidator<Header> for NeoXConsensus {
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        validate_present_timestamp(header.timestamp)?;
        self.ethereum.validate_header(header)?;
        self.validate_neox_header(header.header())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        self.validate_neox_header_against_parent_fields(header, parent)?;
        let child = header.header();
        let parent_header = parent.header();
        validate_dbft_header(
            child,
            parent_header,
            NEOX_VALIDATOR_COUNT,
            self.chain_spec.neox.dbft.standby_validators.len(),
        )
        .map_err(NeoXConsensusError::Dbft)
        .map_err(ConsensusError::other)?;
        Ok(())
    }
}

/// Lifts a dBFT extraData decode/seal error into the pipeline's [`ConsensusError`].
fn dbft_extra_error(error: DbftExtraError) -> ConsensusError {
    ConsensusError::other(NeoXConsensusError::Dbft(DbftValidationError::Extra(error)))
}

#[cfg(feature = "std")]
fn validate_present_timestamp(timestamp: u64) -> Result<(), ConsensusError> {
    validate_timestamp_at(timestamp, std::time::SystemTime::now())
}

#[cfg(not(feature = "std"))]
const fn validate_present_timestamp(_timestamp: u64) -> Result<(), ConsensusError> {
    Ok(())
}

#[cfg(feature = "std")]
fn validate_timestamp_at(timestamp: u64, now: std::time::SystemTime) -> Result<(), ConsensusError> {
    let present_timestamp = now
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| ConsensusError::other(NeoXConsensusError::SystemTimeBeforeUnixEpoch))?
        .as_secs();
    if timestamp > present_timestamp {
        return Err(ConsensusError::TimestampIsInFuture { timestamp, present_timestamp })
    }
    Ok(())
}

impl<B> Consensus<B> for NeoXConsensus
where
    B: Block<Header = Header>,
{
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<NeoXChainSpec> as Consensus<B>>::validate_body_against_header(
            &self.ethereum,
            body,
            header,
        )
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<NeoXChainSpec> as Consensus<B>>::validate_block_pre_execution(
            &self.ethereum,
            block,
        )
    }

    fn validate_block_pre_execution_with_tx_root(
        &self,
        block: &SealedBlock<B>,
        transaction_root: Option<TransactionRoot>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<NeoXChainSpec> as Consensus<B>>::
            validate_block_pre_execution_with_tx_root(
                &self.ethereum,
                block,
                transaction_root,
            )
    }

    fn is_transient_error(&self, error: &ConsensusError) -> bool {
        matches!(error, ConsensusError::TimestampIsInFuture { .. })
    }
}

const fn validate_neox_parent_timestamp(
    timestamp: u64,
    parent_timestamp: u64,
) -> Result<(), ConsensusError> {
    if timestamp < parent_timestamp {
        Err(ConsensusError::TimestampIsInPast { parent_timestamp, timestamp })
    } else {
        Ok(())
    }
}

impl<N> FullConsensus<N> for NeoXConsensus
where
    N: NodePrimitives<BlockHeader = Header>,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
        receipt_root_bloom: Option<ReceiptRootBloom>,
        block_access_list_hash: Option<B256>,
    ) -> Result<(), ConsensusError> {
        <EthBeaconConsensus<NeoXChainSpec> as FullConsensus<N>>::validate_block_post_execution(
            &self.ethereum,
            block,
            result,
            receipt_root_bloom,
            block_access_list_hash,
        )
    }
}

/// Neo X-specific failures surfaced through [`ConsensusError::Other`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NeoXConsensusError {
    /// dBFT extra or seal validation failed.
    #[error(transparent)]
    Dbft(#[from] DbftValidationError),
    /// The host clock cannot represent a valid Unix timestamp.
    #[error("system clock is before the Unix epoch")]
    SystemTimeBeforeUnixEpoch,
    /// The header uses a format version outside its activation window.
    #[error("unexpected dBFT extra version: expected {expected:?}, got {actual:?}")]
    UnexpectedExtraVersion {
        /// Version selected by the chain specification.
        expected: ExtraVersion,
        /// Version encoded in the header.
        actual: ExtraVersion,
    },
    /// Threshold signatures cannot be used before Anti-MEV activation.
    #[error("threshold dBFT signature used before Anti-MEV activation")]
    ThresholdBeforeAntiMev,
    /// A `PrepareRequest` must carry only the hashable extra prefix, without a seal suffix.
    #[error("invalid unsealed dBFT extra length: expected {expected}, got {actual}")]
    InvalidProposalExtraLength {
        /// Hashable prefix length selected by the version.
        expected: usize,
        /// Received unsealed extra length.
        actual: usize,
    },
    /// Threshold-signed parents have one canonical aggregate and cannot be resealed this way.
    #[error("threshold-signed dBFT parent cannot be replaced by an alternate witness")]
    ThresholdParentReseal,
    /// The carried legacy parent seal hash does not identify the local canonical parent content.
    #[error("invalid dBFT parent seal hash: expected {expected}, got {actual}")]
    ParentSealHashMismatch {
        /// Seal hash calculated from the local canonical parent.
        expected: B256,
        /// Seal hash carried by the primary.
        actual: B256,
    },
    /// Replacing only the parent witness did not produce the parent hash selected by the proposal.
    #[error("invalid resealed dBFT parent hash: expected {expected}, got {actual}")]
    ParentResealHashMismatch {
        /// Parent hash referenced by the proposed child.
        expected: B256,
        /// Hash obtained after installing the carried witness.
        actual: B256,
    },
    /// V0 requires a non-zero next-consensus commitment.
    #[error("V0 dBFT next-consensus commitment is empty")]
    EmptyNextConsensus,
    /// Neo X does not allow ommers.
    #[error("invalid Neo X ommers hash {0}")]
    InvalidOmmersHash(B256),
    /// A sealed dBFT block must use difficulty 1 or 2.
    #[error("invalid Neo X dBFT difficulty {0}")]
    InvalidDifficulty(U256),
    /// Shanghai is active from genesis and the withdrawals root must stay empty.
    #[error("invalid Neo X withdrawals root {0:?}")]
    InvalidWithdrawalsRoot(Option<B256>),
    /// Neo X Cancun headers require the empty parent beacon root.
    #[error("invalid Neo X parent beacon root {0:?}")]
    InvalidParentBeaconRoot(Option<B256>),
    /// Neo X Prague headers require the empty execution requests hash.
    #[error("invalid Neo X requests hash {0:?}")]
    InvalidRequestsHash(Option<B256>),
    /// dBFT rewards must be paid to the configured governance contract.
    #[error("invalid Neo X coinbase: expected {expected}, got {actual}")]
    InvalidCoinbase {
        /// Configured governance reward address.
        expected: alloy_primitives::Address,
        /// Header beneficiary.
        actual: alloy_primitives::Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Address, Bytes, B64};
    use k256::ecdsa::SigningKey;
    use reth_neox_consensus::{
        next_consensus_hash, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN, THRESHOLD_PUBLIC_KEY_LEN,
        THRESHOLD_SIGNATURE_LEN,
    };

    fn unsealed_mainnet_block_one(chain_spec: &NeoXChainSpec) -> SealedHeader<Header> {
        let parent = &chain_spec.inner.genesis_header;
        SealedHeader::seal_slow(Header {
            parent_hash: parent.hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: GOVERNANCE_REWARD_ADDRESS,
            state_root: EMPTY_ROOT_HASH,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            difficulty: U256::from(DIFFICULTY_IN_TURN),
            number: 1,
            gas_limit: parent.gas_limit,
            timestamp: parent.timestamp,
            extra_data: Bytes::copy_from_slice(&[ExtraVersion::V0 as u8]),
            mix_hash: parent.mix_hash,
            nonce: B64::from(u64::to_be_bytes(1)),
            base_fee_per_gas: Some(20_000_000_000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        })
    }

    fn test_validator_keys() -> Vec<(Address, SigningKey)> {
        let mut validators = (1_u8..=NEOX_VALIDATOR_COUNT as u8)
            .map(|value| {
                let mut secret = [0_u8; 32];
                secret[31] = value;
                let key = SigningKey::from_slice(&secret).unwrap();
                let public_key = key.verifying_key().to_encoded_point(false);
                let address = Address::from_slice(&keccak256(&public_key.as_bytes()[1..])[12..]);
                (address, key)
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|(address, _)| *address);
        validators
    }

    fn signed_parent_variants() -> (SealedHeader<Header>, SealedHeader<Header>, Bytes, B256, B256) {
        let validators = test_validator_keys();
        let addresses = validators.iter().map(|(address, _)| *address).collect::<Vec<_>>();
        let next_consensus = next_consensus_hash(&addresses);
        let grandparent = SealedHeader::seal_slow(Header {
            extra_data: DbftExtra::genesis_v0(addresses.clone()).encode(),
            mix_hash: next_consensus,
            gas_limit: 30_000_000,
            ..Default::default()
        });
        let mut parent = Header {
            parent_hash: grandparent.hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: GOVERNANCE_REWARD_ADDRESS,
            state_root: EMPTY_ROOT_HASH,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            difficulty: U256::from(DIFFICULTY_IN_TURN),
            number: 1,
            gas_limit: 30_000_000,
            timestamp: 1,
            extra_data: Bytes::copy_from_slice(&[ExtraVersion::V0 as u8]),
            mix_hash: next_consensus,
            nonce: B64::from(u64::to_be_bytes(1)),
            base_fee_per_gas: Some(20_000_000_000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };
        let seal_hash = ecdsa_seal_hash(&parent).unwrap();
        let signatures = validators
            .iter()
            .take(bft_honest_node_count(NEOX_VALIDATOR_COUNT))
            .map(|(_, key)| {
                let (signature, recovery_id) =
                    key.sign_prehash_recoverable(seal_hash.as_slice()).unwrap();
                let mut raw = [0_u8; ECDSA_SIGNATURE_LEN];
                raw[..64].copy_from_slice(&signature.to_bytes());
                raw[64] = recovery_id.to_byte();
                raw
            })
            .collect::<Vec<_>>();
        parent.extra_data = DbftExtra::Ecdsa {
            version: ExtraVersion::V0,
            fallback_next_consensus: None,
            validators: addresses.clone(),
            signatures: signatures.clone(),
        }
        .encode();
        let canonical = SealedHeader::seal_slow(parent);

        let mut alternate_signatures = signatures;
        alternate_signatures.reverse();
        let alternate_extra = DbftExtra::Ecdsa {
            version: ExtraVersion::V0,
            fallback_next_consensus: None,
            validators: addresses,
            signatures: alternate_signatures,
        }
        .encode();
        let mut alternate = canonical.clone_header();
        alternate.extra_data = alternate_extra.clone();
        let alternate_hash = alternate.hash_slow();
        (grandparent, canonical, alternate_extra, seal_hash, alternate_hash)
    }

    #[test]
    fn canonical_mainnet_genesis_is_valid_standalone() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));

        assert!(consensus.validate_header(&chain_spec.inner.genesis_header).is_ok());
    }

    #[test]
    fn validates_unsealed_proposal_primary_and_parent_fields() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let proposal = unsealed_mainnet_block_one(&chain_spec);

        consensus.validate_proposal_header(&proposal, &chain_spec.inner.genesis_header, 1).unwrap();
    }

    #[test]
    fn rejects_seal_suffix_and_round_field_mismatches_in_proposals() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let parent = &chain_spec.inner.genesis_header;

        let mut header = unsealed_mainnet_block_one(&chain_spec).clone_header();
        header.extra_data = Bytes::copy_from_slice(&[ExtraVersion::V0 as u8, 0]);
        let error = consensus
            .validate_proposal_header(&SealedHeader::seal_slow(header), parent, 1)
            .unwrap_err();
        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::InvalidProposalExtraLength {
                expected: HASHABLE_EXTRA_V0_LEN,
                actual: 2,
            })
        ));

        let mut header = unsealed_mainnet_block_one(&chain_spec).clone_header();
        header.nonce = B64::from(u64::to_be_bytes(2));
        let error = consensus
            .validate_proposal_header(&SealedHeader::seal_slow(header), parent, 1)
            .unwrap_err();
        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::Dbft(DbftValidationError::WrongPrimary {
                expected: 1,
                actual: 2,
            }))
        ));

        let mut header = unsealed_mainnet_block_one(&chain_spec).clone_header();
        header.difficulty = U256::from(DIFFICULTY_OUT_OF_TURN);
        let error = consensus
            .validate_proposal_header(&SealedHeader::seal_slow(header), parent, 1)
            .unwrap_err();
        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::Dbft(DbftValidationError::WrongDifficulty { .. }))
        ));
    }

    #[test]
    fn authenticates_an_alternative_parent_quorum_witness() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(chain_spec);
        let (grandparent, canonical, alternate_extra, seal_hash, alternate_hash) =
            signed_parent_variants();
        assert_ne!(canonical.hash(), alternate_hash);

        let resealed = consensus
            .validate_parent_reseal(
                &canonical,
                &grandparent,
                seal_hash,
                alternate_extra.clone(),
                alternate_hash,
            )
            .unwrap();
        assert_eq!(resealed.hash(), alternate_hash);
        assert_eq!(resealed.extra_data, alternate_extra);

        let error = consensus
            .validate_parent_reseal(
                &canonical,
                &grandparent,
                B256::ZERO,
                resealed.extra_data.clone(),
                alternate_hash,
            )
            .unwrap_err();
        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::ParentSealHashMismatch { .. })
        ));
    }

    #[test]
    fn cancun_uses_the_empty_trie_root_for_parent_beacon_root() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let mut header = chain_spec.inner.genesis_header.clone_header();
        header.timestamp = u64::MAX;
        header.parent_beacon_block_root = Some(EMPTY_ROOT_HASH);
        header.requests_hash = Some(EMPTY_REQUESTS_HASH);

        assert!(consensus.validate_neox_header(&header).is_ok());

        header.parent_beacon_block_root = Some(B256::ZERO);
        assert!(matches!(
            consensus
                .validate_neox_header(&header)
                .unwrap_err()
                .downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::InvalidParentBeaconRoot(Some(root))) if *root == B256::ZERO
        ));
    }

    #[test]
    fn rejects_wrong_extra_version_before_activation() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let mut header = chain_spec.inner.genesis_header.clone_header();
        header.extra_data = DbftExtra::Threshold {
            version: ExtraVersion::V2,
            fallback_next_consensus: B256::ZERO,
            public_key: [0; THRESHOLD_PUBLIC_KEY_LEN],
            signature: [0; THRESHOLD_SIGNATURE_LEN],
        }
        .encode();

        let error = consensus.validate_neox_header(&header).unwrap_err();
        assert!(error.is_other::<NeoXConsensusError>());
        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::UnexpectedExtraVersion {
                expected: ExtraVersion::V0,
                actual: ExtraVersion::V2,
            })
        ));
    }

    #[test]
    fn rejects_threshold_scheme_in_transition_block() {
        let chain_spec = NeoXChainSpec::testnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));
        let header = Header {
            number: chain_spec.neox.anti_mev_block - 1,
            extra_data: DbftExtra::Threshold {
                version: ExtraVersion::V1,
                fallback_next_consensus: B256::ZERO,
                public_key: [0; THRESHOLD_PUBLIC_KEY_LEN],
                signature: [0; THRESHOLD_SIGNATURE_LEN],
            }
            .encode(),
            mix_hash: B256::repeat_byte(1),
            difficulty: U256::from(1),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        };

        assert!(matches!(
            consensus
                .validate_neox_header(&header)
                .unwrap_err()
                .downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::ThresholdBeforeAntiMev)
        ));
    }

    #[test]
    fn neo_x_allows_equal_parent_and_child_timestamps() {
        assert!(validate_neox_parent_timestamp(10, 10).is_ok());
        assert!(matches!(
            validate_neox_parent_timestamp(9, 10),
            Err(ConsensusError::TimestampIsInPast { parent_timestamp: 10, timestamp: 9 })
        ));
    }

    #[test]
    fn future_timestamp_errors_are_transient() {
        let consensus = NeoXConsensus::new(NeoXChainSpec::mainnet().unwrap());
        let error = ConsensusError::TimestampIsInFuture { timestamp: 11, present_timestamp: 10 };

        assert!(<NeoXConsensus as Consensus<reth_ethereum_primitives::Block>>::is_transient_error(
            &consensus, &error
        ));
    }

    #[test]
    fn pre_epoch_system_clock_returns_consensus_error() {
        let before_epoch = std::time::SystemTime::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("one second before the epoch is representable");
        let error = validate_timestamp_at(0, before_epoch).unwrap_err();

        assert!(matches!(
            error.downcast_other_ref::<NeoXConsensusError>(),
            Some(NeoXConsensusError::SystemTimeBeforeUnixEpoch)
        ));
    }

    #[test]
    fn timestamp_validation_uses_supplied_present_time() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);

        assert!(validate_timestamp_at(10, now).is_ok());
        assert!(matches!(
            validate_timestamp_at(11, now),
            Err(ConsensusError::TimestampIsInFuture { timestamp: 11, present_timestamp: 10 })
        ));
    }
}
