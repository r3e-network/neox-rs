//! Reth consensus-pipeline integration for Neo X dBFT.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{fmt::Debug, sync::Arc};
use alloy_consensus::{constants::EMPTY_ROOT_HASH, Header, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::{B256, U256};
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
    bft_honest_node_count, validate_header as validate_dbft_header, DbftExtra, DbftValidationError,
    ExtraVersion, SignatureScheme, ECDSA_SIGNATURE_LEN, HASHABLE_EXTRA_V1_LEN,
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
            .map_err(DbftValidationError::Extra)
            .map_err(NeoXConsensusError::Dbft)
            .map_err(ConsensusError::other)?;
        let expected_version = self.chain_spec.extra_version_at_block(header.number);
        if extra.version() != expected_version {
            return Err(ConsensusError::other(NeoXConsensusError::UnexpectedExtraVersion {
                expected: expected_version,
                actual: extra.version(),
            }))
        }
        if !self.chain_spec.is_anti_mev_active_at_block(header.number) &&
            matches!(extra.signature_scheme(), SignatureScheme::Threshold)
        {
            return Err(ConsensusError::other(NeoXConsensusError::ThresholdBeforeAntiMev))
        }
        if matches!(extra.version(), ExtraVersion::V0) && header.mix_hash == B256::ZERO {
            return Err(ConsensusError::other(NeoXConsensusError::EmptyNextConsensus))
        }
        if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::other(NeoXConsensusError::InvalidOmmersHash(
                header.ommers_hash,
            )))
        }
        if header.number > 0 &&
            header.difficulty != U256::from(1) &&
            header.difficulty != U256::from(2)
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
            header.parent_beacon_block_root != Some(B256::ZERO)
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
}

impl HeaderValidator<Header> for NeoXConsensus {
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        #[cfg(feature = "std")]
        {
            let present_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_secs();
            if header.timestamp > present_timestamp {
                return Err(ConsensusError::TimestampIsInFuture {
                    timestamp: header.timestamp,
                    present_timestamp,
                })
            }
        }
        self.ethereum.validate_header(header)?;
        self.validate_neox_header(header.header())
    }

    fn validate_header_against_parent(
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
    use reth_neox_consensus::{THRESHOLD_PUBLIC_KEY_LEN, THRESHOLD_SIGNATURE_LEN};

    #[test]
    fn canonical_mainnet_genesis_is_valid_standalone() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let consensus = NeoXConsensus::new(Arc::clone(&chain_spec));

        assert!(consensus.validate_header(&chain_spec.inner.genesis_header).is_ok());
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
}
