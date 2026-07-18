use crate::{
    NeoXGenesisConfig, NeoXHardfork, NEOX_MAINNET_BOOTNODES, NEOX_MAINNET_CHAIN_ID,
    NEOX_MAINNET_GENESIS_JSON, NEOX_TESTNET_BOOTNODES, NEOX_TESTNET_CHAIN_ID,
    NEOX_TESTNET_GENESIS_JSON, NEOX_VALIDATOR_COUNT,
};
use alloc::{sync::Arc, vec::Vec};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{B256, U256};
use core::fmt;
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork,
    EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_neox_consensus::{next_consensus_hash, DbftExtra, ExtraVersion};
use reth_network_peers::NodeRecord;
use reth_primitives_traits::SealedHeader;
use thiserror::Error;

/// Neo X chain specification backed by Reth's Ethereum [`ChainSpec`].
#[derive(Debug, Clone)]
pub struct NeoXChainSpec {
    /// Ethereum-compatible chain specification.
    pub inner: ChainSpec,
    /// Neo X-specific genesis configuration.
    pub neox: NeoXGenesisConfig,
    /// Network-specific discovery entry points.
    bootnodes: Vec<NodeRecord>,
}

impl NeoXChainSpec {
    /// Returns the dBFT extra-data version required at a block height.
    ///
    /// Neo X switches the format one block before the activation height so that the parent can
    /// commit the identifiers used by the first block under the new signing scheme.
    pub fn extra_version_at_block(&self, block_number: u64) -> ExtraVersion {
        let next_block = block_number.saturating_add(1);
        if self.is_fork_active_at_block(NeoXHardfork::EthSignature, block_number) ||
            self.is_fork_active_at_block(NeoXHardfork::EthSignature, next_block)
        {
            ExtraVersion::V2
        } else if self.is_fork_active_at_block(NeoXHardfork::AntiMev, block_number) ||
            self.is_fork_active_at_block(NeoXHardfork::AntiMev, next_block)
        {
            ExtraVersion::V1
        } else {
            ExtraVersion::V0
        }
    }

    /// Returns whether Anti-MEV threshold signatures are allowed at a block height.
    pub fn is_anti_mev_active_at_block(&self, block_number: u64) -> bool {
        self.is_fork_active_at_block(NeoXHardfork::AntiMev, block_number)
    }

    /// Parses a canonical Neo X genesis and installs Neo X-specific hardforks.
    pub fn from_genesis(genesis: Genesis) -> Result<Self, NeoXChainSpecError> {
        let neox = genesis
            .config
            .extra_fields
            .deserialize_as::<NeoXGenesisConfig>()
            .map_err(NeoXChainSpecError::InvalidExtension)?;

        if neox.dbft.standby_validators.len() != NEOX_VALIDATOR_COUNT {
            return Err(NeoXChainSpecError::InvalidValidatorCount {
                expected: NEOX_VALIDATOR_COUNT,
                actual: neox.dbft.standby_validators.len(),
            })
        }

        let mut inner = ChainSpec::from_genesis(genesis);
        let genesis_extra = DbftExtra::genesis_v0(neox.dbft.standby_validators.clone());
        let mut genesis_header = inner.genesis_header.clone_header();
        genesis_header.extra_data = genesis_extra.encode();
        genesis_header.mix_hash = next_consensus_hash(
            genesis_extra.validators().expect("genesis V0 always contains validators"),
        );
        inner.genesis_header = SealedHeader::new_unhashed(genesis_header);
        inner.hardforks.extend([
            (NeoXHardfork::Dkg, ForkCondition::Block(neox.dkg_block)),
            (NeoXHardfork::AntiMev, ForkCondition::Block(neox.anti_mev_block)),
            (NeoXHardfork::EthSignature, ForkCondition::Block(neox.eth_signature_block)),
        ]);

        let bootnodes = match inner.chain.id() {
            NEOX_MAINNET_CHAIN_ID => parse_bootnodes(&NEOX_MAINNET_BOOTNODES),
            NEOX_TESTNET_CHAIN_ID => parse_bootnodes(&NEOX_TESTNET_BOOTNODES),
            _ => Vec::new(),
        };

        Ok(Self { inner, neox, bootnodes })
    }

    /// Loads the canonical Neo X `MainNet` chain specification.
    pub fn mainnet() -> Result<Arc<Self>, NeoXChainSpecError> {
        Self::from_json(NEOX_MAINNET_GENESIS_JSON).map(Arc::new)
    }

    /// Loads the canonical Neo X T4 `TestNet` chain specification.
    pub fn testnet() -> Result<Arc<Self>, NeoXChainSpecError> {
        Self::from_json(NEOX_TESTNET_GENESIS_JSON).map(Arc::new)
    }

    /// Loads a Neo X chain specification from genesis JSON.
    pub fn from_json(json: &str) -> Result<Self, NeoXChainSpecError> {
        let genesis = serde_json::from_str(json).map_err(NeoXChainSpecError::InvalidGenesis)?;
        Self::from_genesis(genesis)
    }
}

/// Errors produced while constructing a Neo X chain specification.
#[derive(Debug, Error)]
pub enum NeoXChainSpecError {
    /// The genesis JSON itself is malformed.
    #[error("invalid Neo X genesis JSON: {0}")]
    InvalidGenesis(serde_json::Error),
    /// Neo X extension fields are missing or malformed.
    #[error("invalid Neo X genesis extension: {0}")]
    InvalidExtension(serde_json::Error),
    /// Neo X currently requires exactly seven standby validators.
    #[error("invalid dBFT standby validator count: expected {expected}, got {actual}")]
    InvalidValidatorCount {
        /// Required validator count.
        expected: usize,
        /// Validator count present in genesis.
        actual: usize,
    },
}

impl Hardforks for NeoXChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(&self) -> impl Iterator<Item = (&dyn Hardfork, ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &Head) -> ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(&self, head: Head) -> ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthereumHardforks for NeoXChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl EthExecutorSpec for NeoXChainSpec {
    fn deposit_contract_address(&self) -> Option<alloy_primitives::Address> {
        self.inner.deposit_contract_address()
    }
}

impl EthChainSpec for NeoXChainSpec {
    type Header = alloy_consensus::Header;

    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(&self, timestamp: u64) -> BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> alloc::boxed::Box<dyn fmt::Display> {
        alloc::boxed::Box::new(self.inner.display_hardforks())
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner.genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    fn bootnodes(&self) -> Option<alloc::vec::Vec<NodeRecord>> {
        (!self.bootnodes.is_empty()).then(|| self.bootnodes.clone())
    }

    fn final_paris_total_difficulty(&self) -> Option<U256> {
        self.inner.final_paris_total_difficulty()
    }
}

fn parse_bootnodes(nodes: &[&str]) -> Vec<NodeRecord> {
    nodes
        .iter()
        .map(|node| node.parse().expect("built-in Neo X bootnode must be a valid enode record"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GOVERNANCE_REWARD_ADDRESS, NEOX_BLOCK_PERIOD_SECS, NEOX_MAINNET_CHAIN_ID,
        NEOX_MAINNET_GENESIS_HASH, NEOX_TESTNET_CHAIN_ID, NEOX_TESTNET_GENESIS_HASH,
    };
    use alloy_primitives::b256;
    use reth_chainspec::Hardforks;

    const VALIDATORS: &str = r#"[
        "0x34a3b2abb99b4c128acf61dcbbd1fcac0b161652",
        "0x641ec1c538fa17e6ad8193c9b580f6850b114280",
        "0xe3973f57e8a0aa312c1917ab0e6a05d8b6af6609",
        "0xa61ac4a4f006f4fceeb72ee0012a2d3367168d10",
        "0xe6d1a9db6a0893926bd81c0ef93aaaa543c116f0",
        "0x4fe8af0dbb633283d8e9703668142fd130f2818d",
        "0x763452f65353fffe73d46539e51a6ddfc0e2c86a"
    ]"#;

    fn minimal_mainnet_genesis() -> Genesis {
        let raw = format!(
            r#"{{
                "config": {{
                    "chainId": {NEOX_MAINNET_CHAIN_ID},
                    "homesteadBlock": 0,
                    "eip150Block": 0,
                    "eip155Block": 0,
                    "eip158Block": 0,
                    "byzantiumBlock": 0,
                    "constantinopleBlock": 0,
                    "petersburgBlock": 0,
                    "istanbulBlock": 0,
                    "berlinBlock": 0,
                    "londonBlock": 0,
                    "shanghaiTime": 0,
                    "neoXDKGBlock": 3623040,
                    "neoXAMEVBlock": 3749760,
                    "neoXEthSigBlock": 3749760,
                    "dbft": {{
                        "period": {NEOX_BLOCK_PERIOD_SECS},
                        "standbyValidators": {VALIDATORS},
                        "coinbase": "{GOVERNANCE_REWARD_ADDRESS}"
                    }}
                }},
                "gasLimit": "30000000",
                "difficulty": "1",
                "alloc": {{}}
            }}"#
        );
        serde_json::from_str(&raw).expect("valid test genesis")
    }

    #[test]
    fn parses_mainnet_extensions_and_forks() {
        let spec =
            NeoXChainSpec::from_genesis(minimal_mainnet_genesis()).expect("valid Neo X spec");

        assert_eq!(spec.chain().id(), NEOX_MAINNET_CHAIN_ID);
        assert_eq!(spec.neox.dbft.period, NEOX_BLOCK_PERIOD_SECS);
        assert_eq!(spec.neox.dbft.coinbase, GOVERNANCE_REWARD_ADDRESS);
        assert!(spec.neox.has_expected_validator_count());
        assert_eq!(spec.fork(NeoXHardfork::Dkg), ForkCondition::Block(3_623_040));
        assert_eq!(spec.fork(NeoXHardfork::AntiMev), ForkCondition::Block(3_749_760));
        assert_eq!(spec.fork(NeoXHardfork::EthSignature), ForkCondition::Block(3_749_760));
    }

    #[test]
    fn rejects_wrong_validator_count() {
        let mut genesis = minimal_mainnet_genesis();
        let extension = genesis.config.extra_fields.get_mut("dbft").expect("dbft extension");
        extension["standbyValidators"] = serde_json::json!([]);

        assert!(matches!(
            NeoXChainSpec::from_genesis(genesis),
            Err(NeoXChainSpecError::InvalidValidatorCount { expected: 7, actual: 0 })
        ));
    }

    #[test]
    fn canonical_mainnet_genesis_hash_matches() {
        let spec = NeoXChainSpec::mainnet().expect("canonical MainNet spec");

        assert_eq!(spec.chain().id(), NEOX_MAINNET_CHAIN_ID);
        assert_eq!(spec.genesis_hash(), NEOX_MAINNET_GENESIS_HASH);
        assert_eq!(
            spec.genesis_header().mix_hash,
            b256!("eb59c093e3a02bfa4e0d4677d4769022cd9399bbc8b93ad1e892acd6a08aa533")
        );
        assert_eq!(spec.genesis_header().extra_data.len(), 466);
    }

    #[test]
    fn canonical_testnet_genesis_hash_matches() {
        let spec = NeoXChainSpec::testnet().expect("canonical TestNet spec");

        assert_eq!(spec.chain().id(), NEOX_TESTNET_CHAIN_ID);
        assert_eq!(spec.genesis_hash(), NEOX_TESTNET_GENESIS_HASH);
        assert_eq!(spec.neox.dkg_block, 1_990_080);
        assert_eq!(spec.neox.anti_mev_block, 2_088_000);
        assert_eq!(spec.neox.eth_signature_block, 3_750_000);
    }

    #[test]
    fn canonical_networks_have_official_discovery_bootnodes() {
        let mainnet = NeoXChainSpec::mainnet().unwrap();
        let testnet = NeoXChainSpec::testnet().unwrap();

        assert_eq!(mainnet.bootnodes().unwrap().len(), NEOX_MAINNET_BOOTNODES.len());
        assert_eq!(testnet.bootnodes().unwrap().len(), NEOX_TESTNET_BOOTNODES.len());
        assert!(mainnet.bootnodes().unwrap().iter().all(|node| node.tcp_addr().port() == 30_303));
        assert!(testnet.bootnodes().unwrap().iter().all(|node| node.tcp_addr().port() == 30_304));
    }

    #[test]
    fn extra_version_changes_one_block_before_signature_forks() {
        let spec = NeoXChainSpec::mainnet().unwrap();

        assert_eq!(spec.extra_version_at_block(spec.neox.anti_mev_block - 2), ExtraVersion::V0);
        assert_eq!(spec.extra_version_at_block(spec.neox.anti_mev_block - 1), ExtraVersion::V2);
        assert_eq!(spec.extra_version_at_block(spec.neox.anti_mev_block), ExtraVersion::V2);

        let testnet = NeoXChainSpec::testnet().unwrap();
        assert_eq!(
            testnet.extra_version_at_block(testnet.neox.anti_mev_block - 1),
            ExtraVersion::V1
        );
        assert_eq!(
            testnet.extra_version_at_block(testnet.neox.eth_signature_block - 1),
            ExtraVersion::V2
        );
    }
}
