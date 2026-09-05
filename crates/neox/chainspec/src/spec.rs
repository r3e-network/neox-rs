use crate::{
    NeoXGenesisConfig, NeoXHardfork, NEOX_MAINNET_BOOTNODES, NEOX_MAINNET_CHAIN_ID,
    NEOX_MAINNET_GENESIS_JSON, NEOX_MAX_VALIDATOR_COUNT, NEOX_TESTNET_BOOTNODES,
    NEOX_TESTNET_CHAIN_ID, NEOX_TESTNET_GENESIS_JSON,
};
use alloc::{sync::Arc, vec::Vec};
use alloy_eips::eip7840::BlobParams;
use alloy_evm::eth::spec::EthExecutorSpec;
use alloy_genesis::Genesis;
use alloy_primitives::{keccak256, Address, B256, U256};
use core::fmt;
use reth_chainspec::{
    BaseFeeParams, Chain, ChainSpec, DepositContract, EthChainSpec, EthereumHardfork,
    EthereumHardforks, ForkCondition, ForkFilter, ForkId, Hardfork, Hardforks, Head,
};
use reth_neox_consensus::{
    next_consensus_hash, validate_threshold_points, validate_threshold_public_key, DbftExtra,
    DbftExtraError, DbftValidationError, ExtraVersion,
};
use reth_network_peers::NodeRecord;
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

    /// Returns whether strict PKCS#7 unpadding is enforced for Anti-MEV transactions at a block
    /// height.
    pub fn is_pkcs7_strict_active_at_block(&self, block_number: u64) -> bool {
        self.is_fork_active_at_block(NeoXHardfork::Pkcs7Strict, block_number)
    }

    /// Parses a canonical Neo X genesis and installs Neo X-specific hardforks.
    pub fn from_genesis(mut genesis: Genesis) -> Result<Self, NeoXChainSpecError> {
        let neox = genesis
            .config
            .extra_fields
            .deserialize_as::<NeoXGenesisConfig>()
            .map_err(NeoXChainSpecError::InvalidExtension)?;

        if !neox.has_expected_validator_count() {
            return Err(NeoXChainSpecError::InvalidValidatorCount {
                expected: NEOX_MAX_VALIDATOR_COUNT,
                actual: neox.dbft.standby_validators.len(),
            });
        }
        if neox.dbft.period == 0 {
            return Err(NeoXChainSpecError::ZeroBlockPeriod)
        }
        if neox.dbft.coinbase == Address::ZERO {
            return Err(NeoXChainSpecError::ZeroCoinbase)
        }
        validate_validator_set(&neox.dbft.standby_validators)?;

        // Geth fills these fields independently. In particular, a custom genesis may provide one
        // commitment explicitly while relying on the configured standby set for the other.
        let default_extra = DbftExtra::genesis_v0(neox.dbft.standby_validators.clone());
        if genesis.extra_data.is_empty() {
            genesis.extra_data = default_extra.try_encode()?;
        }
        if genesis.mix_hash == B256::ZERO {
            genesis.mix_hash = next_consensus_hash(
                default_extra.validators().expect("non-empty V0 genesis validators"),
            );
        }
        validate_explicit_dbft_genesis(&genesis)?;

        let mut inner = ChainSpec::from_genesis(genesis);
        inner.hardforks.extend([
            (NeoXHardfork::Dkg, ForkCondition::Block(neox.dkg_block)),
            (NeoXHardfork::AntiMev, ForkCondition::Block(neox.anti_mev_block)),
            (NeoXHardfork::EthSignature, ForkCondition::Block(neox.eth_signature_block)),
        ]);
        if let Some(strict_block) = neox.pkcs7_strict_block {
            inner.hardforks.insert(NeoXHardfork::Pkcs7Strict, ForkCondition::Block(strict_block));
        }

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
    /// A zero block period would continuously trigger view changes.
    #[error("zero-period dBFT chain is not supported")]
    ZeroBlockPeriod,
    /// dBFT requires a nonzero block-reward beneficiary.
    #[error("empty dBFT coinbase is not allowed")]
    ZeroCoinbase,
    /// A dBFT validator identifier cannot be the zero address.
    #[error("dBFT validator at index {index} is the zero address")]
    ZeroValidator {
        /// Position of the invalid validator in the supplied list.
        index: usize,
    },
    /// Every dBFT validator identifier must be unique.
    #[error("duplicate dBFT validator {address}")]
    DuplicateValidator {
        /// Repeated validator address.
        address: Address,
    },
    /// Explicit dBFT genesis extra data is malformed.
    #[error("invalid explicit dBFT genesis extraData: {0}")]
    InvalidDbftGenesisExtra(#[from] DbftExtraError),
    /// Explicit threshold genesis points are not valid BLS12-381 subgroup encodings.
    #[error("invalid explicit dBFT genesis threshold points: {0}")]
    InvalidDbftGenesisThreshold(#[from] DbftValidationError),
    /// Explicit dBFT genesis fields commit to different consensus identities.
    #[error("explicit dBFT genesis mixHash mismatch: expected {expected}, got {actual}")]
    DbftGenesisConsensusMismatch {
        /// Consensus commitment derived from the explicit extra data.
        expected: B256,
        /// Mix hash encoded by the genesis file.
        actual: B256,
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

fn validate_explicit_dbft_genesis(genesis: &Genesis) -> Result<(), NeoXChainSpecError> {
    let validator_count = genesis
        .config
        .extra_fields
        .deserialize_as::<NeoXGenesisConfig>()
        .map_err(NeoXChainSpecError::InvalidExtension)?
        .validator_count();
    let extra = DbftExtra::decode(&genesis.extra_data, validator_count)?;
    if let Some(validators) = extra.validators() {
        validate_validator_set(validators)?;
    }
    let expected = if let Some(public_key) = extra.threshold_public_key() {
        let signature = extra
            .threshold_signature()
            .expect("threshold dBFT genesis extra always contains a signature");
        // Neo X Geth permits the canonical compressed point-at-infinity as a threshold signature
        // sentinel at genesis because genesis commits the public key but has no preceding dBFT
        // round to sign it. Every non-genesis threshold signature still goes through full point
        // and cryptographic verification.
        if signature[0] == 0xc0 && signature[1..].iter().all(|byte| *byte == 0) {
            validate_threshold_public_key(public_key)?;
        } else {
            validate_threshold_points(public_key, signature)?;
        }
        keccak256(public_key)
    } else {
        next_consensus_hash(
            extra.validators().expect("ECDSA dBFT genesis extra always contains validators"),
        )
    };
    if genesis.mix_hash != expected {
        return Err(NeoXChainSpecError::DbftGenesisConsensusMismatch {
            expected,
            actual: genesis.mix_hash,
        });
    }
    Ok(())
}

fn validate_validator_set(validators: &[Address]) -> Result<(), NeoXChainSpecError> {
    if let Some(index) = validators.iter().position(|validator| *validator == Address::ZERO) {
        return Err(NeoXChainSpecError::ZeroValidator { index })
    }
    let mut sorted = validators.to_vec();
    sorted.sort_unstable();
    if let Some(duplicate) = sorted.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(NeoXChainSpecError::DuplicateValidator { address: duplicate[0] })
    }
    Ok(())
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
    use alloy_primitives::{b256, hex};
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
    const VALID_THRESHOLD_PUBLIC_KEY: [u8; 48] = hex!(
        "97cbfe3649c0ae4cf27deca9a3c760563b5a96342e5afad9e768418b1a0cec5f3d9874137fe43648ff0a1ec7b7520045"
    );
    const VALID_THRESHOLD_SIGNATURE: [u8; 96] = hex!(
        "8a8e4eccbc2ce3ab61e28e8e1e039ad8485a3e84950fe8ce32aad06f0e7ae45a9350a86195cf2b9671d35be63536767603f8aa9de9798ce725492b9a9ab97f6ee7cd4acd2eeac231d3eebb207de72e9a99f7ad417a8972a48ee54d2e747b1b65"
    );

    fn threshold_extra(public_key: [u8; 48], signature: [u8; 96]) -> DbftExtra {
        DbftExtra::Threshold {
            version: ExtraVersion::V2,
            fallback_next_consensus: B256::repeat_byte(0x11),
            public_key,
            signature,
        }
    }

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

    fn dbft_config_mut(genesis: &mut Genesis) -> &mut serde_json::Value {
        genesis.config.extra_fields.get_mut("dbft").expect("dbft extension")
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
    fn rejects_empty_validator_count() {
        let mut genesis = minimal_mainnet_genesis();
        let extension = genesis.config.extra_fields.get_mut("dbft").expect("dbft extension");
        extension["standbyValidators"] = serde_json::json!([]);

        assert!(matches!(
            NeoXChainSpec::from_genesis(genesis),
            Err(NeoXChainSpecError::InvalidValidatorCount { expected: 256, actual: 0 })
        ));
    }

    #[test]
    fn accepts_geth_private_network_validator_counts() {
        for count in [1_usize, 4, 7] {
            let mut genesis = minimal_mainnet_genesis();
            let validators = (1..=count).map(|index| format!("0x{index:040x}")).collect::<Vec<_>>();
            dbft_config_mut(&mut genesis)["standbyValidators"] =
                serde_json::to_value(validators).expect("validator list serializes");
            genesis.extra_data = DbftExtra::genesis_v0(
                (1..=count)
                    .map(|index| {
                        let mut bytes = [0_u8; 20];
                        bytes[19] = index as u8;
                        Address::from(bytes)
                    })
                    .collect(),
            )
            .try_encode()
            .unwrap();
            genesis.mix_hash = next_consensus_hash(
                DbftExtra::decode(&genesis.extra_data, count).unwrap().validators().unwrap(),
            );
            let spec = NeoXChainSpec::from_genesis(genesis).expect("private Geth count parses");
            assert_eq!(spec.neox.validator_count(), count);
        }
    }

    #[test]
    fn rejects_zero_period_coinbase_and_validator_addresses() {
        let mut zero_period = minimal_mainnet_genesis();
        dbft_config_mut(&mut zero_period)["period"] = serde_json::json!(0);
        assert!(matches!(
            NeoXChainSpec::from_genesis(zero_period),
            Err(NeoXChainSpecError::ZeroBlockPeriod)
        ));

        let mut zero_coinbase = minimal_mainnet_genesis();
        dbft_config_mut(&mut zero_coinbase)["coinbase"] =
            serde_json::json!("0x0000000000000000000000000000000000000000");
        assert!(matches!(
            NeoXChainSpec::from_genesis(zero_coinbase),
            Err(NeoXChainSpecError::ZeroCoinbase)
        ));

        let mut zero_validator = minimal_mainnet_genesis();
        dbft_config_mut(&mut zero_validator)["standbyValidators"][3] =
            serde_json::json!("0x0000000000000000000000000000000000000000");
        assert!(matches!(
            NeoXChainSpec::from_genesis(zero_validator),
            Err(NeoXChainSpecError::ZeroValidator { index: 3 })
        ));
    }

    #[test]
    fn rejects_duplicate_standby_validators() {
        let mut genesis = minimal_mainnet_genesis();
        let dbft = dbft_config_mut(&mut genesis);
        let duplicate = dbft["standbyValidators"][0].clone();
        dbft["standbyValidators"][4] = duplicate;

        assert!(matches!(
            NeoXChainSpec::from_genesis(genesis),
            Err(NeoXChainSpecError::DuplicateValidator { .. })
        ));
    }

    #[test]
    fn preserves_complete_explicit_dbft_genesis_header() {
        let mut genesis = minimal_mainnet_genesis();
        let explicit_extra = threshold_extra(VALID_THRESHOLD_PUBLIC_KEY, VALID_THRESHOLD_SIGNATURE)
            .try_encode()
            .unwrap();
        let explicit_mix_hash = keccak256(VALID_THRESHOLD_PUBLIC_KEY);
        genesis.extra_data = explicit_extra.clone();
        genesis.mix_hash = explicit_mix_hash;

        let spec = NeoXChainSpec::from_genesis(genesis).unwrap();
        assert_eq!(spec.genesis_header().extra_data, explicit_extra);
        assert_eq!(spec.genesis_header().mix_hash, explicit_mix_hash);
    }

    #[test]
    fn rejects_malformed_explicit_threshold_genesis_points() {
        let mut malformed_public_key = minimal_mainnet_genesis();
        malformed_public_key.extra_data =
            threshold_extra([0_u8; 48], VALID_THRESHOLD_SIGNATURE).try_encode().unwrap();
        malformed_public_key.mix_hash = keccak256([0_u8; 48]);
        assert!(matches!(
            NeoXChainSpec::from_genesis(malformed_public_key),
            Err(NeoXChainSpecError::InvalidDbftGenesisThreshold(
                DbftValidationError::InvalidThresholdPublicKey
            ))
        ));

        let mut malformed_signature = minimal_mainnet_genesis();
        malformed_signature.extra_data =
            threshold_extra(VALID_THRESHOLD_PUBLIC_KEY, [1_u8; 96]).try_encode().unwrap();
        malformed_signature.mix_hash = keccak256(VALID_THRESHOLD_PUBLIC_KEY);
        assert!(matches!(
            NeoXChainSpec::from_genesis(malformed_signature),
            Err(NeoXChainSpecError::InvalidDbftGenesisThreshold(
                DbftValidationError::InvalidThresholdSignature
            ))
        ));
    }

    #[test]
    fn accepts_geth_infinity_threshold_signature_sentinel_at_genesis() {
        let mut genesis = minimal_mainnet_genesis();
        let mut genesis_signature = [0_u8; 96];
        genesis_signature[0] = 0xc0;
        let explicit_extra =
            threshold_extra(VALID_THRESHOLD_PUBLIC_KEY, genesis_signature).try_encode().unwrap();
        genesis.extra_data = explicit_extra.clone();
        genesis.mix_hash = keccak256(VALID_THRESHOLD_PUBLIC_KEY);

        let spec = NeoXChainSpec::from_genesis(genesis).unwrap();
        assert_eq!(spec.genesis_header().extra_data, explicit_extra);
        assert_eq!(spec.genesis_header().mix_hash, keccak256(VALID_THRESHOLD_PUBLIC_KEY));
    }

    #[test]
    fn synthesizes_each_missing_dbft_genesis_header_field_independently() {
        let synthesized = NeoXChainSpec::from_genesis(minimal_mainnet_genesis()).unwrap();
        let expected_extra = synthesized.genesis_header().extra_data.clone();
        let expected_mix_hash = synthesized.genesis_header().mix_hash;

        let mut missing_extra = minimal_mainnet_genesis();
        missing_extra.mix_hash = expected_mix_hash;
        let spec = NeoXChainSpec::from_genesis(missing_extra).unwrap();
        assert_eq!(spec.genesis_header().extra_data, expected_extra);
        assert_eq!(spec.genesis_header().mix_hash, expected_mix_hash);

        let mut missing_mix_hash = minimal_mainnet_genesis();
        missing_mix_hash.extra_data = expected_extra.clone();
        let spec = NeoXChainSpec::from_genesis(missing_mix_hash).unwrap();
        assert_eq!(spec.genesis_header().extra_data, expected_extra);
        assert_eq!(spec.genesis_header().mix_hash, expected_mix_hash);
    }

    #[test]
    fn rejects_inconsistent_explicit_dbft_genesis_header() {
        let mut inconsistent_mix = minimal_mainnet_genesis();
        inconsistent_mix.mix_hash = B256::repeat_byte(0x33);
        assert!(matches!(
            NeoXChainSpec::from_genesis(inconsistent_mix),
            Err(NeoXChainSpecError::DbftGenesisConsensusMismatch { .. })
        ));

        let mut inconsistent = minimal_mainnet_genesis();
        inconsistent.extra_data =
            threshold_extra(VALID_THRESHOLD_PUBLIC_KEY, VALID_THRESHOLD_SIGNATURE)
                .try_encode()
                .unwrap();
        inconsistent.mix_hash = B256::repeat_byte(0x44);
        assert!(matches!(
            NeoXChainSpec::from_genesis(inconsistent),
            Err(NeoXChainSpecError::DbftGenesisConsensusMismatch { .. })
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
    fn privnet_spec_parses_with_out_of_order_forks() {
        // A private-network genesis: time forks in the past relative to live heads,
        // Neo X block forks far in the future, and no Paris fork. Such schedules
        // violate the EIP-6122 assumption that block forks precede time forks; the
        // beacon handshake handles them via fork-hash family membership (see
        // `reachable_fork_hashes` in `reth-neox-network`). This asserts the spec
        // parses and produces distinct folded/unfolded fork hashes across heads.
        let raw = r#"{
            "config": {
                "chainId": 47763777,
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
                "cancunTime": 1763000000,
                "pragueTime": 1763000000,
                "osakaTime": 1782700000,
                "neoXDKGBlock": 1000000000000,
                "neoXAMEVBlock": 1000000000000,
                "neoXEthSigBlock": 1000000000000,
                "dbft": {
                    "period": 1,
                    "standbyValidators": [
                        "0x34a3b2abb99b4c128acf61dcbbd1fcac0b161652",
                        "0x641ec1c538fa17e6ad8193c9b580f6850b114280",
                        "0xe3973f57e8a0aa312c1917ab0e6a05d8b6af6609",
                        "0xa61ac4a4f006f4fceeb72ee0012a2d3367168d10",
                        "0xe6d1a9db6a0893926bd81c0ef93aaaa543c116f0",
                        "0x4fe8af0dbb633283d8e9703668142fd130f2818d",
                        "0x763452f65353fffe73d46539e51a6ddfc0e2c86a"
                    ],
                    "coinbase": "0x1212000000000000000000000000000000000004"
                }
            },
            "gasLimit": "30000000",
            "difficulty": "1",
            "alloc": {}
        }"#;
        let genesis: Genesis = serde_json::from_str(raw).expect("valid privnet genesis");
        let spec = NeoXChainSpec::from_genesis(genesis).expect("valid privnet spec");
        let fresh = Head { number: 0, timestamp: 0, ..Default::default() };
        let live = Head { number: 57, timestamp: 1_784_485_765, ..Default::default() };
        // The past time forks fold into the live head's hash but not the fresh one's,
        // while the far-future block forks stay pending for both.
        let fresh_id = spec.fork_filter(fresh).current();
        let live_id = spec.fork_filter(live).current();
        assert_ne!(fresh_id.hash, live_id.hash);
        assert_eq!(fresh_id.next, 1_000_000_000_000);
        assert_eq!(live_id.next, 1_000_000_000_000);
    }

    #[test]
    fn mainnet_fork_id_matches_filter_current() {
        // The handler advertises `fork_filter(head).current()`; on the built-in
        // MainNet spec this must stay identical to `fork_id(head)` so live-network
        // behavior is unchanged.
        let spec = NeoXChainSpec::mainnet().expect("mainnet spec");
        for head in [
            Head { number: 0, timestamp: 0, ..Default::default() },
            Head { number: 7_150_000, timestamp: 1_784_485_765, ..Default::default() },
        ] {
            assert_eq!(spec.fork_id(&head), spec.fork_filter(head).current());
        }
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

    #[test]
    fn pkcs7_strict_activation_follows_configured_height() {
        let raw = r#"{
            "config": {
                "chainId": 12345,
                "neoXDKGBlock": 10,
                "neoXAMEVBlock": 20,
                "neoXEthSigBlock": 30,
                "neoXPkcs7StrictBlock": 50,
                "dbft": {
                    "period": 5,
                    "standbyValidators": [
                        "0x34a3b2abb99b4c128acf61dcbbd1fcac0b161652",
                        "0x641ec1c538fa17e6ad8193c9b580f6850b114280",
                        "0xe3973f57e8a0aa312c1917ab0e6a05d8b6af6609",
                        "0xa61ac4a4f006f4fceeb72ee0012a2d3367168d10",
                        "0xe6d1a9db6a0893926bd81c0ef93aaaa543c116f0",
                        "0x4fe8af0dbb633283d8e9703668142fd130f2818d",
                        "0x763452f65353fffe73d46539e51a6ddfc0e2c86a"
                    ],
                    "coinbase": "0x1212000000000000000000000000000000000004"
                }
            },
            "gasLimit": "30000000",
            "difficulty": "1",
            "alloc": {}
        }"#;
        let genesis: Genesis = serde_json::from_str(raw).expect("valid genesis");
        let spec = NeoXChainSpec::from_genesis(genesis).expect("valid spec");
        assert!(!spec.is_pkcs7_strict_active_at_block(49));
        assert!(spec.is_pkcs7_strict_active_at_block(50));
        assert!(spec.is_pkcs7_strict_active_at_block(100));

        let mainnet = NeoXChainSpec::mainnet().unwrap();
        assert!(!mainnet.is_pkcs7_strict_active_at_block(1_000_000));
    }
}
