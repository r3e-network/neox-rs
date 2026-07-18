//! Reth execution configuration for Neo X.

use crate::{NeoXBlockExecutorFactory, GOVERNANCE_REWARD_PROXY_ADDRESS};
use alloc::{borrow::Cow, sync::Arc};
use alloy_consensus::Header;
use alloy_evm::{eth::EthBlockExecutionCtx, EvmEnv};
use alloy_primitives::{B256, U256};
use alloy_rpc_types_engine::ExecutionData;
use core::convert::Infallible;
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    eth::NextEvmEnvAttributes, ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator,
    ExecutionCtxFor, NextBlockEnvAttributes,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_neox_chainspec::NeoXChainSpec;
use reth_primitives_traits::{SealedBlock, SealedHeader};
use revm::primitives::hardfork::SpecId;

/// Reth EVM configuration for Neo X block import and construction.
#[derive(Debug, Clone)]
pub struct NeoXEvmConfig {
    /// Neo X block-executor factory.
    pub executor_factory: NeoXBlockExecutorFactory<RethReceiptBuilder, Arc<NeoXChainSpec>>,
    /// Ethereum-format block assembler; dBFT consensus fields are completed by the validator.
    pub block_assembler: EthBlockAssembler<NeoXChainSpec>,
    /// Ethereum Engine API payload decoder reused before applying Neo X environment overrides.
    engine_compat: EthEvmConfig<NeoXChainSpec>,
}

impl NeoXEvmConfig {
    /// Creates a Neo X execution configuration.
    pub fn new(chain_spec: Arc<NeoXChainSpec>) -> Self {
        Self {
            executor_factory: NeoXBlockExecutorFactory::from_chain_spec(
                RethReceiptBuilder::default(),
                Arc::clone(&chain_spec),
            ),
            block_assembler: EthBlockAssembler::new(Arc::clone(&chain_spec)),
            engine_compat: EthEvmConfig::new(chain_spec),
        }
    }

    /// Returns the active chain specification.
    pub const fn chain_spec(&self) -> &Arc<NeoXChainSpec> {
        self.executor_factory.spec()
    }
}

impl ConfigureEngineEvm<ExecutionData> for NeoXEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        let mut env = self.engine_compat.evm_env_for_payload(payload)?;
        env.block_env.difficulty = U256::from(2);
        env.block_env.prevrandao = Some(B256::ZERO);
        env.block_env.beneficiary = GOVERNANCE_REWARD_PROXY_ADDRESS;
        Ok(env)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.engine_compat.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.engine_compat.tx_iterator_for_payload(payload)
    }
}

impl ConfigureEvm for NeoXEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = NeoXBlockExecutorFactory<RethReceiptBuilder, Arc<NeoXChainSpec>>;
    type BlockAssembler = EthBlockAssembler<NeoXChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        let mut env = EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(header.timestamp),
        );
        // Neo X uses the mix hash for its next-consensus commitment. Geth therefore exposes zero
        // through PREVRANDAO even though Shanghai instructions are active.
        env.block_env.difficulty = header.difficulty;
        env.block_env.prevrandao = Some(B256::ZERO);
        Ok(env)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        let mut env = EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: B256::ZERO,
                gas_limit: attributes.gas_limit,
                slot_number: attributes.slot_number,
            },
            // PolicyProxy is authoritative. Keeping the signed parent value is a safe template;
            // the validator payload path replaces it from parent state before execution.
            parent.base_fee_per_gas.unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec().blob_params_at_timestamp(attributes.timestamp),
        );
        env.block_env.difficulty = U256::from(2);
        env.block_env.prevrandao = Some(B256::ZERO);
        env.block_env.beneficiary = GOVERNANCE_REWARD_PROXY_ADDRESS;
        Ok(env)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: None,
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(|w| Cow::Owned(w.into_inner())),
            extra_data: attributes.extra_data,
            slot_number: attributes.slot_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256};

    #[test]
    fn imported_header_preserves_dbft_difficulty_and_hides_mix_from_prevrandao() {
        let config = NeoXEvmConfig::new(NeoXChainSpec::mainnet().unwrap());
        let header = Header {
            number: 1,
            difficulty: U256::from(1),
            mix_hash: B256::repeat_byte(0x42),
            ..config.chain_spec().inner.genesis_header.clone_header()
        };

        let env = config.evm_env(&header).unwrap();
        assert_eq!(env.block_env.difficulty, U256::from(1));
        assert_eq!(env.block_env.prevrandao, Some(B256::ZERO));
    }

    #[test]
    fn next_block_template_uses_governance_beneficiary_and_parent_policy_fee() {
        let config = NeoXEvmConfig::new(NeoXChainSpec::mainnet().unwrap());
        let parent = Header {
            number: 1,
            timestamp: 1_722_000_000,
            base_fee_per_gas: Some(20_000_000_000),
            ..Default::default()
        };
        let attributes = NextBlockEnvAttributes {
            timestamp: parent.timestamp + 5,
            suggested_fee_recipient: Address::repeat_byte(0x99),
            prev_randao: B256::repeat_byte(0x77),
            gas_limit: 30_000_000,
            parent_beacon_block_root: None,
            withdrawals: None,
            extra_data: Bytes::new(),
            slot_number: None,
        };

        let env = config.next_evm_env(&parent, &attributes).unwrap();
        assert_eq!(env.block_env.beneficiary, GOVERNANCE_REWARD_PROXY_ADDRESS);
        assert_eq!(env.block_env.basefee, 20_000_000_000);
        assert_eq!(env.block_env.difficulty, U256::from(2));
        assert_eq!(env.block_env.prevrandao, Some(B256::ZERO));
    }
}
