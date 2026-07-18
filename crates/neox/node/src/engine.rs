//! Engine payload conversion that restores Neo X dBFT header fields.

use alloy_primitives::{B64, U256};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, PayloadAttributes as EthPayloadAttributes, PayloadError,
};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_forks::EthereumHardforks;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_neox_chainspec::NeoXChainSpec;
use reth_node_api::{AddOnsContext, FullNodeComponents, NodeTypes, PayloadTypes};
use reth_node_builder::rpc::PayloadValidatorBuilder;
use reth_node_ethereum::EthereumEngineValidator;
use reth_payload_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
};
use reth_payload_validator::{cancun, prague, shanghai};
use reth_primitives_traits::{Block as _, SealedBlock};
use std::sync::Arc;

/// Converts Engine API payloads into Neo X headers before hash and consensus validation.
#[derive(Debug, Clone)]
pub struct NeoXEngineValidator {
    chain_spec: Arc<NeoXChainSpec>,
    engine_compat: EthereumEngineValidator<NeoXChainSpec>,
}

impl NeoXEngineValidator {
    /// Creates a Neo X payload validator.
    pub fn new(chain_spec: Arc<NeoXChainSpec>) -> Self {
        Self { engine_compat: EthereumEngineValidator::new(Arc::clone(&chain_spec)), chain_spec }
    }
}

impl<Types> PayloadValidator<Types> for NeoXEngineValidator
where
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        let ExecutionData { mut payload, sidecar } = payload;
        let expected_hash = payload.block_hash();

        // Alloy's Ethereum Engine API decoder rejects extraData longer than 32 bytes before the
        // configured consensus validator gets to inspect it. Neo X stores the dBFT seal and
        // validator metadata in that field, so temporarily remove it while reusing Alloy's
        // transaction/base-fee/sidecar conversion and restore it on the resulting header. The
        // Neo X consensus adapter performs the exact versioned length and structure checks later.
        let extra_data = match &mut payload {
            ExecutionPayload::V1(payload) => core::mem::take(&mut payload.extra_data),
            ExecutionPayload::V2(payload) => core::mem::take(&mut payload.payload_inner.extra_data),
            ExecutionPayload::V3(payload) => {
                core::mem::take(&mut payload.payload_inner.payload_inner.extra_data)
            }
            ExecutionPayload::V4(payload) => {
                core::mem::take(&mut payload.payload_inner.payload_inner.payload_inner.extra_data)
            }
        };
        let mut block =
            payload.try_into_block_with_sidecar(&sidecar).map_err(NewPayloadError::from)?;
        block.header.extra_data = extra_data;
        // The Engine API omits both PoW difficulty and nonce. Neo X uses those fields for the dBFT
        // primary index and its in-turn/out-of-turn weight. Reconstruct the seven possible primary
        // indices and accept only the unique pair whose canonical hash matches the payload.
        let validator_count = self.chain_spec.neox.dbft.standby_validators.len();
        let mut last_hash = block.hash_slow();
        let sealed_block = if block.header.number == 0 {
            block.header.nonce = self.chain_spec.inner.genesis_header.nonce;
            block.header.difficulty = self.chain_spec.inner.genesis_header.difficulty;
            let block = block.seal_slow();
            last_hash = block.hash();
            (block.hash() == expected_hash).then_some(block)
        } else {
            (0..validator_count).find_map(|primary| {
                block.header.nonce = B64::from((primary as u64).to_be_bytes());
                block.header.difficulty =
                    if block.header.number % validator_count as u64 == primary as u64 {
                        U256::from(2)
                    } else {
                        U256::from(1)
                    };
                let candidate = block.clone().seal_slow();
                last_hash = candidate.hash();
                (candidate.hash() == expected_hash).then_some(candidate)
            })
        };
        let Some(sealed_block) = sealed_block else {
            return Err(
                PayloadError::BlockHash { execution: last_hash, consensus: expected_hash }.into()
            )
        };

        shanghai::ensure_well_formed_fields(
            sealed_block.body(),
            self.chain_spec.is_shanghai_active_at_timestamp(sealed_block.timestamp),
        )?;
        cancun::ensure_well_formed_fields(
            &sealed_block,
            sidecar.cancun(),
            self.chain_spec.is_cancun_active_at_timestamp(sealed_block.timestamp),
        )?;
        prague::ensure_well_formed_fields(
            sealed_block.body(),
            sidecar.prague(),
            self.chain_spec.is_prague_active_at_timestamp(sealed_block.timestamp),
        )?;

        Ok(sealed_block)
    }
}

impl<Types> EngineApiValidator<Types> for NeoXEngineValidator
where
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, Types::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<NeoXChainSpec> as EngineApiValidator<Types>>::validate_version_specific_fields(
            &self.engine_compat,
            version,
            payload_or_attrs,
        )
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &Types::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        <EthereumEngineValidator<NeoXChainSpec> as EngineApiValidator<Types>>::ensure_well_formed_attributes(
            &self.engine_compat,
            version,
            attributes,
        )
    }
}

/// Builds [`NeoXEngineValidator`] for both the engine tree and authenticated Engine API.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeoXEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for NeoXEngineValidatorBuilder
where
    Types: NodeTypes<
        ChainSpec = NeoXChainSpec,
        Primitives = EthPrimitives,
        Payload: PayloadTypes<
            PayloadAttributes = EthPayloadAttributes,
            ExecutionData = ExecutionData,
        >,
    >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = NeoXEngineValidator;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(NeoXEngineValidator::new(Arc::clone(&ctx.config.chain)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{Bytes, B256};
    use reth_ethereum_engine_primitives::EthPayloadTypes;
    use reth_ethereum_primitives::BlockBody;

    #[test]
    fn engine_roundtrip_restores_dbft_nonce_and_out_of_turn_difficulty() {
        let chain_spec = NeoXChainSpec::mainnet().unwrap();
        let validator = NeoXEngineValidator::new(Arc::clone(&chain_spec));
        let mut header = chain_spec.inner.genesis_header.clone_header();
        header.parent_hash = chain_spec.inner.genesis_header.hash();
        header.number = 1;
        header.timestamp = 5;
        header.nonce = B64::from(5_u64.to_be_bytes());
        header.difficulty = U256::from(1);
        header.mix_hash = B256::repeat_byte(0x42);
        header.gas_limit = 30_000_000;
        header.base_fee_per_gas = Some(1_000_000_000);
        header.extra_data = Bytes::from(vec![0x42; 201]);
        let body = BlockBody { withdrawals: Some(Default::default()), ..Default::default() };
        let block = Block { header, body }.seal_slow();
        let expected_hash = block.hash();
        let execution_data = EthPayloadTypes::block_to_payload(block, None);

        let converted = <NeoXEngineValidator as PayloadValidator<
            reth_ethereum_engine_primitives::EthEngineTypes,
        >>::convert_payload_to_block(&validator, execution_data)
        .unwrap();
        assert_eq!(converted.hash(), expected_hash);
        assert_eq!(converted.nonce, B64::from(5_u64.to_be_bytes()));
        assert_eq!(converted.difficulty, U256::from(1));
        assert_eq!(converted.extra_data.len(), 201);
        assert!(converted.body().transactions.is_empty());
    }

    #[test]
    fn unpatched_ethereum_payload_header_has_zero_difficulty() {
        let block = Block {
            header: Header {
                difficulty: U256::from(2),
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1_000_000_000),
                ..Default::default()
            },
            body: Default::default(),
        }
        .seal_slow();
        let data = EthPayloadTypes::block_to_payload(block, None);
        let ExecutionData { payload, sidecar } = data;
        let unpatched: Block = payload.try_into_block_with_sidecar(&sidecar).unwrap();
        assert_eq!(unpatched.header.difficulty, U256::ZERO);
    }
}
