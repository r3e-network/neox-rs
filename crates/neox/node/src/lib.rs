//! Reth node-component wiring for a Neo X full node.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_ethereum_primitives::EthPrimitives;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::NeoXEvmConfig;
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
    },
    node::Node,
    BuilderContext, NodeAdapter,
};
use reth_node_ethereum::{
    EthereumAddOns, EthereumEngineValidatorBuilder, EthereumEthApiBuilder, EthereumNetworkBuilder,
    EthereumPayloadBuilder, EthereumPoolBuilder,
};
use reth_provider::EthStorage;
use std::sync::Arc;

/// Type configuration for an independent Neo X full node.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct NeoXNode;

/// Builds the execution and consensus pair required by non-node CLI commands.
pub fn cli_components(chain_spec: Arc<NeoXChainSpec>) -> (NeoXEvmConfig, Arc<NeoXConsensus>) {
    (NeoXEvmConfig::new(Arc::clone(&chain_spec)), Arc::new(NeoXConsensus::new(chain_spec)))
}

impl NodeTypes for NeoXNode {
    type Primitives = EthPrimitives;
    type ChainSpec = NeoXChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

impl<N> Node<N> for NeoXNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        NeoXExecutorBuilder,
        NeoXConsensusBuilder,
    >;

    type AddOns =
        EthereumAddOns<NodeAdapter<N>, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(NeoXExecutorBuilder)
            .payload(BasicPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(NeoXConsensusBuilder)
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}

/// Builds the Neo X EVM and block executor.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeoXExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for NeoXExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = NeoXChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = NeoXEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(NeoXEvmConfig::new(ctx.chain_spec()))
    }
}

/// Builds the Neo X dBFT import validator.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeoXConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for NeoXConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = NeoXChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<NeoXConsensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(NeoXConsensus::new(ctx.chain_spec())))
    }
}
