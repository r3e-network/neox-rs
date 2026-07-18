//! Reth node-component wiring for a Neo X full node.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod engine;
mod pool;
mod sync;

pub use engine::{NeoXEngineValidator, NeoXEngineValidatorBuilder};
pub use pool::NeoXPoolBuilder;
pub use reth_neox_network::NeoXSidecarStore;
pub use sync::{run_beacon_sync, BeaconSyncContext};

use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_ethereum_primitives::EthPrimitives;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::NeoXEvmConfig;
use reth_neox_network::{BeaconEvent, BeaconLocalStatus, BeaconProtocol, BeaconVersion};
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, PeersInfo};
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NetworkBuilder,
    },
    node::Node,
    rpc::{BasicEngineApiBuilder, BasicEngineValidatorBuilder, Identity, RpcAddOns},
    BuilderContext, NodeAdapter,
};
use reth_node_ethereum::{EthereumAddOns, EthereumEthApiBuilder, EthereumPayloadBuilder};
use reth_provider::EthStorage;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionPool};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::info;

/// Type configuration for an independent Neo X full node.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NeoXNode {
    beacon: BeaconProtocol,
    beacon_events: Arc<Mutex<Option<mpsc::UnboundedReceiver<BeaconEvent>>>>,
    sidecar_store_enabled: bool,
}

impl NeoXNode {
    /// Creates a Neo X node preset and its shared beacon protocol state.
    pub fn new(chain_spec: Arc<NeoXChainSpec>) -> Self {
        let genesis = chain_spec.inner.genesis_header.hash();
        let genesis_total_difficulty = chain_spec.inner.genesis_header.difficulty;
        let (beacon, events) = BeaconProtocol::new(
            chain_spec,
            BeaconLocalStatus {
                network_id: 0,
                total_difficulty: genesis_total_difficulty,
                head: genesis,
                head_number: 0,
                head_timestamp: 0,
                genesis,
                blob_sync: false,
            },
        );
        Self {
            beacon,
            beacon_events: Arc::new(Mutex::new(Some(events))),
            sidecar_store_enabled: false,
        }
    }

    /// Advertises finalized Neo X sidecar serving for this node preset.
    pub const fn with_sidecar_store(mut self) -> Self {
        self.sidecar_store_enabled = true;
        self
    }

    /// Returns the shared beacon protocol command and status handle.
    pub const fn beacon_protocol(&self) -> &BeaconProtocol {
        &self.beacon
    }

    /// Takes the single validated beacon-event receiver used by the sync driver.
    pub fn take_beacon_events(&self) -> Option<mpsc::UnboundedReceiver<BeaconEvent>> {
        self.beacon_events.lock().expect("beacon events lock poisoned").take()
    }
}

impl Default for NeoXNode {
    fn default() -> Self {
        Self::new(NeoXChainSpec::mainnet().expect("canonical Neo X mainnet genesis must parse"))
    }
}

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
        NeoXPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        NeoXNetworkBuilder,
        NeoXExecutorBuilder,
        NeoXConsensusBuilder,
    >;

    type AddOns = EthereumAddOns<NodeAdapter<N>, EthereumEthApiBuilder, NeoXEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(NeoXPoolBuilder)
            .executor(NeoXExecutorBuilder)
            .payload(BasicPayloadServiceBuilder::default())
            .network(NeoXNetworkBuilder {
                beacon: self.beacon.clone(),
                sidecar_store_enabled: self.sidecar_store_enabled,
            })
            .consensus(NeoXConsensusBuilder)
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::new(RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            NeoXEngineValidatorBuilder,
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Identity::new(),
        ))
    }
}

/// Builds the standard `eth`/`snap` network and adds Neo X `beacon/1,2` before it starts.
#[derive(Debug, Clone)]
pub struct NeoXNetworkBuilder {
    beacon: BeaconProtocol,
    sidecar_store_enabled: bool,
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for NeoXNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = NeoXChainSpec>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
{
    type Network =
        NetworkHandle<BasicNetworkPrimitives<PrimitivesTy<Node::Types>, PoolPooledTx<Pool>>>;

    async fn build_network(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<Self::Network> {
        let chain_spec = ctx.chain_spec();
        let head = ctx.head();
        self.beacon.update_status(BeaconLocalStatus {
            network_id: chain_spec.inner.chain.id(),
            total_difficulty: head.total_difficulty,
            head: head.hash,
            head_number: head.number,
            head_timestamp: head.timestamp,
            genesis: chain_spec.inner.genesis_header.hash(),
            blob_sync: self.sidecar_store_enabled,
        });

        let mut network = ctx.network_builder().await?;
        network.network_mut().add_rlpx_sub_protocol(self.beacon.handler(BeaconVersion::V2));
        network.network_mut().add_rlpx_sub_protocol(self.beacon.handler(BeaconVersion::V1));
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), "Neo X P2P networking initialized with beacon/1,2");
        Ok(handle)
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
