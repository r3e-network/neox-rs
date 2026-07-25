//! Reth node-component wiring for a Neo X full node.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod antimev;
mod dkg;
mod dkg_call;
mod dkg_contract_state;
mod dkg_executor;
mod dkg_material;
mod dkg_prover;
mod dkg_replay;
mod dkg_storage;
mod dkg_submit;
mod dkg_task;
mod dkg_transaction;
mod engine;
mod metrics;
mod pool;
mod producer;
mod proposal;
mod reconstruction;
mod signer;
mod sync;
mod validator;

pub use antimev::{
    AntiMevEnvelope, AntiMevEnvelopeResolution, AntiMevFallbackReason, AntiMevPreBlock,
    AntiMevProposal, AntiMevProposalError, AntiMevResolutionError, EnvelopeDkgEpoch,
};
pub use dkg::{
    read_dkg_schedule, read_dkg_state, DkgPhase, DkgPublicKey, DkgReceiptState, DkgSchedule,
    DkgScheduleError, DkgScheduleStateError, DkgState, DkgStateError, DkgTaskAction, DkgTaskWatch,
};
pub use dkg_call::{
    decode_dkg_zk_version, read_dkg_zk_version_at_state, DkgContractCall, DkgContractCallError,
    DkgContractMethod, DkgGroth16Proof, DkgZkVersionError, DkgZkVersionStateError,
    DKG_ZK_VERSION_SELECTOR, NEOX_DKG_MESSAGE_LEN, NEOX_DKG_PVSS_LEN,
};
pub use dkg_contract_state::{
    read_dkg_message_public_key, read_dkg_message_public_keys, read_dkg_task_contract_state,
    DkgTaskContractState, DkgTaskContractStateError,
};
pub use dkg_executor::{
    DkgExecutorAction, DkgExecutorError, DkgExecutorOutcome, DkgTaskExecutor, DkgTaskId,
};
pub use dkg_material::{
    generate_dkg_task_material, prove_dkg_task_material, DkgRecipient, DkgTaskMaterial,
    DkgTaskPreparationError,
};
pub use dkg_prover::{
    DkgProofArtifact, DkgProver, DkgProverArtifacts, DkgProverError, DkgProverOutput,
    DkgShareScalar,
};
pub use dkg_replay::{
    apply_dkg_canonical_epoch, apply_dkg_canonical_recovery, apply_dkg_canonical_round,
    read_dkg_canonical_epoch, read_dkg_canonical_pvss, read_dkg_canonical_recovery,
    read_dkg_canonical_round, rebuild_dkg_canonical_round, rebuild_dkg_canonical_store,
    DkgCanonicalEpoch, DkgCanonicalPvss, DkgCanonicalRecovery, DkgCanonicalRound, DkgReplayError,
    DkgReplayOutcome,
};
pub use dkg_storage::{
    read_dkg_aggregated_commitment, read_dkg_recovery_messages, read_dkg_reshare_contribution,
    read_dkg_reshare_pvss, read_dkg_share_contribution, read_dkg_share_pvss, DkgStorageError,
    DkgStoredContribution, DkgStoredRecovery,
};
pub use dkg_submit::{submit_dkg_pool_transaction, DkgTransactionSubmitError};
pub use dkg_task::{DkgTaskContext, DkgTaskPlan, DkgTaskPlanError, DkgTaskPlanner};
pub use dkg_transaction::{
    DkgTransactionBuildError, DkgTransactionBuilder, DkgTransactionInputs,
    DEFAULT_DKG_TRANSACTION_GAS_LIMIT,
};
pub use engine::{NeoXEngineValidator, NeoXEngineValidatorBuilder};
pub use metrics::NeoXDkgMetrics;
pub use pool::NeoXPoolBuilder;
pub use producer::{
    build_primary_proposal, PrimaryProposal, PrimaryProposalAttributes, PrimaryProposalError,
    DEFAULT_PRIMARY_GAS_LIMIT,
};
pub use proposal::{
    verify_proposal, DbftProposalError, ProposalContents, ProposalTransactionAction,
    ProposalTransactionSync, VerifiedProposal,
};
pub use reconstruction::{
    reconstruct_antimev_proposal, AntiMevDropReason, AntiMevReconstruction,
    AntiMevReconstructionError, AntiMevReplacementFallback, AntiMevTransactionDecision,
    StaticPoolRejection, STATIC_POOL_MAX_TX_SIZE, STATIC_POOL_MIN_TIP,
};
pub use reth_neox_network::NeoXSidecarStore;
pub use signer::{DbftSigner, DbftSignerError, DkgShareEpoch, DkgTransactionRequest};
pub use sync::{run_beacon_sync, BeaconSyncContext};
pub use validator::{
    read_governance_pending_validators, read_governance_validator_set, read_governance_validators,
    DbftRoundProgress, DbftRoundState, DbftStateError, DbftVerifiedCommitSeal,
    GovernanceValidatorSet,
};

use alloy_eips::eip2124::Head;
use reth_ethereum_engine_primitives::EthEngineTypes;
use reth_ethereum_forks::Hardforks;
use reth_ethereum_primitives::EthPrimitives;
use reth_neox_chainspec::NeoXChainSpec;
use reth_neox_consensus_engine::NeoXConsensus;
use reth_neox_evm::NeoXEvmConfig;
use reth_neox_network::{
    BeaconEventReceiver, BeaconLocalStatus, BeaconProtocol, BeaconVersion, DbftEventReceiver,
    DbftProtocol,
};
use reth_network::{primitives::BasicNetworkPrimitives, NetworkHandle, NetworkManager, PeersInfo};
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
use tracing::info;

/// Type configuration for an independent Neo X full node.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NeoXNode {
    beacon: BeaconProtocol,
    beacon_events: Arc<Mutex<Option<BeaconEventReceiver>>>,
    dbft: DbftProtocol,
    dbft_events: Arc<Mutex<Option<DbftEventReceiver>>>,
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
        let (dbft, dbft_events) = DbftProtocol::new(0);
        Self {
            beacon,
            beacon_events: Arc::new(Mutex::new(Some(events))),
            dbft,
            dbft_events: Arc::new(Mutex::new(Some(dbft_events))),
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
    pub fn take_beacon_events(&self) -> Option<BeaconEventReceiver> {
        self.beacon_events.lock().expect("beacon events lock poisoned").take()
    }

    /// Returns the shared dBFT protocol command and verified-message handle.
    pub const fn dbft_protocol(&self) -> &DbftProtocol {
        &self.dbft
    }

    /// Takes the single validated dBFT-event receiver used by the consensus driver.
    pub fn take_dbft_events(&self) -> Option<DbftEventReceiver> {
        self.dbft_events.lock().expect("dBFT events lock poisoned").take()
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
                dbft: self.dbft.clone(),
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

/// Builds the standard `eth`/`snap` network and adds Neo X `beacon/1,2` and `dbft/0`.
#[derive(Debug, Clone)]
pub struct NeoXNetworkBuilder {
    beacon: BeaconProtocol,
    dbft: DbftProtocol,
    sidecar_store_enabled: bool,
}

impl<Node, Pool> NetworkBuilder<Node, Pool> for NeoXNetworkBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = NeoXChainSpec, Primitives = EthPrimitives>>,
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
        let launch_head = ctx.head();
        let seed = BeaconLocalStatus {
            network_id: chain_spec.inner.chain.id(),
            total_difficulty: launch_head.total_difficulty,
            head: launch_head.hash,
            head_number: launch_head.number,
            head_timestamp: launch_head.timestamp,
            genesis: chain_spec.inner.genesis_header.hash(),
            blob_sync: self.sidecar_store_enabled,
        };
        let provider = ctx.provider().clone();
        let status_chain_spec = Arc::clone(&chain_spec);
        let status = tokio::task::spawn_blocking(move || {
            // Reth's launch `Head` currently carries zero total difficulty. Resolve a stable
            // provider snapshot before any eth/beacon peer can handshake against that stale seed.
            sync::authoritative_canonical_status(&provider, seed, status_chain_spec.as_ref(), false)
        })
        .await
        .map_err(|error| eyre::eyre!("Neo X canonical-head task failed: {error}"))?
        .map_err(|error| eyre::eyre!("failed to resolve Neo X canonical head: {error}"))?;
        self.beacon.update_status(status);
        self.dbft.update_height(status.head_number);

        // reth's core eth-protocol Status advertises `ChainSpec::fork_id(head)`, which skips
        // time-based forks on chain specs without a Paris fork, but validates incoming peers with
        // `fork_filter(head).current()`, which folds them. On a Neo X config without Paris (e.g. a
        // private network, or any custom genesis) the advertised and validated fork ids diverge the
        // moment a time fork activates, so every node rejects every eth session while still
        // gossiping blocks over the beacon protocol. Steady-state production is unaffected
        // (blocks arrive as head+1 over beacon), but a validator that falls behind can
        // never run reth's pipeline backfill — it has zero eth peers to download the gap
        // from. Advertise the folded fork id so it matches the validation filter; on the
        // built-in MainNet spec (which has Paris) the two are already identical, so live
        // behavior and Neo X Geth eth-protocol interop are unchanged.
        let head_for_fork = Head {
            number: status.head_number,
            timestamp: status.head_timestamp,
            hash: status.head,
            total_difficulty: status.total_difficulty,
            ..Default::default()
        };
        let folded_fork_id = Hardforks::fork_filter(chain_spec.as_ref(), head_for_fork).current();
        let mut network_config =
            ctx.build_network_config(ctx.network_config_builder()?.set_head(head_for_fork));
        network_config.status.forkid = folded_fork_id;
        let mut network = NetworkManager::builder(network_config).await?;
        network.network_mut().add_rlpx_sub_protocol(self.beacon.handler(BeaconVersion::V2));
        network.network_mut().add_rlpx_sub_protocol(self.beacon.handler(BeaconVersion::V1));
        network.network_mut().add_rlpx_sub_protocol(self.dbft.handler());
        let handle = ctx.start_network(network, pool);
        info!(target: "reth::cli", enode=%handle.local_node_record(), block_number = status.head_number, block_hash = %status.head, total_difficulty = %status.total_difficulty, "Neo X P2P networking initialized with beacon/1,2 and dbft/0");
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
