//! Neo X transaction-pool construction and parent-state policy validation.

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{Address, U256};
use reth_evm::ConfigureEvm;
use reth_neox_antimev::{encrypted_gas, is_envelope, MIN_ENCRYPTED_GAS_LIMIT};
use reth_neox_evm::{
    policy_blacklist_storage_key, policy_storage_key, POLICY_BASE_FEE_SLOT,
    POLICY_ENVELOPE_FEE_SLOT, POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT,
    POLICY_PROXY_ADDRESS,
};
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_node_builder::{
    components::{PoolBuilder, TxPoolBuilder},
    BuilderContext, FullNodeTypes, NodeTypes,
};
use reth_provider::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore,
    error::{InvalidPoolTransactionError, PoolTransactionError},
    EthPooledTransaction, EthTransactionPool, PoolTransaction, TransactionValidationTaskExecutor,
};
use std::any::Any;
use thiserror::Error;
use tracing::{debug, info};

/// Builds an Ethereum-format pool with Neo X `PolicyProxy` validation.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeoXPoolBuilder;

impl<Types, Node, Evm> PoolBuilder<Node, Evm> for NeoXPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: reth_chainspec::EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = reth_ethereum_primitives::TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore, Evm>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();
        let blobs_disabled = ctx.config().txpool.disable_blobs_support ||
            ctx.config().txpool.blobpool_max_count == 0;
        let blob_store = reth_node_builder::components::create_blob_store(ctx)?;

        let builder =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .set_eip4844(!blobs_disabled)
                .kzg_settings(ctx.kzg_settings()?)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee);
        let mut validator = builder.build::<EthPooledTransaction, _>(blob_store.clone());

        let provider = ctx.provider().clone();
        validator.set_additional_stateful_validation(move |_origin, tx, _account_state| {
            let state = provider
                .latest()
                .map_err(|error| NeoXPoolPolicyError::Provider(error.to_string()))?;
            validate_policy(tx, state.as_ref())
        });

        if validator.eip4844() {
            let kzg_settings = validator.kzg_settings().clone();
            ctx.task_executor().spawn_blocking_task(async move {
                let _ = kzg_settings.get();
                debug!(target: "reth::cli", "Initialized KZG settings");
            });
        }

        let validator = TransactionValidationTaskExecutor::spawn(
            validator,
            ctx.task_executor(),
            ctx.config().txpool.additional_validation_tasks,
        );
        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "reth::cli", "Neo X policy-aware transaction pool initialized");
        debug!(target: "reth::cli", "Spawned Neo X txpool maintenance task");
        Ok(transaction_pool)
    }
}

fn validate_policy(
    tx: &EthPooledTransaction,
    state: &dyn StateProvider,
) -> Result<(), InvalidPoolTransactionError> {
    let blocked = state
        .storage(POLICY_PROXY_ADDRESS, policy_blacklist_storage_key(tx.sender()).into())
        .map_err(|error| NeoXPoolPolicyError::Provider(error.to_string()))?
        .unwrap_or_default();
    if !blocked.is_zero() {
        return Err(NeoXPoolPolicyError::BlockedSender(tx.sender()).into())
    }

    let base_fee = read_policy_slot(state, POLICY_BASE_FEE_SLOT)?;
    let base_fee_u64 =
        u64::try_from(base_fee).map_err(|_| NeoXPoolPolicyError::BaseFeeOutOfRange(base_fee))?;
    let mut minimum_tip = read_policy_slot(state, POLICY_MIN_GAS_TIP_CAP_SLOT)?;
    let envelope = is_envelope(tx.ty(), tx.kind().to().copied(), tx.input());

    if envelope {
        let maximum_gas = read_policy_slot(state, POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT)?;
        if U256::from(tx.gas_limit()) > maximum_gas {
            return Err(NeoXPoolPolicyError::EnvelopeGasAbovePolicy {
                gas_limit: tx.gas_limit(),
                maximum_gas,
            }
            .into())
        }

        let inner_gas = encrypted_gas(tx.input());
        if inner_gas < MIN_ENCRYPTED_GAS_LIMIT {
            return Err(NeoXPoolPolicyError::EncryptedGasBelowMinimum(inner_gas).into())
        }
        if tx.gas_limit() < u64::from(inner_gas) {
            return Err(NeoXPoolPolicyError::EnvelopeGasBelowEncrypted {
                gas_limit: tx.gas_limit(),
                inner_gas,
            }
            .into())
        }

        minimum_tip =
            minimum_tip.saturating_add(read_policy_slot(state, POLICY_ENVELOPE_FEE_SLOT)?);
    }

    let effective_tip = tx.effective_tip_per_gas(base_fee_u64).unwrap_or_default();
    if U256::from(effective_tip) < minimum_tip {
        return Err(
            NeoXPoolPolicyError::TipBelowPolicy { effective_tip, minimum_tip, base_fee }.into()
        )
    }
    Ok(())
}

fn read_policy_slot(
    state: &dyn StateProvider,
    slot: u64,
) -> Result<U256, InvalidPoolTransactionError> {
    state
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())
        .map(|value| value.unwrap_or_default())
        .map_err(|error| NeoXPoolPolicyError::Provider(error.to_string()).into())
}

#[derive(Debug, Error)]
enum NeoXPoolPolicyError {
    #[error("failed to read Neo X policy state: {0}")]
    Provider(String),
    #[error("transaction sender {0} is blacklisted by Neo X PolicyProxy")]
    BlockedSender(Address),
    #[error("Neo X PolicyProxy base fee does not fit the execution header: {0}")]
    BaseFeeOutOfRange(U256),
    #[error("Envelope gas limit {gas_limit} exceeds Neo X policy maximum {maximum_gas}")]
    EnvelopeGasAbovePolicy { gas_limit: u64, maximum_gas: U256 },
    #[error("encrypted transaction gas {0} is below the Neo X minimum")]
    EncryptedGasBelowMinimum(u32),
    #[error("Envelope gas limit {gas_limit} is below encrypted transaction gas {inner_gas}")]
    EnvelopeGasBelowEncrypted { gas_limit: u64, inner_gas: u32 },
    #[error(
        "effective tip {effective_tip} is below Neo X policy minimum {minimum_tip} at base fee {base_fee}"
    )]
    TipBelowPolicy { effective_tip: u128, minimum_tip: U256, base_fee: U256 },
}

impl From<NeoXPoolPolicyError> for InvalidPoolTransactionError {
    fn from(error: NeoXPoolPolicyError) -> Self {
        Self::Other(Box::new(error))
    }
}

impl PoolTransactionError for NeoXPoolPolicyError {
    fn is_bad_transaction(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
