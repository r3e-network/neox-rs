//! Canonical-block validator DKG runtime for the Neo X full-node executable.

use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_primitives::{Address, Bytes, B256, U256};
use futures::{Stream, StreamExt};
use reth_chain_state::CanonStateNotification;
use reth_ethereum_primitives::{EthPrimitives, Receipt, TransactionSigned};
use reth_neox_antimev::{
    global_public_key_from_commitment, verify_aggregated_dkg_commitment,
    verify_aggregated_dkg_share, DkgKeyStore, NEOX_DKG_SCALER,
};
use reth_neox_evm::{
    policy_storage_key, NeoXEvmConfig, KEY_MANAGEMENT_PROXY_ADDRESS,
    KEY_MANAGEMENT_ROUND_NUMBER_SLOT, POLICY_BASE_FEE_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT,
    POLICY_PROXY_ADDRESS,
};
use reth_neox_node::{
    apply_dkg_canonical_recovery, apply_dkg_canonical_round, generate_dkg_task_material,
    prove_dkg_task_material, read_dkg_canonical_epoch, read_dkg_canonical_pvss,
    read_dkg_canonical_recovery, read_dkg_canonical_round, read_dkg_message_public_keys,
    read_dkg_recovery_messages, read_dkg_schedule, read_dkg_task_contract_state,
    read_dkg_zk_version_at_state, read_governance_pending_validators,
    read_governance_validator_set, rebuild_dkg_canonical_round, rebuild_dkg_canonical_store,
    submit_dkg_pool_transaction, DbftSigner, DkgCanonicalEpoch, DkgCanonicalPvss,
    DkgCanonicalRecovery, DkgCanonicalRound, DkgContractMethod, DkgExecutorAction,
    DkgExecutorOutcome, DkgProver, DkgRecipient, DkgReplayError, DkgSchedule, DkgShareEpoch,
    DkgTaskContext, DkgTaskExecutor, DkgTaskId, DkgTaskMaterial, DkgTaskPlan, DkgTaskPlanner,
    DkgTransactionBuilder, DkgTransactionInputs, NeoXDkgMetrics,
};
use reth_provider::{BlockReaderIdExt, ReceiptProvider, StateProvider, StateProviderFactory};
use reth_transaction_pool::{PoolTransaction, PoolTx, TransactionPool};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, task::JoinHandle, time::MissedTickBehavior};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// Secret state and prover configuration owned exclusively by the validator DKG task.
pub(crate) struct DkgRuntimeConfig {
    /// Validator consensus and transaction signer shared with dBFT.
    pub signer: DbftSigner,
    /// Decrypted, validator-bound DKG state.
    pub store: DkgKeyStore,
    /// Authenticated encrypted-state path.
    pub keystore_path: PathBuf,
    /// Zeroized password retained only for atomic state persistence.
    pub password: Zeroizing<Vec<u8>>,
    /// Sandboxed external encryption/proof helper.
    pub prover: DkgProver,
    /// Operator-selected deployed verifier version, zero or one.
    pub zk_version: u64,
    /// EIP-155 chain ID and deterministic sharing domain separator.
    pub chain_id: u64,
}

impl DkgRuntimeConfig {
    fn persist(&self) -> eyre::Result<()> {
        self.store.save_encrypted(&self.keystore_path, &self.password)?;
        Ok(())
    }

    fn install_signer_shares(&self, canonical_head: alloy_primitives::B256) -> eyre::Result<()> {
        let round = self.store.round();
        let current = self
            .store
            .current_private_share()
            .map(|share| -> eyre::Result<_> {
                let public_key =
                    self.store.current_global_public_key().copied().ok_or_else(|| {
                        eyre::eyre!("settled current DKG share has no global public key")
                    })?;
                Ok((*share.as_bytes(), DkgShareEpoch::new(round, public_key, canonical_head)))
            })
            .transpose()?;
        let previous = self
            .store
            .previous_private_share()
            .map(|share| -> eyre::Result<_> {
                let previous_round = round
                    .checked_sub(1)
                    .ok_or_else(|| eyre::eyre!("previous DKG share exists before round one"))?;
                let public_key =
                    self.store.previous_global_public_key().copied().ok_or_else(|| {
                        eyre::eyre!("settled previous DKG share has no global public key")
                    })?;
                Ok((
                    *share.as_bytes(),
                    DkgShareEpoch::new(previous_round, public_key, canonical_head),
                ))
            })
            .transpose()?;
        self.signer.replace_canonical_dkg_private_shares(current, previous)?;
        Ok(())
    }
}

struct DkgRuntimeMachine {
    /// Last canonical head for which a complete heartbeat finished successfully.
    canonical_head: Option<(u64, alloy_primitives::B256)>,
    epoch: Option<(DkgSchedule, u64)>,
    membership: Option<(Option<u64>, Option<u64>)>,
    /// Canonical round and current-set membership for which signer shares were installed.
    ///
    /// This is deliberately process-local: if installation fails after the encrypted keystore
    /// was persisted, the marker remains unset and the next canonical heartbeat retries it.
    signer_installation: Option<(u64, Option<u64>, alloy_primitives::B256)>,
    /// Full settled-round material last replayed from one canonical state snapshot.
    settled_canonical: Option<DkgSettledCanonical>,
    /// Full unfinished-round contribution set last replayed into the local keystore.
    active_canonical: Option<DkgCanonicalRound>,
    /// Full recovery set last replayed for this validator, if it is a recovery recipient.
    recovery_canonical: Option<DkgCanonicalRecovery>,
    planner: DkgTaskPlanner,
    executor: DkgTaskExecutor,
    transactions: DkgTransactionBuilder,
    preparations: HashMap<DkgTaskId, DkgPreparationHandle>,
    /// Canonical recipient inputs that all queued material and transactions were built against.
    task_inputs: Option<DkgTaskInputSnapshot>,
    /// Local tasks already represented by canonical contract storage at the current head.
    canonical_tasks: HashSet<DkgTaskId>,
    /// Every locally submitted hash retained until confirmation, expiry, or canonical
    /// invalidation.
    owned_transactions: HashMap<DkgTaskId, Vec<B256>>,
    /// Task ownership and nonce reservations staged for release after the canonical-head fence.
    pending_transaction_releases: HashSet<DkgTaskId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DkgSettledCanonical {
    round: u64,
    current_index: Option<u64>,
    pvss: Option<DkgCanonicalPvss>,
    epoch: Option<DkgCanonicalEpoch>,
}

impl DkgSettledCanonical {
    fn read(
        state: &dyn StateProvider,
        round: u64,
        current_index: Option<u64>,
    ) -> eyre::Result<Self> {
        let (pvss, epoch) = if round == 0 {
            (None, None)
        } else {
            (
                Some(read_dkg_canonical_pvss(state, round)?),
                Some(read_dkg_canonical_epoch(state, round, current_index)?),
            )
        };
        Ok(Self { round, current_index, pvss, epoch })
    }
}

struct DkgPreparationHandle {
    started: Instant,
    source_head: B256,
    inputs: DkgTaskInputSnapshot,
    task: JoinHandle<Result<Bytes, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DkgTaskInputSnapshot {
    pending: Vec<Address>,
    message_public_keys: Vec<[u8; 65]>,
}

impl DkgTaskInputSnapshot {
    fn read(state: &dyn StateProvider, pending: &[Address]) -> eyre::Result<Self> {
        Ok(Self {
            pending: pending.to_vec(),
            message_public_keys: read_dkg_message_public_keys(state, pending)?,
        })
    }
}

struct DkgPreparationContext<'a> {
    config: &'a mut DkgRuntimeConfig,
    machine: &'a mut DkgRuntimeMachine,
    metrics: &'a NeoXDkgMetrics,
    inputs: &'a DkgTaskInputSnapshot,
    canonical_head: B256,
    height: u64,
}

struct DkgActionContext<'a, Provider, Pool> {
    provider: &'a Provider,
    pool: &'a Pool,
    config: &'a DkgRuntimeConfig,
    machine: &'a mut DkgRuntimeMachine,
    metrics: &'a NeoXDkgMetrics,
    canonical_head: B256,
    height: u64,
}

struct DkgHeartbeatContext<'a, Provider, Pool> {
    provider: &'a Provider,
    pool: &'a Pool,
    evm_config: &'a NeoXEvmConfig,
    config: &'a mut DkgRuntimeConfig,
    machine: &'a mut DkgRuntimeMachine,
    metrics: &'a NeoXDkgMetrics,
}

#[derive(Debug)]
struct CanonicalHeadChanged(String);

impl fmt::Display for CanonicalHeadChanged {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalHeadChanged {}

#[derive(Debug, PartialEq, Eq)]
enum InitialReconciliationWakeup<T> {
    Canonical(T),
    Maintenance,
    Closed,
}

async fn wait_for_initial_reconciliation_wakeup<Notifications>(
    canonical: &mut Notifications,
    maintenance_delay: Duration,
) -> InitialReconciliationWakeup<Notifications::Item>
where
    Notifications: Stream + Unpin,
{
    tokio::select! {
        notification = canonical.next() => match notification {
            Some(notification) => InitialReconciliationWakeup::Canonical(notification),
            None => InitialReconciliationWakeup::Closed,
        },
        _ = tokio::time::sleep(maintenance_delay) => InitialReconciliationWakeup::Maintenance,
    }
}

impl DkgRuntimeMachine {
    fn new(chain_id: u64) -> eyre::Result<Self> {
        Ok(Self {
            canonical_head: None,
            epoch: None,
            membership: None,
            signer_installation: None,
            settled_canonical: None,
            active_canonical: None,
            recovery_canonical: None,
            planner: DkgTaskPlanner::default(),
            executor: DkgTaskExecutor::default(),
            transactions: DkgTransactionBuilder::new(chain_id)?,
            preparations: HashMap::new(),
            task_inputs: None,
            canonical_tasks: HashSet::new(),
            owned_transactions: HashMap::new(),
            pending_transaction_releases: HashSet::new(),
        })
    }

    fn reset_task_work(&mut self, chain_id: u64) -> eyre::Result<()> {
        for preparation in self.preparations.drain().map(|(_, preparation)| preparation) {
            preparation.task.abort();
        }
        self.planner = DkgTaskPlanner::default();
        self.executor = DkgTaskExecutor::default();
        self.transactions = DkgTransactionBuilder::new(chain_id)?;
        Ok(())
    }

    fn drain_owned_transactions(&mut self) -> Vec<B256> {
        self.pending_transaction_releases.clear();
        self.owned_transactions.drain().flat_map(|(_, hashes)| hashes).collect()
    }

    fn stage_transaction_release(&mut self, id: DkgTaskId) -> bool {
        let tracked = self.transactions.reservation(id).is_some() ||
            self.owned_transactions.contains_key(&id);
        self.pending_transaction_releases.insert(id);
        tracked
    }

    fn reset_epoch_task_work(
        &mut self,
        chain_id: u64,
        epoch: Option<(DkgSchedule, u64)>,
        membership: (Option<u64>, Option<u64>),
    ) -> eyre::Result<()> {
        self.reset_task_work(chain_id)?;
        self.epoch = epoch;
        self.membership = Some(membership);
        self.active_canonical = None;
        self.recovery_canonical = None;
        self.task_inputs = None;
        self.canonical_tasks.clear();
        Ok(())
    }

    fn suspend_task_work(&mut self, chain_id: u64) -> eyre::Result<()> {
        self.reset_task_work(chain_id)?;
        self.active_canonical = None;
        self.recovery_canonical = None;
        self.task_inputs = None;
        self.canonical_tasks.clear();
        Ok(())
    }

    fn invalidate_head_work(&mut self, chain_id: u64) -> eyre::Result<()> {
        self.reset_task_work(chain_id)?;
        self.canonical_head = None;
        self.signer_installation = None;
        self.active_canonical = None;
        self.recovery_canonical = None;
        self.task_inputs = None;
        self.canonical_tasks.clear();
        Ok(())
    }
}

impl Drop for DkgRuntimeMachine {
    fn drop(&mut self) {
        for preparation in self.preparations.drain().map(|(_, preparation)| preparation) {
            preparation.task.abort();
        }
    }
}

/// Runs the validator-only DKG service until the canonical notification stream closes.
pub(crate) async fn run_dkg_runtime<Provider, Pool, Notifications>(
    provider: Provider,
    pool: Pool,
    evm_config: NeoXEvmConfig,
    mut config: DkgRuntimeConfig,
    mut canonical: Notifications,
    startup_ready: oneshot::Sender<Result<(), String>>,
) where
    Provider: BlockReaderIdExt<Header = Header>
        + ReceiptProvider<Receipt = Receipt>
        + StateProviderFactory
        + Clone,
    Pool: TransactionPool + Clone,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
    Notifications: Stream<Item = CanonStateNotification<EthPrimitives>> + Unpin,
{
    let metrics = NeoXDkgMetrics::default();
    let mut startup_ready = Some(startup_ready);
    let mut machine = match DkgRuntimeMachine::new(config.chain_id) {
        Ok(machine) => machine,
        Err(error) => {
            error!(target: "neox_rs::dkg", %error, "Invalid Neo X DKG runtime configuration");
            let _ = startup_ready
                .take()
                .expect("startup readiness sender must be present")
                .send(Err(error.to_string()));
            return;
        }
    };

    let mut initial_reorg = true;
    loop {
        match provider.latest_header() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let message = "cannot initialize DKG runtime without a canonical header".to_owned();
                if let Err(cleanup_error) =
                    invalidate_canonical_attempt(&pool, &config, &mut machine)
                {
                    let message =
                        format!("{message}; initial DKG cleanup also failed: {cleanup_error}");
                    let _ = startup_ready
                        .take()
                        .expect("startup readiness sender must be present")
                        .send(Err(message.clone()));
                    error!(target: "neox_rs::dkg", %message, "Initial Neo X DKG reconciliation cleanup failed");
                    return;
                }
                warn!(target: "neox_rs::dkg", %message, "Initial Neo X DKG reconciliation deferred while canonical sync advances");
                match wait_for_initial_reconciliation_wakeup(&mut canonical, Duration::from_secs(1))
                    .await
                {
                    InitialReconciliationWakeup::Canonical(notification) => {
                        initial_reorg |=
                            matches!(notification, CanonStateNotification::Reorg { .. });
                    }
                    InitialReconciliationWakeup::Maintenance => {}
                    InitialReconciliationWakeup::Closed => {
                        let message = "Neo X DKG canonical notification stream closed before initial canonical reconciliation".to_owned();
                        let _ = startup_ready
                            .take()
                            .expect("startup readiness sender must be present")
                            .send(Err(message.clone()));
                        error!(target: "neox_rs::dkg", %message);
                        return;
                    }
                }
                continue;
            }
            Err(error) => {
                if let Err(cleanup_error) =
                    invalidate_canonical_attempt(&pool, &config, &mut machine)
                {
                    let message =
                        format!("{error}; initial DKG cleanup also failed: {cleanup_error}");
                    let _ = startup_ready
                        .take()
                        .expect("startup readiness sender must be present")
                        .send(Err(message.clone()));
                    error!(target: "neox_rs::dkg", %message, "Initial Neo X DKG reconciliation cleanup failed");
                    return;
                }
                warn!(target: "neox_rs::dkg", %error, "Initial Neo X DKG reconciliation deferred after canonical header read failed");
                match wait_for_initial_reconciliation_wakeup(&mut canonical, Duration::from_secs(1))
                    .await
                {
                    InitialReconciliationWakeup::Canonical(notification) => {
                        initial_reorg |=
                            matches!(notification, CanonStateNotification::Reorg { .. });
                    }
                    InitialReconciliationWakeup::Maintenance => {}
                    InitialReconciliationWakeup::Closed => {
                        let message = "Neo X DKG canonical notification stream closed before initial canonical reconciliation".to_owned();
                        let _ = startup_ready
                            .take()
                            .expect("startup readiness sender must be present")
                            .send(Err(message.clone()));
                        error!(target: "neox_rs::dkg", %message);
                        return;
                    }
                }
                continue;
            }
        }
        match heartbeat(
            DkgHeartbeatContext {
                provider: &provider,
                pool: &pool,
                evm_config: &evm_config,
                config: &mut config,
                machine: &mut machine,
                metrics: &metrics,
            },
            initial_reorg,
        )
        .await
        {
            Ok(()) => {
                let _ = startup_ready
                    .take()
                    .expect("startup readiness sender must be present")
                    .send(Ok(()));
                break;
            }
            Err(error) if error.downcast_ref::<CanonicalHeadChanged>().is_some() => {
                if let Err(cleanup_error) =
                    invalidate_canonical_attempt(&pool, &config, &mut machine)
                {
                    let message = format!(
                        "failed to invalidate stale initial DKG work after {error}: {cleanup_error}"
                    );
                    let _ = startup_ready
                        .take()
                        .expect("startup readiness sender must be present")
                        .send(Err(message.clone()));
                    error!(target: "neox_rs::dkg", %message, "Initial Neo X DKG reconciliation cleanup failed");
                    return;
                }
                initial_reorg = false;
                debug!(target: "neox_rs::dkg", %error, "Canonical head advanced during initial DKG reconciliation; retrying latest state");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                if let Err(cleanup_error) =
                    invalidate_canonical_attempt(&pool, &config, &mut machine)
                {
                    let message =
                        format!("{error}; initial DKG cleanup also failed: {cleanup_error}");
                    let _ = startup_ready
                        .take()
                        .expect("startup readiness sender must be present")
                        .send(Err(message.clone()));
                    error!(target: "neox_rs::dkg", %message, "Initial Neo X DKG reconciliation cleanup failed");
                    return;
                }
                initial_reorg = false;
                warn!(target: "neox_rs::dkg", %error, "Initial Neo X DKG reconciliation deferred while canonical sync advances");
                match wait_for_initial_reconciliation_wakeup(&mut canonical, Duration::from_secs(1))
                    .await
                {
                    InitialReconciliationWakeup::Canonical(notification) => {
                        initial_reorg =
                            matches!(notification, CanonStateNotification::Reorg { .. });
                    }
                    InitialReconciliationWakeup::Maintenance => {}
                    InitialReconciliationWakeup::Closed => {
                        let message = "Neo X DKG canonical notification stream closed before initial canonical reconciliation".to_owned();
                        let _ = startup_ready
                            .take()
                            .expect("startup readiness sender must be present")
                            .send(Err(message.clone()));
                        error!(target: "neox_rs::dkg", %message);
                        return;
                    }
                }
            }
        }
    }

    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // `interval` starts ready; consume that tick so maintenance begins after one full period.
    maintenance.tick().await;
    loop {
        let notification = tokio::select! {
            notification = canonical.next() => Some(notification),
            _ = maintenance.tick() => None,
        };
        let (height, reorg) = match notification {
            Some(Some(notification)) => {
                let reorg = matches!(notification, CanonStateNotification::Reorg { .. });
                let height = if let Some(tip) = notification.tip_checked() {
                    tip.number()
                } else {
                    match provider.latest_header() {
                        Ok(Some(header)) => header.number(),
                        Ok(None) => {
                            if let Err(cleanup_error) =
                                invalidate_canonical_attempt(&pool, &config, &mut machine)
                            {
                                error!(target: "neox_rs::dkg", %cleanup_error, "Failed to invalidate Neo X DKG work after a canonical revert lost the latest header");
                                return;
                            }
                            warn!(target: "neox_rs::dkg", "Canonical revert temporarily left Neo X DKG without a latest header");
                            continue;
                        }
                        Err(error) => {
                            if let Err(cleanup_error) =
                                invalidate_canonical_attempt(&pool, &config, &mut machine)
                            {
                                error!(target: "neox_rs::dkg", %error, %cleanup_error, "Failed to invalidate Neo X DKG work after a canonical revert header read failed");
                                return;
                            }
                            warn!(target: "neox_rs::dkg", %error, "Failed to read DKG height after canonical revert");
                            continue;
                        }
                    }
                };
                (height, reorg)
            }
            Some(None) => break,
            None => match provider.latest_header() {
                // A proof can finish while the chain is idle. Drive the complete heartbeat at the
                // same head so prepared calldata can submit and receipt/expiry actions can advance.
                Ok(Some(header)) => (header.number(), false),
                Ok(None) => {
                    warn!(target: "neox_rs::dkg", "Periodic Neo X DKG heartbeat temporarily has no latest header");
                    continue;
                }
                Err(error) => {
                    warn!(target: "neox_rs::dkg", %error, "Periodic Neo X DKG heartbeat failed to read the latest header");
                    continue;
                }
            },
        };
        let mut retry_reorg = reorg;
        loop {
            match heartbeat(
                DkgHeartbeatContext {
                    provider: &provider,
                    pool: &pool,
                    evm_config: &evm_config,
                    config: &mut config,
                    machine: &mut machine,
                    metrics: &metrics,
                },
                retry_reorg,
            )
            .await
            {
                Ok(()) => break,
                Err(error) if error.downcast_ref::<CanonicalHeadChanged>().is_some() => {
                    if let Err(cleanup_error) =
                        invalidate_canonical_attempt(&pool, &config, &mut machine)
                    {
                        error!(target: "neox_rs::dkg", height, reorg, %error, %cleanup_error, "Failed to invalidate stale Neo X DKG work");
                        return;
                    }
                    retry_reorg = false;
                    debug!(target: "neox_rs::dkg", height, reorg, %error, "Canonical head advanced during DKG reconciliation; retrying latest state");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    if let Err(cleanup_error) =
                        invalidate_canonical_attempt(&pool, &config, &mut machine)
                    {
                        error!(target: "neox_rs::dkg", height, reorg, %error, %cleanup_error, "Failed to invalidate failed Neo X DKG work");
                        return;
                    }
                    warn!(target: "neox_rs::dkg", height, reorg, %error, "Neo X DKG heartbeat failed");
                    retry_reorg = false;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    if let Err(error) = invalidate_canonical_attempt(&pool, &config, &mut machine) {
        error!(target: "neox_rs::dkg", %error, "Failed to invalidate Neo X DKG work after the canonical notification stream closed");
        return;
    }
    warn!(target: "neox_rs::dkg", "Neo X DKG canonical notification stream closed");
}

async fn heartbeat<Provider, Pool>(
    context: DkgHeartbeatContext<'_, Provider, Pool>,
    reorg: bool,
) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header>
        + ReceiptProvider<Receipt = Receipt>
        + StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    let DkgHeartbeatContext { provider, pool, evm_config, config, machine, metrics } = context;
    metrics.canonical_reconciliations_total.increment(1);
    if reorg {
        metrics.canonical_reorgs_total.increment(1);
    }
    let canonical_header = provider.latest_header()?.ok_or_else(|| {
        CanonicalHeadChanged("canonical DKG heartbeat temporarily has no latest header".into())
    })?;
    let canonical_head = canonical_header.hash();
    let height = canonical_header.number();
    if provider.block_hash(height)? != Some(canonical_head) {
        return Err(CanonicalHeadChanged(format!(
            "canonical DKG header {canonical_head} at height {height} is not in the canonical number mapping"
        ))
        .into());
    }
    let canonical_discontinuity = match machine.canonical_head {
        Some((previous_height, _)) if height < previous_height => true,
        Some((previous_height, previous_hash)) => {
            provider.block_hash(previous_height)? != Some(previous_hash)
        }
        None => false,
    };
    let canonical_reset = reorg || canonical_discontinuity;
    if canonical_reset {
        config.signer.replace_optional_dkg_private_shares(None, None)?;
        machine.signer_installation = None;
    }
    let state = match provider.state_by_block_hash(canonical_head) {
        Ok(state) => state,
        Err(error) => {
            let latest_changed =
                provider.latest_header()?.is_some_and(|header| header.hash() != canonical_head);
            if latest_changed {
                return Err(CanonicalHeadChanged(format!(
                    "canonical DKG state {canonical_head} was detached during reconciliation: {error}"
                ))
                .into());
            }
            return Err(error.into());
        }
    };
    let current_round = read_dkg_current_round(state.as_ref())?;
    let current = read_governance_validator_set(state.as_ref())?.original;
    let current_index = validator_index(&current, config.signer.account());
    let previous_membership = machine.membership;
    let current_membership_changed =
        previous_membership.is_some_and(|(previous, _)| previous != current_index);

    // Canonical notification streams may skip lagged reorg events. Compare the complete settled
    // material from the current state snapshot so an equal-round branch change cannot be missed.
    let settled_canonical =
        DkgSettledCanonical::read(state.as_ref(), current_round, current_index)?;
    let settled_changed =
        machine.settled_canonical.as_ref().is_some_and(|prior| prior != &settled_canonical);
    if settled_changed {
        discard_owned_pool_transactions(pool, machine);
        machine.reset_task_work(config.chain_id)?;
        info!(target: "neox_rs::dkg", height, round = current_round, "Reset Neo X DKG tasks after settled canonical material changed");
    }
    reconcile_settled_round(
        provider,
        canonical_head,
        config,
        &settled_canonical,
        &mut machine.signer_installation,
    )?;
    machine.settled_canonical = Some(settled_canonical);
    machine.membership =
        Some((current_index, previous_membership.and_then(|(_, pending_index)| pending_index)));

    // Everything below this point is active-round task input. Failure must suspend transaction
    // work without revoking the settled share that was just reconciled against this head.
    let schedule = match read_dkg_schedule(state.as_ref()) {
        Ok(schedule) => schedule,
        Err(error) => {
            suspend_task_work_at_head(
                provider,
                pool,
                config,
                machine,
                metrics,
                (height, canonical_head),
                &error,
            )?;
            return Ok(());
        }
    };
    let contract = match read_dkg_task_contract_state(state.as_ref()) {
        Ok(contract) => contract,
        Err(error) => {
            suspend_task_work_at_head(
                provider,
                pool,
                config,
                machine,
                metrics,
                (height, canonical_head),
                &error,
            )?;
            return Ok(());
        }
    };
    if contract.current_round != current_round {
        let error = eyre::eyre!(
            "canonical DKG round changed within one state snapshot: settled {current_round}, task state {}",
            contract.current_round
        );
        suspend_task_work_at_head(
            provider,
            pool,
            config,
            machine,
            metrics,
            (height, canonical_head),
            &error,
        )?;
        return Ok(());
    }

    let epoch = (schedule, contract.next_round);
    metrics.current_round.set(contract.next_round as f64);
    if canonical_reset ||
        machine.epoch != Some(epoch) ||
        previous_membership.is_none() ||
        current_membership_changed
    {
        discard_owned_pool_transactions(pool, machine);
        machine.reset_epoch_task_work(config.chain_id, Some(epoch), (current_index, None))?;
        info!(target: "neox_rs::dkg", height, reorg, canonical_discontinuity, current_index = ?current_index, round = contract.next_round, "Reset Neo X DKG canonical runtime state");
    }
    if recovery_plan_inputs_detached(machine.planner.recovery_indices(), &contract.recovery_indices)
    {
        discard_owned_pool_transactions(pool, machine);
        machine.reset_task_work(config.chain_id)?;
        info!(target: "neox_rs::dkg", height, round = contract.next_round, "Reset Neo X DKG tasks after canonical recovery inputs diverged");
    }

    let active = height >= schedule.share_start && height < schedule.target;
    let mut pending = Vec::new();
    let mut pending_index = None;
    let mut active_canonical = None;
    if active {
        let canonical_zk_version =
            read_dkg_zk_version_at_state(state.as_ref(), canonical_header.header(), evm_config);
        if let Err(error) = check_dkg_zk_version(config.zk_version, canonical_zk_version) {
            suspend_task_work_at_head(
                provider,
                pool,
                config,
                machine,
                metrics,
                (height, canonical_head),
                &error,
            )?;
            return Ok(());
        }
        pending = match read_governance_pending_validators(state.as_ref()) {
            Ok(pending) => pending,
            Err(error) => {
                suspend_task_work_at_head(
                    provider,
                    pool,
                    config,
                    machine,
                    metrics,
                    (height, canonical_head),
                    &error,
                )?;
                return Ok(());
            }
        };
        pending_index = validator_index(&pending, config.signer.account());
        let membership = (current_index, pending_index);
        let membership_changed = previous_membership.is_some_and(|previous| previous != membership);
        if membership_changed {
            metrics.validator_set_changes_total.increment(1);
        }
        let pending_changed =
            machine.membership.is_some_and(|(_, previous)| previous != pending_index) ||
                machine.task_inputs.as_ref().is_some_and(|inputs| inputs.pending != pending);
        if pending_changed {
            discard_owned_pool_transactions(pool, machine);
            machine.reset_task_work(config.chain_id)?;
            machine.task_inputs = None;
            machine.recovery_canonical = None;
            info!(target: "neox_rs::dkg", height, pending_index = ?pending_index, "Reset Neo X DKG tasks after pending validator membership changed");
        }
        machine.membership = Some(membership);

        let replay = (|| -> eyre::Result<DkgCanonicalRound> {
            let active_round = config
                .store
                .round()
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("Neo X DKG round exceeds u64"))?;
            if active_round != contract.next_round {
                eyre::bail!(
                    "reconciled DKG keystore expects round {active_round}, but canonical contract expects round {}",
                    contract.next_round
                );
            }
            let canonical = read_dkg_canonical_round(state.as_ref(), active_round)?;
            let active_changed = machine.active_canonical.as_ref() != Some(&canonical);
            let active_regressed = machine
                .active_canonical
                .as_ref()
                .is_some_and(|prior| canonical_round_regressed(prior, &canonical));
            if active_regressed {
                discard_owned_pool_transactions(pool, machine);
                machine.reset_task_work(config.chain_id)?;
                info!(target: "neox_rs::dkg", height, round = active_round, "Reset Neo X DKG tasks after canonical round material regressed");
            }
            let replay = if canonical_reset ||
                current_membership_changed ||
                pending_changed ||
                active_changed ||
                !config.store.is_sharing()
            {
                rebuild_dkg_canonical_round(
                    &mut config.store,
                    U256::from(config.chain_id),
                    pending_index,
                    &canonical,
                )?
            } else {
                apply_dkg_canonical_round(&mut config.store, pending_index, &canonical)?
            };
            if replay.store_changed {
                config.persist()?;
                debug!(target: "neox_rs::dkg", round = active_round, shares = replay.shares_received, reshares = replay.reshares_received, "Persisted canonical Neo X DKG replay");
            }
            machine.active_canonical = Some(canonical.clone());

            let recoverable =
                contract.share_ready && (1..=2).contains(&contract.recovery_indices.len());
            if height >= schedule.recover_start && recoverable {
                if !config.store.is_recovering() {
                    config.store.on_recover_period_start();
                    config.persist()?;
                }
                if height >= schedule.recover_check &&
                    pending_index.is_some_and(|index| contract.recovery_indices.contains(&index))
                {
                    let recovery = read_dkg_canonical_recovery(
                        state.as_ref(),
                        active_round,
                        pending_index.expect("membership checked above"),
                    )?;
                    let recovery_changed = machine.recovery_canonical.as_ref() != Some(&recovery);
                    let recovery_regressed = machine
                        .recovery_canonical
                        .as_ref()
                        .is_some_and(|prior| canonical_recovery_regressed(prior, &recovery));
                    if recovery_regressed {
                        discard_owned_pool_transactions(pool, machine);
                        machine.reset_task_work(config.chain_id)?;
                        info!(target: "neox_rs::dkg", height, round = active_round, "Reset Neo X DKG tasks after canonical recovery material regressed");
                    }
                    if recovery_changed {
                        // Recovery application is add-only, so restart its isolated group whenever
                        // the complete canonical set changes, including a lagged reorg event.
                        config.store.on_recover_period_start();
                    }
                    let replay = apply_dkg_canonical_recovery(&mut config.store, &recovery)?;
                    if recovery_replay_requires_persistence(recovery_changed, replay.store_changed)
                    {
                        config.persist()?;
                        debug!(target: "neox_rs::dkg", round = active_round, recoveries = replay.recoveries_received, "Persisted canonical Neo X DKG recovery replay");
                    }
                    machine.recovery_canonical = Some(recovery);
                }
            }
            Ok(canonical)
        })();
        match replay {
            Ok(canonical) => active_canonical = Some(canonical),
            Err(error) => {
                suspend_task_work_at_head(
                    provider,
                    pool,
                    config,
                    machine,
                    metrics,
                    (height, canonical_head),
                    &error,
                )?;
                return Ok(());
            }
        }
    } else if config.store.is_sharing() {
        let mut reverted =
            match DkgKeyStore::load_encrypted(&config.keystore_path, &config.password) {
                Ok(store) => store,
                Err(error) => {
                    suspend_task_work_at_head(
                        provider,
                        pool,
                        config,
                        machine,
                        metrics,
                        (height, canonical_head),
                        &error,
                    )?;
                    return Ok(());
                }
            };
        reverted.revert_round();
        if let Err(error) = reverted.save_encrypted(&config.keystore_path, &config.password) {
            suspend_task_work_at_head(
                provider,
                pool,
                config,
                machine,
                metrics,
                (height, canonical_head),
                &error,
            )?;
            return Ok(());
        }
        config.store = reverted;
        discard_owned_pool_transactions(pool, machine);
        machine.reset_epoch_task_work(config.chain_id, Some(epoch), (current_index, None))?;
        info!(target: "neox_rs::dkg", round = contract.next_round, "Discarded unfinished Neo X DKG round outside its canonical window");
    }

    let task_context = DkgTaskContext {
        schedule,
        current_height: height,
        next_round: contract.next_round,
        current_index,
        pending_index,
        share_ready: contract.share_ready,
        recovery_indices: &contract.recovery_indices,
    };
    let task_inputs = if let Some(canonical) = active_canonical.as_ref() {
        let canonical_tasks = match canonical_local_tasks(state.as_ref(), &task_context, canonical)
        {
            Ok(tasks) => tasks,
            Err(error) => {
                suspend_task_work_at_head(
                    provider,
                    pool,
                    config,
                    machine,
                    metrics,
                    (height, canonical_head),
                    &error,
                )?;
                return Ok(());
            }
        };
        reconcile_canonical_local_tasks(pool, machine, config.chain_id, canonical_tasks, height)?;

        let task_inputs = match DkgTaskInputSnapshot::read(state.as_ref(), &pending) {
            Ok(inputs) => inputs,
            Err(error) => {
                suspend_task_work_at_head(
                    provider,
                    pool,
                    config,
                    machine,
                    metrics,
                    (height, canonical_head),
                    &error,
                )?;
                return Ok(());
            }
        };
        if let Err(error) = check_pending_message_key(
            pending_index,
            &task_inputs.message_public_keys,
            config.store.message_public_key(),
        ) {
            suspend_task_work_at_head(
                provider,
                pool,
                config,
                machine,
                metrics,
                (height, canonical_head),
                &error,
            )?;
            return Ok(());
        }
        let task_inputs_changed =
            machine.task_inputs.as_ref().is_some_and(|prior| prior != &task_inputs);
        if task_inputs_changed {
            discard_owned_pool_transactions(pool, machine);
            machine.reset_task_work(config.chain_id)?;
            info!(target: "neox_rs::dkg", height, round = contract.next_round, "Reset Neo X DKG tasks after canonical recipient inputs changed");
        }
        machine.task_inputs = Some(task_inputs.clone());
        Some(task_inputs)
    } else {
        machine.task_inputs = None;
        machine.canonical_tasks.clear();
        None
    };

    let mut tasks = machine.planner.take_tasks(task_context)?;
    tasks.retain(|plan| !machine.canonical_tasks.contains(&DkgTaskId::from(plan)));
    let inserted = machine.executor.enqueue(tasks);
    if inserted > 0 {
        metrics.tasks_queued_total.increment(inserted as u64);
        info!(target: "neox_rs::dkg", height, inserted, round = contract.next_round, "Queued Neo X DKG validator tasks");
    }

    if let Some(task_inputs) = task_inputs.as_ref() {
        poll_preparations(machine, metrics, height, canonical_head, task_inputs).await?;
    }
    let preparation_limit = usize::from(machine.preparations.is_empty());
    let actions = machine.executor.actions_with_preparation_limit(height, preparation_limit);
    for action in actions {
        match action {
            DkgExecutorAction::Prepare { id, plan } => {
                let Some(task_inputs) = task_inputs.as_ref() else {
                    eyre::bail!("Neo X DKG executor requested preparation outside an active round");
                };
                start_preparation(
                    DkgPreparationContext {
                        config,
                        machine,
                        metrics,
                        inputs: task_inputs,
                        canonical_head,
                        height,
                    },
                    id,
                    &plan,
                )?;
            }
            action => {
                handle_action(
                    DkgActionContext {
                        provider,
                        pool,
                        config,
                        machine,
                        metrics,
                        canonical_head,
                        height,
                    },
                    action,
                )
                .await?;
            }
        }
    }
    metrics.queued_tasks.set(machine.executor.len() as f64);
    ensure_canonical_head(provider, canonical_head)?;
    commit_transaction_releases(pool, machine);
    machine.canonical_head = Some((height, canonical_head));
    Ok(())
}

fn canonical_local_tasks(
    state: &dyn StateProvider,
    context: &DkgTaskContext<'_>,
    canonical: &DkgCanonicalRound,
) -> eyre::Result<HashSet<DkgTaskId>> {
    let mut tasks =
        canonical_contribution_tasks(context.current_index, context.pending_index, canonical);
    if context.current_height >= context.schedule.recover_start &&
        let Some(sender_index) = context.current_index &&
        (context.recovery_indices.is_empty() ||
            (context.share_ready && (1..=2).contains(&context.recovery_indices.len())))
    {
        let mut complete = true;
        for &recipient_index in context.recovery_indices {
            let messages = read_dkg_recovery_messages(state, canonical.round, recipient_index)?;
            if !messages.iter().any(|message| message.sender_index == sender_index) {
                complete = false;
                break;
            }
        }
        if complete {
            tasks.insert(DkgTaskId {
                round: canonical.round,
                method: DkgContractMethod::Recover,
                sender_index,
            });
        }
    }
    Ok(tasks)
}

fn recovery_plan_inputs_detached(planned: &[u64], canonical: &[u64]) -> bool {
    !planned.is_empty() && planned != canonical
}

fn canonical_round_regressed(prior: &DkgCanonicalRound, current: &DkgCanonicalRound) -> bool {
    prior.round != current.round ||
        prior.shares.iter().any(|contribution| !current.shares.contains(contribution)) ||
        prior.reshares.iter().any(|contribution| !current.reshares.contains(contribution))
}

fn canonical_recovery_regressed(
    prior: &DkgCanonicalRecovery,
    current: &DkgCanonicalRecovery,
) -> bool {
    prior.round != current.round ||
        prior.recipient_index != current.recipient_index ||
        prior.source_share != current.source_share ||
        prior.messages.iter().any(|message| !current.messages.contains(message))
}

const fn recovery_replay_requires_persistence(
    recovery_changed: bool,
    replay_store_changed: bool,
) -> bool {
    recovery_changed || replay_store_changed
}

fn canonical_contribution_tasks(
    current_index: Option<u64>,
    pending_index: Option<u64>,
    canonical: &DkgCanonicalRound,
) -> HashSet<DkgTaskId> {
    let mut tasks = HashSet::new();
    if let Some(index) = pending_index &&
        canonical.shares.iter().any(|contribution| contribution.sender_index == index)
    {
        tasks.insert(DkgTaskId {
            round: canonical.round,
            method: DkgContractMethod::Share,
            sender_index: index,
        });
    }
    if let Some(index) = current_index &&
        canonical.reshares.iter().any(|contribution| contribution.sender_index == index)
    {
        tasks.insert(DkgTaskId {
            round: canonical.round,
            method: DkgContractMethod::Reshare,
            sender_index: index,
        });
    }
    if let Some(index) = pending_index &&
        canonical.reshares.iter().any(|contribution| contribution.sender_index == index)
    {
        tasks.insert(DkgTaskId {
            round: canonical.round,
            method: DkgContractMethod::ReshareRecovered,
            sender_index: index,
        });
    }
    tasks
}

fn reconcile_canonical_local_tasks<Pool>(
    pool: &Pool,
    machine: &mut DkgRuntimeMachine,
    chain_id: u64,
    canonical: HashSet<DkgTaskId>,
    height: u64,
) -> eyre::Result<()>
where
    Pool: TransactionPool,
{
    let detached = machine.canonical_tasks.iter().any(|id| !canonical.contains(id));
    if detached {
        discard_owned_pool_transactions(pool, machine);
        machine.reset_task_work(chain_id)?;
        info!(target: "neox_rs::dkg", height, "Reset Neo X DKG tasks after a local canonical contribution was detached");
    }

    let completed = canonical
        .iter()
        .filter(|id| !machine.canonical_tasks.contains(id))
        .copied()
        .collect::<Vec<_>>();
    for id in completed {
        retire_canonical_task(pool, machine, id, height);
    }
    machine.canonical_tasks = canonical;
    Ok(())
}

fn retire_canonical_task<Pool>(
    _pool: &Pool,
    machine: &mut DkgRuntimeMachine,
    id: DkgTaskId,
    height: u64,
) where
    Pool: TransactionPool,
{
    let mut retired = if let Some(preparation) = machine.preparations.remove(&id) {
        preparation.task.abort();
        true
    } else {
        false
    };
    retired |= machine.executor.retire(id);
    retired |= machine.stage_transaction_release(id);
    if retired {
        info!(target: "neox_rs::dkg", height, ?id, "Retired Neo X DKG task already present in canonical storage");
    }
}

fn suspend_task_work_at_head<Provider, Pool>(
    provider: &Provider,
    pool: &Pool,
    config: &DkgRuntimeConfig,
    machine: &mut DkgRuntimeMachine,
    metrics: &NeoXDkgMetrics,
    canonical_head: (u64, B256),
    error: &dyn std::fmt::Display,
) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header>,
    Pool: TransactionPool,
{
    let (height, canonical_head) = canonical_head;
    discard_owned_pool_transactions(pool, machine);
    machine.suspend_task_work(config.chain_id)?;
    metrics.queued_tasks.set(0.0);
    ensure_canonical_head(provider, canonical_head)?;
    machine.canonical_head = Some((height, canonical_head));
    warn!(target: "neox_rs::dkg", height, %error, "Suspended Neo X DKG transaction work while retaining canonical signer shares");
    Ok(())
}

fn invalidate_canonical_attempt<Pool>(
    pool: &Pool,
    config: &DkgRuntimeConfig,
    machine: &mut DkgRuntimeMachine,
) -> eyre::Result<()>
where
    Pool: TransactionPool,
{
    // Always attempt both operations: a poisoned signer lock must not leave prover jobs or a task
    // in `Submitting`, and an executor reset failure must not leave the old share authorized.
    let clear_result = config.signer.replace_optional_dkg_private_shares(None, None);
    discard_owned_pool_transactions(pool, machine);
    let invalidate_result = machine.invalidate_head_work(config.chain_id);
    clear_result?;
    invalidate_result
}

fn discard_owned_pool_transactions<Pool>(pool: &Pool, machine: &mut DkgRuntimeMachine)
where
    Pool: TransactionPool,
{
    let hashes = machine.drain_owned_transactions();
    if !hashes.is_empty() {
        let requested = hashes.len();
        let removed = pool.remove_transactions(hashes).len();
        debug!(target: "neox_rs::dkg", requested, removed, "Discarded locally owned Neo X DKG pool transactions");
    }
}

fn commit_transaction_releases<Pool>(pool: &Pool, machine: &mut DkgRuntimeMachine)
where
    Pool: TransactionPool,
{
    let releases = std::mem::take(&mut machine.pending_transaction_releases);
    for id in releases {
        if let Some(hashes) = machine.owned_transactions.get(&id) {
            pool.remove_transactions(hashes.clone());
        }
        machine.owned_transactions.remove(&id);
        machine.transactions.release(id);
    }
}

async fn poll_preparations(
    machine: &mut DkgRuntimeMachine,
    metrics: &NeoXDkgMetrics,
    height: u64,
    canonical_head: B256,
    inputs: &DkgTaskInputSnapshot,
) -> eyre::Result<()> {
    let completed = machine
        .preparations
        .iter()
        .filter_map(|(id, preparation)| preparation.task.is_finished().then_some(*id))
        .collect::<Vec<_>>();
    for id in completed {
        let preparation = machine
            .preparations
            .remove(&id)
            .expect("completed DKG preparation must remain registered");
        let mut result = match preparation.task.await {
            Ok(result) => result,
            Err(error) => Err(format!("Neo X DKG prover task failed: {error}")),
        };
        if preparation.inputs != *inputs {
            result = Err(format!(
                "canonical DKG preparation inputs changed after proving at {}",
                preparation.source_head
            ));
        } else if preparation.source_head != canonical_head {
            debug!(target: "neox_rs::dkg", ?id, source_head = %preparation.source_head, %canonical_head, "Accepted Neo X DKG proof across a head advance with identical canonical inputs");
        }
        record_preparation(machine, metrics, height, id, result, preparation.started)?;
    }
    Ok(())
}

fn start_preparation(
    context: DkgPreparationContext<'_>,
    id: DkgTaskId,
    plan: &DkgTaskPlan,
) -> eyre::Result<()> {
    let DkgPreparationContext { config, machine, metrics, inputs, canonical_head, height } =
        context;
    metrics.prover_attempts_total.increment(1);
    let started = Instant::now();
    let material = match prepare_task_material(config, &inputs.message_public_keys, plan) {
        Ok(material) => material,
        Err(error) => {
            record_preparation(machine, metrics, height, id, Err(error.to_string()), started)?;
            return Ok(());
        }
    };
    if material.must_persist_store() &&
        let Err(error) = config.persist()
    {
        record_preparation(machine, metrics, height, id, Err(error.to_string()), started)?;
        return Ok(());
    }

    let prover = config.prover.clone();
    let zk_version = config.zk_version;
    let task = tokio::spawn(async move {
        prove_dkg_task_material(&prover, zk_version, material)
            .await
            .map_err(|error| error.to_string())
    });
    let previous = machine.preparations.insert(
        id,
        DkgPreparationHandle { started, source_head: canonical_head, inputs: inputs.clone(), task },
    );
    debug_assert!(previous.is_none(), "a DKG task cannot have two prover jobs");
    Ok(())
}

fn record_preparation(
    machine: &mut DkgRuntimeMachine,
    metrics: &NeoXDkgMetrics,
    height: u64,
    id: DkgTaskId,
    result: Result<Bytes, String>,
    started: Instant,
) -> eyre::Result<()> {
    metrics.prover_duration_seconds.record(started.elapsed().as_secs_f64());
    let outcome = machine.executor.record_prepared(id, result)?;
    record_outcome(metrics, &outcome);
    log_outcome(height, outcome);
    Ok(())
}

fn reconcile_settled_round<Provider>(
    provider: &Provider,
    canonical_head: alloy_primitives::B256,
    config: &mut DkgRuntimeConfig,
    canonical: &DkgSettledCanonical,
    signer_installation: &mut Option<(u64, Option<u64>, alloy_primitives::B256)>,
) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header> + StateProviderFactory,
{
    let contract_round = canonical.round;
    let current_index = canonical.current_index;
    let local_round = config.store.round();
    let validation_error = if local_round == contract_round {
        match validate_settled_store(&config.store, canonical) {
            Ok(()) => {
                if signer_installation_needed(
                    *signer_installation,
                    contract_round,
                    current_index,
                    canonical_head,
                ) {
                    ensure_canonical_head(provider, canonical_head)?;
                    config.install_signer_shares(canonical_head)?;
                    *signer_installation = Some((contract_round, current_index, canonical_head));
                    info!(target: "neox_rs::dkg", round = contract_round, member = current_index.is_some(), "Installed canonical Neo X DKG epoch shares");
                }
                return Ok(())
            }
            Err(error) => Some(error.to_string()),
        }
    } else {
        None
    };

    // Never leave a previously canonical share usable while detached state is being rebuilt. The
    // caller retries on any read/persistence error, and the marker remains unset until installation
    // succeeds, so a failed rebuild cannot accidentally reactivate stale material.
    config.signer.replace_optional_dkg_private_shares(None, None)?;
    *signer_installation = None;

    let rebuilt = if contract_round == 0 {
        config.store.detached_replay_baseline(0)
    } else {
        let state = provider.state_by_block_hash(canonical_head)?;
        let contributions =
            read_dkg_canonical_round(state.as_ref(), contract_round).map_err(|error| {
                if let Some(validation_error) = validation_error.as_ref() {
                    eyre::eyre!(
                        "local settled DKG round {contract_round} failed canonical validation: \
                         {validation_error}; canonical encrypted-message replay is unavailable: \
                         {error}"
                    )
                } else {
                    eyre::Report::from(error)
                }
            })?;
        let epoch = canonical.epoch.as_ref().expect("nonzero settled round has canonical epoch");
        rebuild_settled_store(&config.store, config.chain_id, current_index, &contributions, epoch)?
    };

    // `save_encrypted` atomically replaces the file. Keep the live store untouched until the
    // complete detached candidate is durable, so no transient baseline can escape on failure.
    rebuilt.save_encrypted(&config.keystore_path, &config.password)?;
    ensure_canonical_head(provider, canonical_head)?;
    config.store = rebuilt;
    config.install_signer_shares(canonical_head)?;
    *signer_installation = Some((contract_round, current_index, canonical_head));
    info!(target: "neox_rs::dkg", round = contract_round, previous_round = local_round, member = current_index.is_some(), "Rebuilt and installed canonical Neo X DKG epoch shares");
    Ok(())
}

fn validate_settled_store(
    store: &DkgKeyStore,
    canonical: &DkgSettledCanonical,
) -> eyre::Result<()> {
    if store.round() != canonical.round {
        eyre::bail!(
            "local Neo X DKG round {} does not match canonical round {}",
            store.round(),
            canonical.round
        );
    }
    if canonical.round == 0 {
        if store.current_private_share().is_some() ||
            store.previous_private_share().is_some() ||
            store.current_global_public_key().is_some() ||
            store.previous_global_public_key().is_some()
        {
            eyre::bail!("local round-zero Neo X DKG store contains settled key material");
        }
        return Ok(())
    }

    let pvss = canonical.pvss.as_ref().expect("nonzero settled round has canonical PVSS");
    let epoch = canonical.epoch.as_ref().expect("nonzero settled round has canonical epoch");
    if pvss.round != canonical.round || epoch.round != canonical.round {
        eyre::bail!("canonical Neo X DKG settled material has mismatched rounds");
    }
    let current_commitment = epoch.aggregated_commitment.as_ref().ok_or_else(|| {
        eyre::eyre!("canonical Neo X DKG round {} has no aggregate", canonical.round)
    })?;
    verify_aggregated_dkg_commitment(current_commitment, &pvss.shares)?;
    let current_global = global_public_key_from_commitment(current_commitment, NEOX_DKG_SCALER)?;
    if store.current_global_public_key() != Some(&current_global) {
        eyre::bail!(
            "local Neo X DKG round {} global key does not match the canonical commitment",
            canonical.round
        );
    }

    match canonical.current_index {
        Some(index) => {
            let private_share = store.current_private_share().ok_or_else(|| {
                eyre::eyre!(
                    "local Neo X DKG round {} is missing the current private share for member {index}",
                    canonical.round
                )
            })?;
            verify_aggregated_dkg_share(index, private_share.as_bytes(), &pvss.shares)?;
            let self_pvss = epoch.self_pvss.as_ref().ok_or_else(|| {
                eyre::eyre!(
                    "canonical Neo X DKG round {} is missing self PVSS for member {index}",
                    canonical.round
                )
            })?;
            if pvss.shares.get(index as usize - 1) != Some(self_pvss) {
                eyre::bail!(
                    "canonical Neo X DKG round {} self PVSS does not match member {index}",
                    canonical.round
                );
            }
        }
        None => {
            if store.current_private_share().is_some() || epoch.self_pvss.is_some() {
                eyre::bail!(
                    "local Neo X DKG round {} retains a private share outside the canonical validator set",
                    canonical.round
                );
            }
        }
    }

    if canonical.round == 1 {
        if !pvss.reshares.is_empty() ||
            epoch.previous_commitment.is_some() ||
            store.previous_private_share().is_some() ||
            store.previous_global_public_key().is_some()
        {
            eyre::bail!("first Neo X DKG round contains unexpected previous-epoch material");
        }
        return Ok(())
    }

    let previous_commitment = epoch.previous_commitment.as_ref().ok_or_else(|| {
        eyre::eyre!(
            "canonical Neo X DKG round {} has no previous aggregate commitment",
            canonical.round
        )
    })?;
    verify_aggregated_dkg_commitment(previous_commitment, &pvss.reshares)?;
    let previous_global = global_public_key_from_commitment(previous_commitment, NEOX_DKG_SCALER)?;
    if store.previous_global_public_key() != Some(&previous_global) {
        eyre::bail!(
            "local Neo X DKG round {} previous global key does not match the canonical commitment",
            canonical.round
        );
    }
    match canonical.current_index {
        Some(index) => {
            let private_share = store.previous_private_share().ok_or_else(|| {
                eyre::eyre!(
                    "local Neo X DKG round {} is missing the previous private share for member {index}",
                    canonical.round
                )
            })?;
            verify_aggregated_dkg_share(index, private_share.as_bytes(), &pvss.reshares)?;
        }
        None if store.previous_private_share().is_some() => {
            eyre::bail!(
                "local Neo X DKG round {} retains a previous private share outside the canonical validator set",
                canonical.round
            );
        }
        None => {}
    }
    Ok(())
}

fn ensure_canonical_head<Provider>(provider: &Provider, expected: B256) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header>,
{
    let header = provider.latest_header()?.ok_or_else(|| {
        CanonicalHeadChanged(
            "canonical DKG reconciliation temporarily lost the latest header".into(),
        )
    })?;
    let actual = header.hash();
    if actual != expected {
        return Err(CanonicalHeadChanged(format!(
            "canonical DKG head changed during reconciliation: expected {expected}, got {actual}"
        ))
        .into());
    }
    if provider.block_hash(header.number())? != Some(actual) {
        return Err(CanonicalHeadChanged(format!(
            "canonical DKG header {actual} at height {} is not in the canonical number mapping",
            header.number()
        ))
        .into());
    }
    Ok(())
}

fn rebuild_settled_store(
    source: &DkgKeyStore,
    chain_id: u64,
    current_index: Option<u64>,
    canonical: &DkgCanonicalRound,
    epoch: &DkgCanonicalEpoch,
) -> Result<DkgKeyStore, DkgReplayError> {
    rebuild_dkg_canonical_store(source, U256::from(chain_id), current_index, canonical, epoch)
}

async fn handle_action<Provider, Pool>(
    context: DkgActionContext<'_, Provider, Pool>,
    action: DkgExecutorAction,
) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header>
        + ReceiptProvider<Receipt = Receipt>
        + StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    let DkgActionContext { provider, pool, config, machine, metrics, canonical_head, height } =
        context;
    match action {
        DkgExecutorAction::Prepare { .. } => {
            eyre::bail!("Neo X DKG prepare action was not scheduled through the prover worker");
        }
        DkgExecutorAction::Submit { id, calldata, .. } => {
            ensure_canonical_head(provider, canonical_head)?;
            let result =
                build_and_submit(provider, pool, config, machine, canonical_head, id, calldata)
                    .await;
            let submitted_hash = result.as_ref().ok().copied();
            let outcome = machine.executor.record_submitted(
                id,
                height,
                result.map_err(|error| error.to_string()),
            );
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    if let Some(hash) = submitted_hash {
                        pool.remove_transaction(hash);
                    }
                    return Err(error.into());
                }
            };
            record_outcome(metrics, &outcome);
            log_outcome(height, outcome);
        }
        DkgExecutorAction::CheckReceipt { id, transaction_hash } => {
            metrics.receipt_checks_total.increment(1);
            let receipt = provider
                .receipt_by_hash(transaction_hash)
                .map(|receipt| match receipt {
                    Some(receipt) if receipt.status() => reth_neox_node::DkgReceiptState::Succeeded,
                    Some(_) => reth_neox_node::DkgReceiptState::Failed,
                    None => reth_neox_node::DkgReceiptState::Missing,
                })
                .map_err(|error| error.to_string());
            let outcome = machine.executor.record_receipt(id, receipt)?;
            record_outcome(metrics, &outcome);
            if matches!(outcome, DkgExecutorOutcome::Confirmed { .. }) {
                machine.stage_transaction_release(id);
            }
            log_outcome(height, outcome);
        }
        DkgExecutorAction::Expire { id } => {
            if let Some(preparation) = machine.preparations.remove(&id) {
                preparation.task.abort();
            }
            machine.stage_transaction_release(id);
            metrics.expired_total.increment(1);
            warn!(target: "neox_rs::dkg", height, ?id, "Neo X DKG task expired before confirmation");
        }
    }
    Ok(())
}

fn record_outcome(metrics: &NeoXDkgMetrics, outcome: &DkgExecutorOutcome) {
    match outcome {
        DkgExecutorOutcome::Prepared { .. } => metrics.task_preparations_total.increment(1),
        DkgExecutorOutcome::PreparationFailed { .. } => {
            metrics.task_preparation_failures_total.increment(1)
        }
        DkgExecutorOutcome::Submitted { .. } => metrics.submissions_total.increment(1),
        DkgExecutorOutcome::SubmissionFailed { .. } => {
            metrics.submission_failures_total.increment(1)
        }
        DkgExecutorOutcome::RetryScheduled { .. } => metrics.replacements_total.increment(1),
        DkgExecutorOutcome::Confirmed { .. } => metrics.confirmed_total.increment(1),
        DkgExecutorOutcome::ReceiptCheckFailed { .. } => {
            metrics.receipt_check_failures_total.increment(1)
        }
    }
}

fn prepare_task_material(
    config: &mut DkgRuntimeConfig,
    message_public_keys: &[[u8; 65]],
    plan: &DkgTaskPlan,
) -> eyre::Result<DkgTaskMaterial> {
    let recipients = recipients_for_plan(plan, message_public_keys)?;
    generate_dkg_task_material(
        &mut config.store,
        config.signer.account(),
        U256::from(config.chain_id),
        plan,
        recipients,
    )
    .map_err(Into::into)
}

fn recipients_for_plan(plan: &DkgTaskPlan, keys: &[[u8; 65]]) -> eyre::Result<Vec<DkgRecipient>> {
    if keys.len() != reth_neox_chainspec::NEOX_VALIDATOR_COUNT {
        eyre::bail!("pending validator message-key count is {}, expected 7", keys.len());
    }
    let indices = match plan.method {
        DkgContractMethod::Recover => plan.recovery_indices.clone(),
        DkgContractMethod::Share |
        DkgContractMethod::Reshare |
        DkgContractMethod::ReshareRecovered => (1..=keys.len() as u64).collect(),
    };
    indices
        .into_iter()
        .map(|index| {
            let key = keys
                .get(index as usize - 1)
                .ok_or_else(|| eyre::eyre!("missing DKG recipient key at index {index}"))?;
            Ok(DkgRecipient::new(index, *key)?)
        })
        .collect()
}

async fn build_and_submit<Provider, Pool>(
    provider: &Provider,
    pool: &Pool,
    config: &DkgRuntimeConfig,
    machine: &mut DkgRuntimeMachine,
    canonical_head: B256,
    id: DkgTaskId,
    calldata: Bytes,
) -> eyre::Result<alloy_primitives::B256>
where
    Provider: BlockReaderIdExt<Header = Header> + StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    let inputs = {
        let state = provider.state_by_block_hash(canonical_head)?;
        let on_chain_nonce = state
            .basic_account(&config.signer.account())?
            .map(|account| account.nonce)
            .unwrap_or_default();
        let base_fee_per_gas = read_policy_u128(state.as_ref(), POLICY_BASE_FEE_SLOT)?;
        let minimum_priority_fee_per_gas =
            read_policy_u128(state.as_ref(), POLICY_MIN_GAS_TIP_CAP_SLOT)?;
        DkgTransactionInputs { on_chain_nonce, base_fee_per_gas, minimum_priority_fee_per_gas }
    };
    let request = if machine.transactions.reservation(id).is_some() {
        machine.transactions.bump(id, calldata, inputs)?
    } else {
        machine.transactions.build(id, calldata, inputs, |nonce| {
            pool.get_transaction_by_sender_and_nonce(config.signer.account(), nonce).is_some()
        })?
    };
    let hash = submit_dkg_pool_transaction(pool, &config.signer, request).await?;
    machine.owned_transactions.entry(id).or_default().push(hash);
    if let Err(error) = ensure_canonical_head(provider, canonical_head) {
        pool.remove_transaction(hash);
        return Err(error);
    }
    Ok(hash)
}

fn read_policy_u128(state: &dyn StateProvider, slot: u64) -> eyre::Result<u128> {
    let value =
        state.storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())?.unwrap_or_default();
    u128::try_from(value).map_err(|_| eyre::eyre!("Neo X Policy slot {slot} exceeds u128"))
}

fn read_dkg_current_round(state: &dyn StateProvider) -> eyre::Result<u64> {
    let round = state
        .storage(KEY_MANAGEMENT_PROXY_ADDRESS, U256::from(KEY_MANAGEMENT_ROUND_NUMBER_SLOT).into())?
        .unwrap_or_default();
    u64::try_from(round).map_err(|_| eyre::eyre!("Neo X KeyManagement round number exceeds u64"))
}

fn check_dkg_zk_version(
    configured: u64,
    canonical: Result<u64, impl std::fmt::Display>,
) -> Result<(), String> {
    let canonical = canonical.map_err(|error| error.to_string())?;
    if canonical != configured {
        return Err(format!(
            "configured Neo X DKG ZK version {configured} does not match canonical KeyManagement.ZK_VERSION() {canonical}"
        ));
    }
    Ok(())
}

fn check_pending_message_key(
    pending_index: Option<u64>,
    message_public_keys: &[[u8; 65]],
    local_message_public_key: [u8; 65],
) -> Result<(), String> {
    // A current-only resharer encrypts exclusively to pending recipients and does not use its own
    // message key. Its settled TPKE share is authenticated separately by canonical replay.
    let Some(index) = pending_index else { return Ok(()) };
    let position = index
        .checked_sub(1)
        .and_then(|position| usize::try_from(position).ok())
        .ok_or_else(|| format!("invalid pending validator index {index} for DKG message key"))?;
    let canonical = message_public_keys.get(position).ok_or_else(|| {
        format!(
            "pending validator index {index} has no canonical DKG message key among {} validators",
            message_public_keys.len()
        )
    })?;
    if canonical != &local_message_public_key {
        return Err(format!(
            "local Neo X DKG message key does not match the canonical key for pending validator index {index}"
        ));
    }
    Ok(())
}

fn validator_index(
    validators: &[alloy_primitives::Address],
    account: alloy_primitives::Address,
) -> Option<u64> {
    validators
        .iter()
        .position(|validator| *validator == account)
        .and_then(|index| u64::try_from(index + 1).ok())
}

fn signer_installation_needed(
    installed: Option<(u64, Option<u64>, alloy_primitives::B256)>,
    round: u64,
    current_index: Option<u64>,
    canonical_head: alloy_primitives::B256,
) -> bool {
    installed != Some((round, current_index, canonical_head))
}

fn log_outcome(height: u64, outcome: DkgExecutorOutcome) {
    match outcome {
        DkgExecutorOutcome::Prepared { id } => {
            info!(target: "neox_rs::dkg", height, ?id, "Prepared Neo X DKG calldata");
        }
        DkgExecutorOutcome::PreparationFailed { id, error } => {
            warn!(target: "neox_rs::dkg", height, ?id, %error, "Neo X DKG preparation failed; retry scheduled");
        }
        DkgExecutorOutcome::Submitted { id, transaction_hash } => {
            info!(target: "neox_rs::dkg", height, ?id, %transaction_hash, "Submitted Neo X DKG transaction");
        }
        DkgExecutorOutcome::SubmissionFailed { id, error } => {
            warn!(target: "neox_rs::dkg", height, ?id, %error, "Neo X DKG submission failed; replacement scheduled");
        }
        DkgExecutorOutcome::RetryScheduled { id, receipt } => {
            warn!(target: "neox_rs::dkg", height, ?id, ?receipt, "Neo X DKG receipt requires replacement");
        }
        DkgExecutorOutcome::Confirmed { id, transaction_hash } => {
            info!(target: "neox_rs::dkg", height, ?id, %transaction_hash, "Confirmed Neo X DKG transaction");
        }
        DkgExecutorOutcome::ReceiptCheckFailed { id, error } => {
            warn!(target: "neox_rs::dkg", height, ?id, %error, "Neo X DKG receipt lookup failed; replacement scheduled");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, Address};
    use futures::stream;
    use reth_neox_antimev::{DkgMessagePrivateKey, DkgPolynomial, G1_EIP2537_LEN};
    use reth_neox_node::{DkgStoredContribution, DkgStoredRecovery};
    use reth_transaction_pool::noop::NoopTransactionPool;

    const MESSAGE_KEY: [u8; 65] = hex!(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
         483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );

    fn plan(method: DkgContractMethod, recovery_indices: Vec<u64>) -> DkgTaskPlan {
        DkgTaskPlan {
            round: 2,
            method,
            sender_index: 1,
            send_height: 100,
            end_height: 200,
            recovery_indices,
        }
    }

    fn schedule(epoch_start: u64, epoch_duration: u64) -> DkgSchedule {
        DkgSchedule::new(epoch_start, epoch_duration, 100).unwrap()
    }

    fn contribution(round: u64, sender_index: u64) -> DkgStoredContribution {
        DkgStoredContribution { round, sender_index, pvss: Bytes::new(), messages: Vec::new() }
    }

    fn test_store() -> DkgKeyStore {
        let mut encoded = [0_u8; 32];
        encoded[31] = 9;
        DkgKeyStore::new(DkgMessagePrivateKey::new(encoded).unwrap())
    }

    fn global_commitment(round: u64) -> [u8; G1_EIP2537_LEN] {
        let mut source = [0_u8; 32];
        source[31] = 17;
        DkgPolynomial::deterministic(&source, U256::from(47_763), round).unwrap().commitment()
            [..G1_EIP2537_LEN]
            .try_into()
            .unwrap()
    }

    #[tokio::test]
    async fn initial_reconciliation_wakes_for_progress_maintenance_and_closure() {
        let mut canonical = stream::iter([true]);
        assert!(matches!(
            wait_for_initial_reconciliation_wakeup(&mut canonical, Duration::from_secs(60)).await,
            InitialReconciliationWakeup::Canonical(true)
        ));

        let mut idle = stream::pending::<bool>();
        assert!(matches!(
            wait_for_initial_reconciliation_wakeup(&mut idle, Duration::ZERO).await,
            InitialReconciliationWakeup::Maintenance
        ));

        let mut closed = stream::empty::<bool>();
        assert!(matches!(
            wait_for_initial_reconciliation_wakeup(&mut closed, Duration::from_secs(60)).await,
            InitialReconciliationWakeup::Closed
        ));
    }

    fn empty_canonical_round(round: u64) -> (DkgCanonicalRound, DkgCanonicalEpoch) {
        (
            DkgCanonicalRound { round, shares: Vec::new(), reshares: Vec::new() },
            DkgCanonicalEpoch {
                round,
                self_pvss: None,
                aggregated_commitment: Some(global_commitment(round)),
                previous_commitment: (round > 1).then(|| global_commitment(round - 1)),
            },
        )
    }

    #[test]
    fn epoch_task_reset_tracks_membership_without_invalidating_settled_signer() {
        let mut machine = DkgRuntimeMachine::new(47763).unwrap();
        let first_schedule = schedule(10, 600);
        assert_eq!(machine.membership, None);
        assert_eq!(machine.signer_installation, None);
        machine
            .reset_epoch_task_work(47763, Some((first_schedule, 2)), (Some(1), Some(2)))
            .unwrap();
        assert_eq!(machine.epoch, Some((first_schedule, 2)));
        assert_eq!(machine.membership, Some((Some(1), Some(2))));
        machine.signer_installation = Some((2, Some(1), B256::repeat_byte(1)));
        machine
            .reset_epoch_task_work(47763, Some((schedule(10, 700), 3)), (Some(2), Some(1)))
            .unwrap();
        assert_eq!(machine.membership, Some((Some(2), Some(1))));
        assert_eq!(machine.signer_installation, Some((2, Some(1), B256::repeat_byte(1))));
    }

    #[test]
    fn task_suspension_preserves_settled_signer_state() {
        let mut machine = DkgRuntimeMachine::new(47_763).unwrap();
        let signer_installation = (2, Some(1), B256::repeat_byte(1));
        let settled =
            DkgSettledCanonical { round: 2, current_index: Some(1), pvss: None, epoch: None };
        machine.signer_installation = Some(signer_installation);
        machine.settled_canonical = Some(settled.clone());
        machine.active_canonical =
            Some(DkgCanonicalRound { round: 3, shares: Vec::new(), reshares: Vec::new() });

        machine.suspend_task_work(47_763).unwrap();

        assert_eq!(machine.signer_installation, Some(signer_installation));
        assert_eq!(machine.settled_canonical, Some(settled));
        assert_eq!(machine.active_canonical, None);
    }

    #[test]
    fn canonical_zk_version_requires_an_exact_configured_match() {
        assert_eq!(check_dkg_zk_version(1, Ok::<_, &str>(1)), Ok(()));

        let mismatch = check_dkg_zk_version(1, Ok::<_, &str>(0)).unwrap_err();
        assert!(mismatch.contains("configured Neo X DKG ZK version 1"));
        assert!(mismatch.contains("ZK_VERSION() 0"));

        assert_eq!(
            check_dkg_zk_version(1, Err::<u64, _>("getter failed")),
            Err("getter failed".to_owned())
        );
    }

    #[test]
    fn pending_validator_message_key_must_match_local_identity() {
        let mut other = MESSAGE_KEY;
        other[64] ^= 1;
        let keys = [other, MESSAGE_KEY];

        assert_eq!(check_pending_message_key(Some(2), &keys, MESSAGE_KEY), Ok(()));
        assert!(check_pending_message_key(Some(1), &keys, MESSAGE_KEY)
            .unwrap_err()
            .contains("does not match"));
        assert!(check_pending_message_key(Some(0), &keys, MESSAGE_KEY)
            .unwrap_err()
            .contains("invalid pending validator index"));
        assert!(check_pending_message_key(Some(3), &keys, MESSAGE_KEY)
            .unwrap_err()
            .contains("has no canonical DKG message key"));
        assert_eq!(check_pending_message_key(None, &keys, MESSAGE_KEY), Ok(()));
    }

    #[test]
    fn canonical_task_inputs_bind_ordered_recipients_and_keys() {
        let base = DkgTaskInputSnapshot {
            pending: vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)],
            message_public_keys: vec![MESSAGE_KEY, MESSAGE_KEY],
        };
        let mut changed = base.clone();
        changed.pending.swap(0, 1);
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.message_public_keys[1][64] ^= 1;
        assert_ne!(base, changed);
    }

    #[test]
    fn recovery_plan_requires_exact_indices_for_stable_calldata() {
        assert!(!recovery_plan_inputs_detached(&[2, 7], &[2, 7]));
        assert!(recovery_plan_inputs_detached(&[2, 7], &[7]));
        assert!(recovery_plan_inputs_detached(&[2, 7], &[]));
        assert!(recovery_plan_inputs_detached(&[2], &[2, 7]));
        assert!(recovery_plan_inputs_detached(&[2, 7], &[3, 7]));
    }

    #[test]
    fn canonical_snapshot_regressions_are_detected_but_additions_are_not() {
        let prior = DkgCanonicalRound {
            round: 3,
            shares: vec![contribution(3, 2)],
            reshares: vec![contribution(3, 4)],
        };
        let added = DkgCanonicalRound {
            round: 3,
            shares: vec![contribution(3, 2), contribution(3, 3)],
            reshares: vec![contribution(3, 4)],
        };
        let removed =
            DkgCanonicalRound { round: 3, shares: Vec::new(), reshares: vec![contribution(3, 4)] };
        assert!(!canonical_round_regressed(&prior, &added));
        assert!(canonical_round_regressed(&prior, &removed));

        let recovery = |sender_index| DkgStoredRecovery {
            round: 3,
            sender_index,
            recipient_index: 2,
            message: Bytes::from(vec![sender_index as u8]),
        };
        let prior_recovery = DkgCanonicalRecovery {
            round: 3,
            recipient_index: 2,
            source_share: contribution(2, 2),
            messages: vec![recovery(1)],
        };
        let added_recovery = DkgCanonicalRecovery {
            messages: vec![recovery(1), recovery(3)],
            ..prior_recovery.clone()
        };
        let removed_recovery =
            DkgCanonicalRecovery { messages: Vec::new(), ..prior_recovery.clone() };
        assert!(!canonical_recovery_regressed(&prior_recovery, &added_recovery));
        assert!(canonical_recovery_regressed(&prior_recovery, &removed_recovery));
    }

    #[test]
    fn canonical_contributions_identify_only_local_completed_tasks() {
        let canonical = DkgCanonicalRound {
            round: 3,
            shares: vec![contribution(3, 4), contribution(3, 7)],
            reshares: vec![contribution(3, 2), contribution(3, 4)],
        };
        let tasks = canonical_contribution_tasks(Some(2), Some(4), &canonical);

        assert_eq!(
            tasks,
            HashSet::from([
                DkgTaskId { round: 3, method: DkgContractMethod::Share, sender_index: 4 },
                DkgTaskId { round: 3, method: DkgContractMethod::Reshare, sender_index: 2 },
                DkgTaskId {
                    round: 3,
                    method: DkgContractMethod::ReshareRecovered,
                    sender_index: 4,
                },
            ])
        );
    }

    #[test]
    fn canonical_completion_defers_nonce_and_ownership_release_until_fenced() {
        let mut machine = DkgRuntimeMachine::new(47_763).unwrap();
        let task = plan(DkgContractMethod::Share, Vec::new());
        let id = DkgTaskId::from(&task);
        machine.executor.enqueue([task]);
        machine
            .transactions
            .build(
                id,
                Bytes::from_static(&[1, 2, 3, 4]),
                DkgTransactionInputs {
                    on_chain_nonce: 0,
                    base_fee_per_gas: 1,
                    minimum_priority_fee_per_gas: 1,
                },
                |_| false,
            )
            .unwrap();
        machine.owned_transactions.insert(id, vec![B256::repeat_byte(0x11)]);

        retire_canonical_task(&NoopTransactionPool::default(), &mut machine, id, 101);

        assert!(machine.executor.is_empty());
        assert!(machine.transactions.reservation(id).is_some());
        assert!(machine.owned_transactions.contains_key(&id));
        assert!(machine.pending_transaction_releases.contains(&id));

        commit_transaction_releases(&NoopTransactionPool::default(), &mut machine);

        assert_eq!(machine.transactions.reservation(id), None);
        assert!(!machine.owned_transactions.contains_key(&id));
        assert!(!machine.pending_transaction_releases.contains(&id));
    }

    #[test]
    fn canonical_invalidation_drains_every_owned_submission_hash() {
        let mut machine = DkgRuntimeMachine::new(47_763).unwrap();
        let id = DkgTaskId::from(&plan(DkgContractMethod::Share, Vec::new()));
        let first = B256::repeat_byte(0x11);
        let replacement = B256::repeat_byte(0x22);
        machine.owned_transactions.insert(id, vec![first, replacement]);
        machine.stage_transaction_release(id);

        let mut drained = machine.drain_owned_transactions();
        drained.sort_unstable();

        let mut expected = vec![first, replacement];
        expected.sort_unstable();
        assert_eq!(drained, expected);
        assert!(machine.owned_transactions.is_empty());
        assert!(machine.pending_transaction_releases.is_empty());
    }

    #[test]
    fn changed_empty_recovery_snapshot_still_requires_persistence() {
        assert!(recovery_replay_requires_persistence(true, false));
        assert!(recovery_replay_requires_persistence(false, true));
        assert!(!recovery_replay_requires_persistence(false, false));
    }

    #[test]
    fn retries_signer_installation_after_round_or_membership_changes() {
        let head = B256::repeat_byte(1);
        assert!(signer_installation_needed(None, 2, Some(1), head));
        assert!(!signer_installation_needed(Some((2, Some(1), head)), 2, Some(1), head));
        assert!(signer_installation_needed(Some((1, Some(1), head)), 2, Some(1), head,));
        assert!(signer_installation_needed(Some((2, Some(1), head)), 2, None, head));
        assert!(signer_installation_needed(
            Some((2, Some(1), head)),
            2,
            Some(1),
            B256::repeat_byte(2),
        ));
    }

    #[test]
    fn rebuilds_settled_store_that_is_ahead_after_rollback() {
        let initial = test_store();
        let (round_two, epoch_two) = empty_canonical_round(2);
        let source = rebuild_settled_store(&initial, 47_763, None, &round_two, &epoch_two).unwrap();
        assert_eq!(source.round(), 2);

        let (round_one, epoch_one) = empty_canonical_round(1);
        let rebuilt = rebuild_settled_store(&source, 47_763, None, &round_one, &epoch_one).unwrap();

        assert_eq!(source.round(), 2);
        assert_eq!(rebuilt.round(), 1);
        assert_eq!(rebuilt.message_public_key(), source.message_public_key());
    }

    #[test]
    fn rebuilds_settled_store_that_is_multiple_rounds_behind() {
        let source = test_store();
        let (round_three, epoch_three) = empty_canonical_round(3);
        let rebuilt =
            rebuild_settled_store(&source, 47_763, None, &round_three, &epoch_three).unwrap();

        assert_eq!(source.round(), 0);
        assert_eq!(rebuilt.round(), 3);
        assert_eq!(rebuilt.message_public_key(), source.message_public_key());
    }

    #[test]
    fn preserves_contract_recipient_order_for_full_and_recovery_tasks() {
        let keys = [MESSAGE_KEY; reth_neox_chainspec::NEOX_VALIDATOR_COUNT];
        let full = recipients_for_plan(&plan(DkgContractMethod::Share, Vec::new()), &keys).unwrap();
        assert_eq!(
            full.iter().map(DkgRecipient::index).collect::<Vec<_>>(),
            (1..=7).collect::<Vec<_>>()
        );

        let recovered =
            recipients_for_plan(&plan(DkgContractMethod::Recover, vec![7, 2]), &keys).unwrap();
        assert_eq!(recovered.iter().map(DkgRecipient::index).collect::<Vec<_>>(), vec![7, 2]);
    }

    #[test]
    fn derives_one_based_validator_index_from_governance_order() {
        let first = Address::repeat_byte(0x11);
        let second = Address::repeat_byte(0x22);
        assert_eq!(validator_index(&[first, second], first), Some(1));
        assert_eq!(validator_index(&[first, second], second), Some(2));
        assert_eq!(validator_index(&[first, second], Address::ZERO), None);
    }
}
