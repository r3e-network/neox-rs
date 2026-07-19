//! Canonical-block validator DKG runtime for the Neo X full-node executable.

use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_primitives::{Bytes, U256};
use futures::{Stream, StreamExt};
use reth_chain_state::CanonStateNotification;
use reth_ethereum_primitives::{EthPrimitives, Receipt, TransactionSigned};
use reth_neox_antimev::{DkgEpochChange, DkgKeyStore};
use reth_neox_evm::{
    policy_storage_key, POLICY_BASE_FEE_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
};
use reth_neox_node::{
    apply_dkg_canonical_epoch, apply_dkg_canonical_recovery, apply_dkg_canonical_round,
    generate_dkg_task_material, prove_dkg_task_material, read_dkg_canonical_epoch,
    read_dkg_canonical_recovery, read_dkg_canonical_round, read_dkg_message_public_keys,
    read_dkg_schedule, read_dkg_task_contract_state, read_governance_pending_validators,
    read_governance_validator_set, rebuild_dkg_canonical_round, submit_dkg_pool_transaction,
    DbftSigner, DkgContractMethod, DkgExecutorAction, DkgExecutorOutcome, DkgProver, DkgRecipient,
    DkgTaskContext, DkgTaskExecutor, DkgTaskId, DkgTaskPlan, DkgTaskPlanner, DkgTransactionBuilder,
    DkgTransactionInputs, NeoXDkgMetrics,
};
use reth_provider::{BlockReaderIdExt, ReceiptProvider, StateProvider, StateProviderFactory};
use reth_transaction_pool::{PoolTransaction, PoolTx, TransactionPool};
use std::{path::PathBuf, time::Instant};
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

    fn install_signer_shares(&self) -> eyre::Result<()> {
        let current = self.store.current_private_share().map(|share| *share.as_bytes());
        let previous = self.store.previous_private_share().map(|share| *share.as_bytes());
        self.signer.replace_optional_dkg_private_shares(current, previous)?;
        Ok(())
    }
}

struct DkgRuntimeMachine {
    epoch: Option<(u64, u64)>,
    membership: Option<(Option<u64>, Option<u64>)>,
    planner: DkgTaskPlanner,
    executor: DkgTaskExecutor,
    transactions: DkgTransactionBuilder,
}

impl DkgRuntimeMachine {
    fn new(chain_id: u64) -> eyre::Result<Self> {
        Ok(Self {
            epoch: None,
            membership: None,
            planner: DkgTaskPlanner::default(),
            executor: DkgTaskExecutor::default(),
            transactions: DkgTransactionBuilder::new(chain_id)?,
        })
    }

    fn reset(
        &mut self,
        chain_id: u64,
        epoch: Option<(u64, u64)>,
        membership: (Option<u64>, Option<u64>),
    ) -> eyre::Result<()> {
        self.epoch = epoch;
        self.membership = Some(membership);
        self.planner = DkgTaskPlanner::default();
        self.executor = DkgTaskExecutor::default();
        self.transactions = DkgTransactionBuilder::new(chain_id)?;
        Ok(())
    }
}

/// Runs the validator-only DKG service until the canonical notification stream closes.
pub(crate) async fn run_dkg_runtime<Provider, Pool, Notifications>(
    provider: Provider,
    pool: Pool,
    mut config: DkgRuntimeConfig,
    mut canonical: Notifications,
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
    let mut machine = match DkgRuntimeMachine::new(config.chain_id) {
        Ok(machine) => machine,
        Err(error) => {
            error!(target: "neox_reth::dkg", %error, "Invalid Neo X DKG runtime configuration");
            return
        }
    };

    match provider.latest_header() {
        Ok(Some(header)) => {
            if let Err(error) = heartbeat(
                &provider,
                &pool,
                &mut config,
                &mut machine,
                &metrics,
                header.number(),
                true,
            )
            .await
            {
                warn!(target: "neox_reth::dkg", %error, "Initial Neo X DKG reconciliation failed");
            }
        }
        Ok(None) => {
            warn!(target: "neox_reth::dkg", "Cannot initialize DKG runtime without a canonical header")
        }
        Err(error) => {
            warn!(target: "neox_reth::dkg", %error, "Failed to read canonical header for DKG runtime")
        }
    }

    while let Some(notification) = canonical.next().await {
        let reorg = matches!(notification, CanonStateNotification::Reorg { .. });
        let height = if let Some(tip) = notification.tip_checked() {
            tip.number()
        } else {
            match provider.latest_header() {
                Ok(Some(header)) => header.number(),
                Ok(None) => continue,
                Err(error) => {
                    warn!(target: "neox_reth::dkg", %error, "Failed to read DKG height after canonical revert");
                    continue
                }
            }
        };
        if let Err(error) =
            heartbeat(&provider, &pool, &mut config, &mut machine, &metrics, height, reorg).await
        {
            warn!(target: "neox_reth::dkg", height, reorg, %error, "Neo X DKG heartbeat failed");
        }
    }
    warn!(target: "neox_reth::dkg", "Neo X DKG canonical notification stream closed");
}

async fn heartbeat<Provider, Pool>(
    provider: &Provider,
    pool: &Pool,
    config: &mut DkgRuntimeConfig,
    machine: &mut DkgRuntimeMachine,
    metrics: &NeoXDkgMetrics,
    height: u64,
    reorg: bool,
) -> eyre::Result<()>
where
    Provider: BlockReaderIdExt<Header = Header>
        + ReceiptProvider<Receipt = Receipt>
        + StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    metrics.canonical_reconciliations_total.increment(1);
    if reorg {
        metrics.canonical_reorgs_total.increment(1);
    }
    let state = provider.latest()?;
    let schedule = read_dkg_schedule(state.as_ref())?;
    let contract = read_dkg_task_contract_state(state.as_ref())?;
    let current = read_governance_validator_set(state.as_ref())?.original;
    let pending = read_governance_pending_validators(state.as_ref())?;
    let current_index = validator_index(&current, config.signer.account());
    let pending_index = validator_index(&pending, config.signer.account());
    let membership = (current_index, pending_index);

    reconcile_settled_round(state.as_ref(), config, contract.current_round, current_index)?;

    let epoch = (schedule.epoch_start, contract.next_round);
    metrics.current_round.set(contract.next_round as f64);
    let membership_changed = machine.membership.is_some_and(|previous| previous != membership);
    if membership_changed {
        metrics.validator_set_changes_total.increment(1);
    }
    if reorg || machine.epoch != Some(epoch) || machine.membership != Some(membership) {
        machine.reset(config.chain_id, Some(epoch), membership)?;
        info!(target: "neox_reth::dkg", height, reorg, current_index = ?current_index, pending_index = ?pending_index, round = contract.next_round, "Reset Neo X DKG canonical runtime state");
    }

    let active = height >= schedule.share_start && height < schedule.target;
    if active {
        let canonical = read_dkg_canonical_round(state.as_ref(), contract.next_round)?;
        let replay = if reorg || !config.store.is_sharing() {
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
            debug!(target: "neox_reth::dkg", round = contract.next_round, shares = replay.shares_received, reshares = replay.reshares_received, "Persisted canonical Neo X DKG replay");
        }

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
                    contract.next_round,
                    pending_index.expect("membership checked above"),
                )?;
                let replay = apply_dkg_canonical_recovery(&mut config.store, &recovery)?;
                if replay.store_changed {
                    config.persist()?;
                    debug!(target: "neox_reth::dkg", round = contract.next_round, recoveries = replay.recoveries_received, "Persisted canonical Neo X DKG recovery replay");
                }
            }
        }
    } else if config.store.is_sharing() {
        config.store.revert_round();
        config.persist()?;
        machine.reset(config.chain_id, Some(epoch), membership)?;
        info!(target: "neox_reth::dkg", round = contract.next_round, "Discarded unfinished Neo X DKG round outside its canonical window");
    }

    let tasks = machine.planner.take_tasks(DkgTaskContext {
        schedule,
        current_height: height,
        next_round: contract.next_round,
        current_index,
        pending_index,
        share_ready: contract.share_ready,
        recovery_indices: &contract.recovery_indices,
    })?;
    let inserted = machine.executor.enqueue(tasks);
    if inserted > 0 {
        metrics.tasks_queued_total.increment(inserted as u64);
        info!(target: "neox_reth::dkg", height, inserted, round = contract.next_round, "Queued Neo X DKG validator tasks");
    }

    let actions = machine.executor.actions(height);
    for action in actions {
        handle_action(provider, pool, config, machine, metrics, &pending, height, action).await?;
    }
    metrics.queued_tasks.set(machine.executor.len() as f64);
    Ok(())
}

fn reconcile_settled_round(
    state: &dyn StateProvider,
    config: &mut DkgRuntimeConfig,
    contract_round: u64,
    current_index: Option<u64>,
) -> eyre::Result<()> {
    let local_round = config.store.round();
    if local_round > contract_round {
        eyre::bail!(
            "encrypted DKG keystore round {local_round} is ahead of canonical round {contract_round}"
        )
    }
    if local_round == contract_round {
        return Ok(())
    }
    if local_round.checked_add(1) != Some(contract_round) {
        eyre::bail!(
            "encrypted DKG keystore round {local_round} is more than one round behind canonical round {contract_round}"
        )
    }

    let canonical = read_dkg_canonical_round(state, contract_round)?;
    rebuild_dkg_canonical_round(
        &mut config.store,
        U256::from(config.chain_id),
        current_index,
        &canonical,
    )?;
    config.persist()?;
    let epoch = read_dkg_canonical_epoch(state, contract_round, current_index)?;
    let change = apply_dkg_canonical_epoch(&mut config.store, current_index.is_some(), &epoch)?;
    if change != (DkgEpochChange::Advanced { round: contract_round }) {
        eyre::bail!("canonical DKG round {contract_round} has no aggregate commitment")
    }
    config.persist()?;
    config.install_signer_shares()?;
    info!(target: "neox_reth::dkg", round = contract_round, member = current_index.is_some(), "Installed canonical Neo X DKG epoch shares");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_action<Provider, Pool>(
    provider: &Provider,
    pool: &Pool,
    config: &mut DkgRuntimeConfig,
    machine: &mut DkgRuntimeMachine,
    metrics: &NeoXDkgMetrics,
    pending: &[alloy_primitives::Address],
    height: u64,
    action: DkgExecutorAction,
) -> eyre::Result<()>
where
    Provider: ReceiptProvider<Receipt = Receipt> + StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    match action {
        DkgExecutorAction::Prepare { id, plan } => {
            metrics.prover_attempts_total.increment(1);
            let started = Instant::now();
            let result = prepare_task(provider, config, pending, &plan).await;
            metrics.prover_duration_seconds.record(started.elapsed().as_secs_f64());
            let outcome =
                machine.executor.record_prepared(id, result.map_err(|error| error.to_string()))?;
            record_outcome(metrics, &outcome);
            log_outcome(height, outcome);
        }
        DkgExecutorAction::Submit { id, calldata, .. } => {
            let result = build_and_submit(provider, pool, config, machine, id, calldata).await;
            let outcome = machine.executor.record_submitted(
                id,
                height,
                result.map_err(|error| error.to_string()),
            )?;
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
                machine.transactions.release(id);
            }
            log_outcome(height, outcome);
        }
        DkgExecutorAction::Expire { id } => {
            machine.transactions.release(id);
            metrics.expired_total.increment(1);
            warn!(target: "neox_reth::dkg", height, ?id, "Neo X DKG task expired before confirmation");
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

async fn prepare_task<Provider>(
    provider: &Provider,
    config: &mut DkgRuntimeConfig,
    pending: &[alloy_primitives::Address],
    plan: &DkgTaskPlan,
) -> eyre::Result<Bytes>
where
    Provider: StateProviderFactory,
{
    let state = provider.latest()?;
    let keys = read_dkg_message_public_keys(state.as_ref(), pending)?;
    let recipients = recipients_for_plan(plan, &keys)?;
    let material = generate_dkg_task_material(
        &mut config.store,
        config.signer.account(),
        U256::from(config.chain_id),
        plan,
        recipients,
    )?;
    if material.must_persist_store() {
        config.persist()?;
    }
    Ok(prove_dkg_task_material(&config.prover, config.zk_version, material).await?)
}

fn recipients_for_plan(plan: &DkgTaskPlan, keys: &[[u8; 65]]) -> eyre::Result<Vec<DkgRecipient>> {
    if keys.len() != reth_neox_chainspec::NEOX_VALIDATOR_COUNT {
        eyre::bail!("pending validator message-key count is {}, expected 7", keys.len())
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
    id: DkgTaskId,
    calldata: Bytes,
) -> eyre::Result<alloy_primitives::B256>
where
    Provider: StateProviderFactory,
    Pool: TransactionPool,
    PoolTx<Pool>: PoolTransaction<Consensus = TransactionSigned>,
{
    let state = provider.latest()?;
    let on_chain_nonce = state
        .basic_account(&config.signer.account())?
        .map(|account| account.nonce)
        .unwrap_or_default();
    let base_fee_per_gas = read_policy_u128(state.as_ref(), POLICY_BASE_FEE_SLOT)?;
    let minimum_priority_fee_per_gas =
        read_policy_u128(state.as_ref(), POLICY_MIN_GAS_TIP_CAP_SLOT)?;
    let inputs =
        DkgTransactionInputs { on_chain_nonce, base_fee_per_gas, minimum_priority_fee_per_gas };
    let request = if machine.transactions.reservation(id).is_some() {
        machine.transactions.bump(id, calldata, inputs)?
    } else {
        machine.transactions.build(id, calldata, inputs, |nonce| {
            pool.get_transaction_by_sender_and_nonce(config.signer.account(), nonce).is_some()
        })?
    };
    Ok(submit_dkg_pool_transaction(pool, &config.signer, request).await?)
}

fn read_policy_u128(state: &dyn StateProvider, slot: u64) -> eyre::Result<u128> {
    let value =
        state.storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())?.unwrap_or_default();
    u128::try_from(value).map_err(|_| eyre::eyre!("Neo X Policy slot {slot} exceeds u128"))
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

fn log_outcome(height: u64, outcome: DkgExecutorOutcome) {
    match outcome {
        DkgExecutorOutcome::Prepared { id } => {
            info!(target: "neox_reth::dkg", height, ?id, "Prepared Neo X DKG calldata");
        }
        DkgExecutorOutcome::PreparationFailed { id, error } => {
            warn!(target: "neox_reth::dkg", height, ?id, %error, "Neo X DKG preparation failed; retry scheduled");
        }
        DkgExecutorOutcome::Submitted { id, transaction_hash } => {
            info!(target: "neox_reth::dkg", height, ?id, %transaction_hash, "Submitted Neo X DKG transaction");
        }
        DkgExecutorOutcome::SubmissionFailed { id, error } => {
            warn!(target: "neox_reth::dkg", height, ?id, %error, "Neo X DKG submission failed; replacement scheduled");
        }
        DkgExecutorOutcome::RetryScheduled { id, receipt } => {
            warn!(target: "neox_reth::dkg", height, ?id, ?receipt, "Neo X DKG receipt requires replacement");
        }
        DkgExecutorOutcome::Confirmed { id, transaction_hash } => {
            info!(target: "neox_reth::dkg", height, ?id, %transaction_hash, "Confirmed Neo X DKG transaction");
        }
        DkgExecutorOutcome::ReceiptCheckFailed { id, error } => {
            warn!(target: "neox_reth::dkg", height, ?id, %error, "Neo X DKG receipt lookup failed; replacement scheduled");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, Address};

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

    #[test]
    fn runtime_reset_tracks_validator_membership() {
        let mut machine = DkgRuntimeMachine::new(47763).unwrap();
        assert_eq!(machine.membership, None);
        machine.reset(47763, Some((10, 2)), (Some(1), Some(2))).unwrap();
        assert_eq!(machine.epoch, Some((10, 2)));
        assert_eq!(machine.membership, Some((Some(1), Some(2))));
        machine.reset(47763, Some((10, 3)), (Some(2), Some(1))).unwrap();
        assert_eq!(machine.membership, Some((Some(2), Some(1))));
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
