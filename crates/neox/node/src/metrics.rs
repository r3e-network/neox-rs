//! Operational metrics for Neo X synchronization and dBFT consensus.

use reth_metrics::{
    metrics::{Counter, Gauge, Histogram},
    Metrics,
};

/// Metrics emitted by the long-lived Neo X synchronization driver.
#[derive(Metrics)]
#[metrics(scope = "neox.sync")]
pub(crate) struct NeoXSyncMetrics {
    /// Current canonical Neo X block height.
    pub(crate) canonical_height: Gauge,
    /// Number of negotiated Neo X beacon peers.
    pub(crate) beacon_peers: Gauge,
    /// Number of negotiated Neo X dBFT peers.
    pub(crate) dbft_peers: Gauge,
    /// Total validated beacon protocol events delivered to the sync driver.
    pub(crate) beacon_events_total: Counter,
    /// Total validated dBFT protocol events delivered to the consensus driver.
    pub(crate) dbft_events_total: Counter,
    /// Total authenticated dBFT state transitions accepted by the active round.
    pub(crate) dbft_transitions_accepted_total: Counter,
    /// Total authenticated dBFT view changes accepted by the active round.
    pub(crate) dbft_view_changes_total: Counter,
    /// Total authenticated dBFT messages ignored after their round became stale.
    pub(crate) dbft_transitions_stale_total: Counter,
    /// Total dBFT state transitions or peer messages rejected as invalid.
    pub(crate) dbft_transitions_rejected_total: Counter,
    /// Total authenticated dBFT messages cached for a height or view the round has not reached.
    pub(crate) dbft_messages_deferred_total: Counter,
    /// Total cached dBFT messages replayed once the round reached their height and view.
    pub(crate) dbft_messages_replayed_total: Counter,
    /// Number of dBFT messages currently held for a future height or view.
    pub(crate) dbft_messages_cached: Gauge,
    /// Total canonical commit and reorg notifications processed.
    pub(crate) canonical_updates_total: Counter,
    /// Total canonical reorg notifications processed.
    pub(crate) canonical_reorgs_total: Counter,
    /// Total propagated blocks dropped for lagging too far behind the local head.
    pub(crate) propagated_blocks_dropped_total: Counter,
}

/// Metrics emitted by the validator-only canonical DKG runtime.
#[derive(Metrics)]
#[metrics(scope = "neox.dkg")]
pub struct NeoXDkgMetrics {
    /// Number of canonical heartbeat reconciliations.
    pub canonical_reconciliations_total: Counter,
    /// Number of heartbeats triggered by a canonical reorganization.
    pub canonical_reorgs_total: Counter,
    /// Number of governance validator membership/index changes observed.
    pub validator_set_changes_total: Counter,
    /// Number of tasks added to the execution queue.
    pub tasks_queued_total: Counter,
    /// Number of successful material/proof preparations.
    pub task_preparations_total: Counter,
    /// Number of material/proof preparation attempts.
    pub prover_attempts_total: Counter,
    /// Number of material/proof preparation failures.
    pub task_preparation_failures_total: Counter,
    /// Number of transactions accepted by the local pool.
    pub submissions_total: Counter,
    /// Number of signing or pool-submission failures.
    pub submission_failures_total: Counter,
    /// Number of canonical receipt checks.
    pub receipt_checks_total: Counter,
    /// Number of receipt RPC/provider failures.
    pub receipt_check_failures_total: Counter,
    /// Number of missing or reverted receipts that caused replacements.
    pub replacements_total: Counter,
    /// Number of successful DKG transaction receipts.
    pub confirmed_total: Counter,
    /// Number of tasks that expired before confirmation.
    pub expired_total: Counter,
    /// Wall-clock duration of external prover attempts, in seconds.
    pub prover_duration_seconds: Histogram,
    /// Current canonical DKG round observed by the runtime.
    pub current_round: Gauge,
    /// Number of tasks still queued or awaiting confirmation.
    pub queued_tasks: Gauge,
}
