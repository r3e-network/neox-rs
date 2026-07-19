//! Operational metrics for Neo X synchronization and dBFT consensus.

use reth_metrics::{
    metrics::{Counter, Gauge},
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
    /// Total authenticated dBFT messages ignored after their round became stale.
    pub(crate) dbft_transitions_stale_total: Counter,
    /// Total dBFT state transitions or peer messages rejected as invalid.
    pub(crate) dbft_transitions_rejected_total: Counter,
    /// Total canonical commit and reorg notifications processed.
    pub(crate) canonical_updates_total: Counter,
    /// Total canonical reorg notifications processed.
    pub(crate) canonical_reorgs_total: Counter,
}
