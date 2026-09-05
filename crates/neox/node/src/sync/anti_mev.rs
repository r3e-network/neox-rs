//! Anti-MEV reconstruction scheduling and attempt ownership.

use crate::{
    reconstruct_antimev_proposal, AntiMevPreBlock, AntiMevReconstruction,
    AntiMevReconstructionError, AntiMevResolutionError, DbftRoundProgress, DbftRoundState,
    DbftStateError, DkgStateError, VerifiedProposal,
};
use alloy_primitives::B256;
use reth_neox_evm::NeoXEvmConfig;
use reth_provider::StateProviderFactory;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub(super) struct AntiMevReconstructionResult {
    pub(super) view: u8,
    pub(super) proposal_hash: B256,
    pub(super) result: Result<AntiMevReconstruction, AntiMevReconstructionTaskError>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AntiMevReconstructionTaskError {
    #[error(transparent)]
    Resolution(#[from] AntiMevResolutionError),
    #[error(transparent)]
    Reconstruction(#[from] AntiMevReconstructionError),
}

impl AntiMevReconstructionTaskError {
    /// Whether the identical inputs may succeed on a later attempt because the failure came from
    /// transient state access rather than from the shares or the proposal itself. Share-set and
    /// proposal failures are deterministic, so only new contributions can change their outcome.
    pub(super) const fn is_transient(&self) -> bool {
        match self {
            Self::Reconstruction(error) => match error {
                AntiMevReconstructionError::Provider(_) => true,
                AntiMevReconstructionError::Governance(error) => {
                    matches!(error, DbftStateError::Provider(_))
                }
                AntiMevReconstructionError::Dkg(error) => {
                    matches!(error, DkgStateError::Provider(_))
                }
                _ => false,
            },
            Self::Resolution(_) => false,
        }
    }
}

/// Transient state failures retry the same share set this many times before the scheduler falls
/// back to waiting for new contributions.
const MAX_TRANSIENT_RETRIES: usize = 5;

/// Base delay for the bounded transient-retry backoff, doubled per consecutive retry.
const TRANSIENT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
struct AntiMevReconstructionAttempt {
    attempted_contributions: usize,
    in_flight: bool,
    /// Whether the last failure was transient, so the same share set may retry.
    retryable: bool,
    transient_retries: usize,
    retry_at: Option<Instant>,
}

impl AntiMevReconstructionAttempt {
    fn begin(&mut self, contribution_count: usize) -> bool {
        if self.in_flight {
            return false
        }
        if contribution_count > self.attempted_contributions {
            self.attempted_contributions = contribution_count;
            self.retryable = false;
            self.transient_retries = 0;
            self.retry_at = None;
            self.in_flight = true;
            return true
        }
        // A failed attempt is only restarted with the identical share set after a transient
        // failure, bounded so a persistently unavailable state service cannot spin the scheduler.
        if self.retryable &&
            self.transient_retries < MAX_TRANSIENT_RETRIES &&
            self.retry_at.is_none_or(|at| Instant::now() >= at)
        {
            self.retryable = false;
            self.transient_retries += 1;
            self.in_flight = true;
            return true
        }
        false
    }

    const fn finish(&mut self) {
        self.in_flight = false;
    }

    /// Marks the finished attempt as retryable with a backoff deadline when its failure was
    /// transient; deterministic failures stay gated on new contributions.
    fn finished_transient(&mut self, transient: bool) {
        self.retryable = transient;
        self.retry_at = transient.then(|| {
            Instant::now() +
                TRANSIENT_RETRY_BACKOFF.saturating_mul(1 << self.transient_retries.min(5))
        });
    }
}

/// Owns background Anti-MEV reconstruction inputs, result correlation, and retry state.
pub(super) struct AntiMevReconstructor<Provider> {
    provider: Provider,
    proposal_evm: NeoXEvmConfig,
    results: mpsc::UnboundedSender<AntiMevReconstructionResult>,
    attempts: HashMap<B256, AntiMevReconstructionAttempt>,
}

impl<Provider> AntiMevReconstructor<Provider> {
    pub(super) fn channel(
        provider: Provider,
        proposal_evm: NeoXEvmConfig,
    ) -> (Self, mpsc::UnboundedReceiver<AntiMevReconstructionResult>) {
        let (results, receiver) = mpsc::unbounded_channel();
        (Self { provider, proposal_evm, results, attempts: HashMap::new() }, receiver)
    }

    pub(super) fn clear(&mut self) {
        self.attempts.clear();
    }

    pub(super) fn finish(&mut self, proposal_hash: B256, transient: bool) {
        if let Some(attempt) = self.attempts.get_mut(&proposal_hash) {
            attempt.finish();
            attempt.finished_transient(transient);
        }
    }

    pub(super) fn attempted_contributions(&self, proposal_hash: B256) -> usize {
        self.attempts.get(&proposal_hash).map_or(0, |attempt| attempt.attempted_contributions)
    }

    pub(super) fn discard(&mut self, proposal_hash: B256) {
        self.attempts.remove(&proposal_hash);
    }
}

impl<Provider> AntiMevReconstructor<Provider>
where
    Provider: StateProviderFactory + Clone + Send + 'static,
{
    pub(super) fn schedule(
        &mut self,
        round: &DbftRoundState,
        view: u8,
        verified_proposals: &HashMap<B256, VerifiedProposal>,
    ) {
        if !round.anti_mev() || round.has_final_header(view) {
            return
        }
        if !matches!(round.progress(view), DbftRoundProgress::PreCommitted { .. }) {
            return
        }
        let Some(proposal_hash) = round.proposal(view).map(|proposal| proposal.hash()) else {
            return
        };
        let Some(dkg_state) = round.dkg_state().cloned() else {
            warn!(target: "neox::validator", view, %proposal_hash, "Cannot reconstruct Anti-MEV block without canonical DKG state");
            return
        };
        let contributions = round
            .pre_commits(view)
            .into_iter()
            .map(|(index, pre_commit)| (index, pre_commit.clone()))
            .collect::<Vec<_>>();
        if contributions.len() < round.quorum() {
            warn!(target: "neox::validator", view, %proposal_hash, contributions = contributions.len(), threshold = round.quorum(), "Anti-MEV share quorum has no complete DKG index mapping");
            return
        }
        let Some(verified) = verified_proposals.get(&proposal_hash).cloned() else {
            debug!(target: "neox::validator", view, %proposal_hash, "Waiting for verified Anti-MEV pre-block before reconstruction");
            return
        };
        let contribution_count = contributions.len();
        let attempt = self.attempts.entry(proposal_hash).or_default();
        if !attempt.begin(contribution_count) {
            return
        }

        let threshold = round.quorum();
        let provider = self.provider.clone();
        let proposal_evm = self.proposal_evm.clone();
        let results = self.results.clone();
        tokio::task::spawn_blocking(move || {
            let result: Result<_, AntiMevReconstructionTaskError> = (|| {
                let anti_mev = verified
                    .anti_mev
                    .as_ref()
                    .ok_or(AntiMevReconstructionError::MissingMetadata)?;
                let contribution_refs = contributions
                    .iter()
                    .map(|(index, pre_commit)| (*index, pre_commit))
                    .collect::<Vec<_>>();
                let resolutions = anti_mev.decrypt_and_validate(
                    &contribution_refs,
                    &dkg_state,
                    threshold,
                    AntiMevPreBlock {
                        transactions: &verified.block.body().transactions,
                        senders: verified.block.senders(),
                        receipts: &verified.execution.result.receipts,
                        parent_base_fee: verified.parent_base_fee,
                    },
                )?;
                Ok(reconstruct_antimev_proposal(verified, resolutions, &provider, &proposal_evm)?)
            })();
            let _ = results.send(AntiMevReconstructionResult { view, proposal_hash, result });
        });
        debug!(target: "neox::validator", view, %proposal_hash, contributions = contribution_count, "Scheduled Neo X Anti-MEV reconstruction attempt");
    }
}

#[cfg(test)]
mod tests {
    use super::{AntiMevReconstructionAttempt, AntiMevReconstructor};
    use alloy_primitives::B256;
    use reth_neox_chainspec::NeoXChainSpec;
    use reth_neox_evm::NeoXEvmConfig;
    use std::time::Instant;

    #[test]
    fn retries_only_after_new_contributions() {
        let mut attempt = AntiMevReconstructionAttempt::default();
        assert!(attempt.begin(5));
        assert!(!attempt.begin(6));
        attempt.finish();
        attempt.finished_transient(false);
        assert!(!attempt.begin(5));
        assert!(attempt.begin(6));
    }

    #[test]
    fn transient_failures_retry_the_same_shares_after_backoff() {
        let mut attempt = AntiMevReconstructionAttempt::default();
        assert!(attempt.begin(7));
        attempt.finish();
        attempt.finished_transient(true);
        // The backoff deadline defers the immediate retry.
        assert!(!attempt.begin(7));
        attempt.retry_at = Some(Instant::now());
        assert!(attempt.begin(7));
        attempt.finish();
        // A deterministic failure returns the gate to new-contributions-only.
        attempt.finished_transient(false);
        assert!(!attempt.begin(7));
        assert!(attempt.begin(8));
    }

    #[test]
    fn transient_retries_are_bounded() {
        let mut attempt = AntiMevReconstructionAttempt::default();
        assert!(attempt.begin(7));
        attempt.finish();
        attempt.finished_transient(true);
        for _ in 0..super::MAX_TRANSIENT_RETRIES {
            attempt.retry_at = Some(Instant::now());
            assert!(attempt.begin(7));
            attempt.finish();
            attempt.finished_transient(true);
        }
        assert!(!attempt.begin(7));
        // New contributions still open a fresh attempt.
        assert!(attempt.begin(8));
    }

    #[test]
    fn clearing_reconstruction_forgets_in_flight_attempts() {
        let proposal_hash = B256::repeat_byte(0x42);
        let proposal_evm = NeoXEvmConfig::new(NeoXChainSpec::mainnet().unwrap());
        let (mut reconstructor, _results) = AntiMevReconstructor::channel((), proposal_evm);
        assert!(reconstructor.attempts.entry(proposal_hash).or_default().begin(5));

        reconstructor.clear();

        assert_eq!(reconstructor.attempted_contributions(proposal_hash), 0);
    }
}
