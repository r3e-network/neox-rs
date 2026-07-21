//! Local dBFT timer ownership and Geth-compatible timeout policy.

use crate::{DbftRoundState, DbftSigner};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DbftTimeout {
    pub(super) height: u64,
    pub(super) view: u8,
    generation: u64,
}

/// Owns the active dBFT timeout token, timeout policy, and delivery channel.
///
/// Tokio sleep tasks are not synchronously cancelled when a round changes. Instead, each arm or
/// disarm advances a generation and [`Self::consume`] accepts only the currently active token.
#[derive(Debug)]
pub(super) struct DbftTimer {
    block_period: Duration,
    generation: u64,
    armed: Option<DbftTimeout>,
    timeouts: mpsc::UnboundedSender<DbftTimeout>,
}

impl DbftTimer {
    pub(super) fn channel(block_period: Duration) -> (Self, mpsc::UnboundedReceiver<DbftTimeout>) {
        let (timeouts, receiver) = mpsc::unbounded_channel();
        (Self { block_period, generation: 0, armed: None, timeouts }, receiver)
    }

    pub(super) fn reset(&mut self, round: Option<&DbftRoundState>, signer: Option<&DbftSigner>) {
        let (Some(round), Some(signer)) = (round, signer) else {
            self.disarm();
            return
        };
        let Some(local_index) = signer.validator_index(round.validators()) else {
            self.disarm();
            return
        };
        let view = round.current_view();
        let is_primary = usize::from(local_index) == round.primary_index(view);
        self.arm(round.height(), view, round_timeout(self.block_period, view, is_primary));
    }

    pub(super) fn arm_post_proposal(&mut self, height: u64, view: u8) {
        self.arm(height, view, post_proposal_timeout(self.block_period, view));
    }

    pub(super) fn arm_recovery(&mut self, height: u64, view: u8) {
        self.arm(height, view, scaled_block_period(self.block_period, 1));
    }

    pub(super) fn arm_change_view(&mut self, height: u64, view: u8, new_view: u8) {
        self.arm(height, view, change_view_timeout(self.block_period, new_view));
    }

    pub(super) const fn disarm(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.armed = None;
    }

    pub(super) fn consume(&mut self, timeout: DbftTimeout) -> bool {
        if self.armed != Some(timeout) {
            return false
        }
        self.armed = None;
        true
    }

    fn arm(&mut self, height: u64, view: u8, delay: Duration) {
        self.generation = self.generation.wrapping_add(1);
        let timeout = DbftTimeout { height, view, generation: self.generation };
        self.armed = Some(timeout);
        let timeouts = self.timeouts.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = timeouts.send(timeout);
        });
        debug!(
            target: "neox::validator",
            block_number = height,
            view,
            ?delay,
            generation = timeout.generation,
            "Armed local Neo X dBFT timer"
        );
    }
}

fn round_timeout(block_period: Duration, view: u8, is_primary: bool) -> Duration {
    if is_primary {
        if view == 0 {
            block_period
        } else {
            Duration::ZERO
        }
    } else {
        scaled_block_period(block_period, u32::from(view) + 1)
    }
}

fn post_proposal_timeout(block_period: Duration, view: u8) -> Duration {
    let delay = scaled_block_period(block_period, u32::from(view) + 1);
    if view == 0 {
        delay.saturating_sub(block_period)
    } else {
        delay
    }
}

fn change_view_timeout(block_period: Duration, new_view: u8) -> Duration {
    scaled_block_period(block_period, u32::from(new_view) + 1)
}

fn scaled_block_period(block_period: Duration, exponent: u32) -> Duration {
    let Some(multiplier) = 1_u32.checked_shl(exponent) else { return Duration::MAX };
    block_period.checked_mul(multiplier).unwrap_or(Duration::MAX)
}

#[cfg(test)]
mod tests {
    use super::{change_view_timeout, post_proposal_timeout, round_timeout, DbftTimer};
    use std::time::Duration;

    #[test]
    fn round_timeouts_match_geth_roles() {
        let period = Duration::from_secs(5);
        assert_eq!(round_timeout(period, 0, true), Duration::from_secs(5));
        assert_eq!(round_timeout(period, 0, false), Duration::from_secs(10));
        assert_eq!(round_timeout(period, 1, true), Duration::ZERO);
        assert_eq!(round_timeout(period, 1, false), Duration::from_secs(20));
    }

    #[test]
    fn post_proposal_timeout_matches_geth() {
        let period = Duration::from_secs(5);
        assert_eq!(post_proposal_timeout(period, 0), Duration::from_secs(5));
        assert_eq!(post_proposal_timeout(period, 1), Duration::from_secs(20));
        assert_eq!(post_proposal_timeout(period, 2), Duration::from_secs(40));
    }

    #[test]
    fn change_view_timeout_uses_new_view_exponent() {
        let period = Duration::from_secs(5);
        assert_eq!(change_view_timeout(period, 1), Duration::from_secs(20));
        assert_eq!(change_view_timeout(period, 2), Duration::from_secs(40));
    }

    #[tokio::test]
    async fn rearming_and_disarming_invalidate_stale_tokens() {
        let (mut timer, _timeouts) = DbftTimer::channel(Duration::from_secs(60));
        timer.arm_post_proposal(42, 0);
        let first = timer.armed.expect("first timeout should be armed");

        timer.arm_post_proposal(42, 1);
        let second = timer.armed.expect("second timeout should be armed");
        assert!(!timer.consume(first));
        assert!(timer.consume(second));

        timer.arm_recovery(42, 1);
        let disarmed = timer.armed.expect("recovery timeout should be armed");
        timer.disarm();
        assert!(!timer.consume(disarmed));
    }
}
