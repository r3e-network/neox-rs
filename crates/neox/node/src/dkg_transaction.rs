//! Per-task DKG transaction nonce reservation and deterministic fee replacement policy.

use crate::{DkgTaskId, DkgTransactionRequest};
use alloy_primitives::Bytes;
use std::collections::HashMap;
use thiserror::Error;

/// Default gas ceiling for proof-verifying `KeyManagement` calls.
pub const DEFAULT_DKG_TRANSACTION_GAS_LIMIT: u64 = 12_000_000;
const FEE_BUMP_DENOMINATOR: u128 = 8;

/// Canonical account and Policy inputs used to price one transaction attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgTransactionInputs {
    /// Current canonical validator-account nonce.
    pub on_chain_nonce: u64,
    /// Next-block Policy base fee.
    pub base_fee_per_gas: u128,
    /// Minimum Policy priority fee.
    pub minimum_priority_fee_per_gas: u128,
}

/// Stable task nonce reservations with explicit same-nonce replacement fee bumps.
#[derive(Debug)]
pub struct DkgTransactionBuilder {
    chain_id: u64,
    gas_limit: u64,
    reservations: HashMap<DkgTaskId, DkgTransactionReservation>,
}

impl DkgTransactionBuilder {
    /// Creates a builder for one chain using the conservative deployed DKG gas ceiling.
    pub fn new(chain_id: u64) -> Result<Self, DkgTransactionBuildError> {
        Self::with_gas_limit(chain_id, DEFAULT_DKG_TRANSACTION_GAS_LIMIT)
    }

    /// Creates a builder with an operator-selected nonzero gas ceiling.
    pub fn with_gas_limit(chain_id: u64, gas_limit: u64) -> Result<Self, DkgTransactionBuildError> {
        if chain_id == 0 {
            return Err(DkgTransactionBuildError::EmptyChainId)
        }
        if gas_limit == 0 {
            return Err(DkgTransactionBuildError::EmptyGasLimit)
        }
        Ok(Self { chain_id, gas_limit, reservations: HashMap::new() })
    }

    /// Builds an initial attempt, reserving the first unoccupied nonce for this task.
    ///
    /// Repeated calls for the same task return the same nonce and fee until [`Self::bump`] is
    /// requested. `nonce_occupied` must reflect canonical/pool transactions not represented by
    /// this builder's in-memory reservations.
    pub fn build(
        &mut self,
        id: DkgTaskId,
        calldata: Bytes,
        inputs: DkgTransactionInputs,
        mut nonce_occupied: impl FnMut(u64) -> bool,
    ) -> Result<DkgTransactionRequest, DkgTransactionBuildError> {
        validate_calldata(&calldata)?;
        self.prune_canonical_nonces(inputs.on_chain_nonce);
        if let Some(reservation) = self.reservations.get(&id) {
            return self.request(calldata, reservation)
        }

        let mut nonce = inputs.on_chain_nonce;
        loop {
            let reserved = self.reservations.values().any(|reservation| reservation.nonce == nonce);
            if !reserved && !nonce_occupied(nonce) {
                break
            }
            nonce = nonce.checked_add(1).ok_or(DkgTransactionBuildError::NonceOverflow)?;
        }
        let reservation = DkgTransactionReservation {
            nonce,
            fee: DkgTransactionFee::initial(inputs)?,
            replacements: 0,
        };
        self.reservations.insert(id, reservation);
        self.request(
            calldata,
            self.reservations.get(&id).expect("new DKG nonce reservation was inserted"),
        )
    }

    /// Reuses a task's nonce and raises both fee caps by at least 12.5 percent.
    pub fn bump(
        &mut self,
        id: DkgTaskId,
        calldata: Bytes,
        inputs: DkgTransactionInputs,
    ) -> Result<DkgTransactionRequest, DkgTransactionBuildError> {
        validate_calldata(&calldata)?;
        if self
            .reservations
            .get(&id)
            .is_some_and(|reservation| reservation.nonce < inputs.on_chain_nonce)
        {
            let reserved =
                self.reservations.remove(&id).expect("checked DKG nonce reservation exists").nonce;
            return Err(DkgTransactionBuildError::NonceAlreadyMined {
                reserved,
                on_chain: inputs.on_chain_nonce,
            })
        }
        self.prune_canonical_nonces(inputs.on_chain_nonce);
        let reservation = {
            let reservation = self
                .reservations
                .get_mut(&id)
                .ok_or(DkgTransactionBuildError::UnknownReservation(id))?;
            reservation.fee = reservation.fee.bumped(inputs)?;
            reservation.replacements = reservation
                .replacements
                .checked_add(1)
                .ok_or(DkgTransactionBuildError::ReplacementOverflow)?;
            *reservation
        };
        self.request(calldata, &reservation)
    }

    /// Releases a completed or expired task reservation.
    pub fn release(&mut self, id: DkgTaskId) -> bool {
        self.reservations.remove(&id).is_some()
    }

    /// Returns the stable reserved nonce and number of explicit replacements for observability.
    pub fn reservation(&self, id: DkgTaskId) -> Option<(u64, u32)> {
        self.reservations.get(&id).map(|reservation| (reservation.nonce, reservation.replacements))
    }

    fn request(
        &self,
        calldata: Bytes,
        reservation: &DkgTransactionReservation,
    ) -> Result<DkgTransactionRequest, DkgTransactionBuildError> {
        if calldata.len() < 4 {
            return Err(DkgTransactionBuildError::InvalidCalldata(calldata.len()))
        }
        Ok(DkgTransactionRequest {
            chain_id: self.chain_id,
            nonce: reservation.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: reservation.fee.max_fee_per_gas,
            max_priority_fee_per_gas: reservation.fee.max_priority_fee_per_gas,
            calldata,
        })
    }

    fn prune_canonical_nonces(&mut self, on_chain_nonce: u64) {
        self.reservations.retain(|_, reservation| reservation.nonce >= on_chain_nonce);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DkgTransactionReservation {
    nonce: u64,
    fee: DkgTransactionFee,
    replacements: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DkgTransactionFee {
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl DkgTransactionFee {
    fn initial(inputs: DkgTransactionInputs) -> Result<Self, DkgTransactionBuildError> {
        let doubled_base =
            inputs.base_fee_per_gas.checked_mul(2).ok_or(DkgTransactionBuildError::FeeOverflow)?;
        let max_fee_per_gas = doubled_base
            .checked_add(inputs.minimum_priority_fee_per_gas)
            .ok_or(DkgTransactionBuildError::FeeOverflow)?;
        Ok(Self { max_fee_per_gas, max_priority_fee_per_gas: inputs.minimum_priority_fee_per_gas })
    }

    fn bumped(self, inputs: DkgTransactionInputs) -> Result<Self, DkgTransactionBuildError> {
        let live = Self::initial(inputs)?;
        let max_priority_fee_per_gas =
            bump_fee(self.max_priority_fee_per_gas)?.max(live.max_priority_fee_per_gas);
        let live_with_bumped_tip = inputs
            .base_fee_per_gas
            .checked_mul(2)
            .and_then(|base| base.checked_add(max_priority_fee_per_gas))
            .ok_or(DkgTransactionBuildError::FeeOverflow)?;
        let max_fee_per_gas =
            bump_fee(self.max_fee_per_gas)?.max(live.max_fee_per_gas).max(live_with_bumped_tip);
        Ok(Self { max_fee_per_gas, max_priority_fee_per_gas })
    }
}

fn bump_fee(value: u128) -> Result<u128, DkgTransactionBuildError> {
    let increment = (value / FEE_BUMP_DENOMINATOR).max(1);
    value.checked_add(increment).ok_or(DkgTransactionBuildError::FeeOverflow)
}

fn validate_calldata(calldata: &Bytes) -> Result<(), DkgTransactionBuildError> {
    if calldata.len() < 4 {
        Err(DkgTransactionBuildError::InvalidCalldata(calldata.len()))
    } else {
        Ok(())
    }
}

/// Invalid chain configuration, nonce state, retry state, or fee arithmetic.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgTransactionBuildError {
    /// EIP-155 replay protection requires a nonzero chain ID.
    #[error("Neo X DKG transaction chain ID must be non-zero")]
    EmptyChainId,
    /// Every DKG contract call needs a nonzero execution-gas ceiling.
    #[error("Neo X DKG transaction gas limit must be non-zero")]
    EmptyGasLimit,
    /// ABI transaction data must include at least a function selector.
    #[error("invalid Neo X DKG transaction calldata length {0}")]
    InvalidCalldata(usize),
    /// The account/pool nonce space cannot be represented by the transaction type.
    #[error("Neo X DKG transaction nonce overflow")]
    NonceOverflow,
    /// A retry was requested after its reservation was completed, expired, or pruned.
    #[error("unknown Neo X DKG transaction reservation for task {0:?}")]
    UnknownReservation(DkgTaskId),
    /// Canonical state advanced past a task nonce before it could be replaced.
    #[error("Neo X DKG reserved nonce {reserved} is below canonical nonce {on_chain}")]
    NonceAlreadyMined {
        /// Reserved nonce.
        reserved: u64,
        /// Current canonical account nonce.
        on_chain: u64,
    },
    /// Replacement-attempt accounting cannot advance further.
    #[error("Neo X DKG replacement counter overflow")]
    ReplacementOverflow,
    /// Live Policy values or replacement arithmetic overflowed EIP-1559 fee fields.
    #[error("Neo X DKG transaction fee overflow")]
    FeeOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DkgContractMethod;

    fn id(method: DkgContractMethod, sender_index: u64) -> DkgTaskId {
        DkgTaskId { round: 9, method, sender_index }
    }

    fn inputs(on_chain_nonce: u64) -> DkgTransactionInputs {
        DkgTransactionInputs {
            on_chain_nonce,
            base_fee_per_gas: 10_000_000_000,
            minimum_priority_fee_per_gas: 20_000_000_000,
        }
    }

    fn calldata(value: u8) -> Bytes {
        Bytes::from(vec![value; 8])
    }

    #[test]
    fn reserves_distinct_first_available_nonces_for_parallel_tasks() {
        let mut builder = DkgTransactionBuilder::new(47_763).unwrap();
        let reshare = id(DkgContractMethod::Reshare, 3);
        let share = id(DkgContractMethod::Share, 2);
        let first = builder.build(reshare, calldata(1), inputs(5), |nonce| nonce == 5).unwrap();
        let second = builder.build(share, calldata(2), inputs(5), |nonce| nonce == 5).unwrap();
        assert_eq!(first.nonce, 6);
        assert_eq!(second.nonce, 7);
        assert_eq!(first.max_priority_fee_per_gas, 20_000_000_000);
        assert_eq!(first.max_fee_per_gas, 40_000_000_000);
        assert_eq!(builder.reservation(reshare), Some((6, 0)));
    }

    #[test]
    fn repeated_build_is_stable_and_explicit_bump_reuses_nonce() {
        let mut builder = DkgTransactionBuilder::new(47_763).unwrap();
        let task = id(DkgContractMethod::Share, 1);
        let first = builder.build(task, calldata(1), inputs(0), |_| false).unwrap();
        let repeated = builder.build(task, calldata(1), inputs(0), |_| true).unwrap();
        assert_eq!(first, repeated);

        let replacement = builder.bump(task, calldata(1), inputs(0)).unwrap();
        assert_eq!(replacement.nonce, first.nonce);
        assert_eq!(replacement.max_priority_fee_per_gas, 22_500_000_000);
        assert_eq!(replacement.max_fee_per_gas, 45_000_000_000);
        assert_eq!(builder.reservation(task), Some((0, 1)));
    }

    #[test]
    fn live_fee_increase_overrides_minimum_replacement_bump() {
        let mut builder = DkgTransactionBuilder::new(47_763).unwrap();
        let task = id(DkgContractMethod::Recover, 4);
        builder.build(task, calldata(1), inputs(0), |_| false).unwrap();
        let replacement = builder
            .bump(
                task,
                calldata(1),
                DkgTransactionInputs {
                    on_chain_nonce: 0,
                    base_fee_per_gas: 30_000_000_000,
                    minimum_priority_fee_per_gas: 25_000_000_000,
                },
            )
            .unwrap();
        assert_eq!(replacement.max_priority_fee_per_gas, 25_000_000_000);
        assert_eq!(replacement.max_fee_per_gas, 85_000_000_000);
    }

    #[test]
    fn canonical_nonce_prunes_mined_reservations_and_release_reuses_capacity() {
        let mut builder = DkgTransactionBuilder::new(47_763).unwrap();
        let first = id(DkgContractMethod::Share, 1);
        let second = id(DkgContractMethod::Share, 2);
        builder.build(first, calldata(1), inputs(3), |_| false).unwrap();
        builder.build(second, calldata(2), inputs(4), |_| false).unwrap();
        assert_eq!(builder.reservation(first), None);
        assert_eq!(builder.reservation(second), Some((4, 0)));
        assert!(builder.release(second));
        assert!(!builder.release(second));
    }

    #[test]
    fn rejects_invalid_configuration_calldata_and_overflow() {
        assert!(matches!(
            DkgTransactionBuilder::new(0),
            Err(DkgTransactionBuildError::EmptyChainId)
        ));
        let mut builder = DkgTransactionBuilder::new(1).unwrap();
        let task = id(DkgContractMethod::Share, 1);
        assert_eq!(
            builder.build(task, Bytes::from_static(&[1, 2, 3]), inputs(0), |_| false),
            Err(DkgTransactionBuildError::InvalidCalldata(3))
        );
        assert!(matches!(
            builder.build(task, calldata(1), inputs(u64::MAX), |_| true),
            Err(DkgTransactionBuildError::NonceOverflow)
        ));
    }
}
