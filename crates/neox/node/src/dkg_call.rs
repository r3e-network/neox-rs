//! Validated ABI payloads and canonical getter calls for Neo X `KeyManagement`.

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::{sol, SolCall};
use reth_evm::{ConfigureEvm, Evm};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use reth_neox_evm::{NeoXEvmConfig, KEY_MANAGEMENT_PROXY_ADDRESS};
use reth_provider::StateProvider;
use reth_revm::{
    context::TxEnv, context_interface::result::ExecutionResult, database::StateProviderDatabase,
};
use thiserror::Error;

/// Deployed selector of the pure `KeyManagement.ZK_VERSION()` getter.
pub const DKG_ZK_VERSION_SELECTOR: [u8; 4] = [0x60, 0x4a, 0x09, 0x02];

/// Gas limit used by pinned Neo X Geth for canonical system-contract getter calls.
const DKG_GETTER_GAS_LIMIT: u64 = 50_000_000;

/// Byte length required by the deployed seven-member Neo X PVSS verifier.
pub const NEOX_DKG_PVSS_LEN: usize = reth_neox_antimev::NEOX_DKG_GENERATED_PVSS_LEN;
/// Byte length of one Neo X DKG ECIES message: uncompressed `R`, nonce, scalar, and GCM tag.
pub const NEOX_DKG_MESSAGE_LEN: usize = 64 + 12 + 32 + 16;

sol! {
    interface IZkDkgV0 {
        function share(bytes pvss, bytes[] messages);
        function reshare(bytes pvss, bytes[] messages);
        function recover(uint256[] idxs, bytes[] messages);
        function reshareRecovered(bytes pvss, bytes[] messages);
    }

    interface IZkDkgV1 {
        function share(
            bytes pvss,
            bytes[] messages,
            uint256[8] proof,
            uint256[2] commitments,
            uint256[2] commitment_pok
        );
        function reshare(
            bytes pvss,
            bytes[] messages,
            uint256[8] proof,
            uint256[2] commitments,
            uint256[2] commitment_pok
        );
        function recover(
            uint256[] idxs,
            bytes[] messages,
            uint256[8] proof,
            uint256[2] commitments,
            uint256[2] commitment_pok
        );
        function reshareRecovered(
            bytes pvss,
            bytes[] messages,
            uint256[8] proof,
            uint256[2] commitments,
            uint256[2] commitment_pok
        );
    }
}

/// One of the four transactions accepted by the Neo X DKG contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DkgContractMethod {
    /// A pending validator publishes its newly generated shares.
    Share,
    /// A current validator transfers its existing share to the pending set.
    Reshare,
    /// A current validator sends recovery material to missing pending validators.
    Recover,
    /// A recovered pending validator publishes the reconstructed reshare.
    ReshareRecovered,
}

/// Groth16 proof values returned by the Neo X seven-, two-, or one-message prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgGroth16Proof {
    /// Eight affine proof coordinates consumed by the Solidity verifier.
    pub proof: [U256; 8],
    /// Two commitment coordinates.
    pub commitments: [U256; 2],
    /// Two proof-of-knowledge commitment coordinates.
    pub commitment_pok: [U256; 2],
}

/// Fully encrypted DKG contract parameters, ready for ABI encoding after proof generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgContractCall {
    /// `share(bytes,bytes[],...)` parameters.
    Share {
        /// Polynomial commitments and proof-of-secret-sharing bytes.
        pvss: Bytes,
        /// One encrypted share for each pending validator.
        messages: Vec<Bytes>,
    },
    /// `reshare(bytes,bytes[],...)` parameters.
    Reshare {
        /// Polynomial commitments and proof-of-secret-sharing bytes.
        pvss: Bytes,
        /// One encrypted reshare for each pending validator.
        messages: Vec<Bytes>,
    },
    /// `recover(uint256[],bytes[],...)` parameters.
    Recover {
        /// One-based indices of pending validators whose reshares are missing.
        indices: Vec<u64>,
        /// One encrypted recovery message per index.
        messages: Vec<Bytes>,
    },
    /// `reshareRecovered(bytes,bytes[],...)` parameters.
    ReshareRecovered {
        /// Reconstructed polynomial commitments and proof-of-secret-sharing bytes.
        pvss: Bytes,
        /// One reconstructed encrypted reshare for each pending validator.
        messages: Vec<Bytes>,
    },
}

impl DkgContractCall {
    /// Returns the deployed contract method represented by these parameters.
    pub const fn method(&self) -> DkgContractMethod {
        match self {
            Self::Share { .. } => DkgContractMethod::Share,
            Self::Reshare { .. } => DkgContractMethod::Reshare,
            Self::Recover { .. } => DkgContractMethod::Recover,
            Self::ReshareRecovered { .. } => DkgContractMethod::ReshareRecovered,
        }
    }

    /// Validates and ABI-encodes the exact ZK-v0 or ZK-v1 `KeyManagement` call.
    ///
    /// The returned bytes include the four-byte function selector and are stable for transaction
    /// retries. ZK-v1 requires a proof, while ZK-v0 rejects one to prevent version confusion.
    pub fn abi_encode(
        &self,
        zk_version: u64,
        proof: Option<&DkgGroth16Proof>,
    ) -> Result<Bytes, DkgContractCallError> {
        self.validate()?;
        match (zk_version, proof) {
            (0, None) => Ok(self.encode_v0()),
            (0, Some(_)) => Err(DkgContractCallError::UnexpectedProof),
            (1, Some(proof)) => Ok(self.encode_v1(proof)),
            (1, None) => Err(DkgContractCallError::MissingProof),
            (version, _) => Err(DkgContractCallError::UnsupportedZkVersion(version)),
        }
    }

    fn validate(&self) -> Result<(), DkgContractCallError> {
        match self {
            Self::Share { pvss, messages } |
            Self::Reshare { pvss, messages } |
            Self::ReshareRecovered { pvss, messages } => {
                if pvss.len() != NEOX_DKG_PVSS_LEN {
                    return Err(DkgContractCallError::InvalidPvssLength(pvss.len()))
                }
                if messages.len() != NEOX_VALIDATOR_COUNT {
                    return Err(DkgContractCallError::InvalidMessageCount {
                        method: self.method(),
                        expected: NEOX_VALIDATOR_COUNT,
                        actual: messages.len(),
                    })
                }
                validate_message_lengths(self.method(), messages)?;
            }
            Self::Recover { indices, messages } => {
                if !(1..=2).contains(&indices.len()) {
                    return Err(DkgContractCallError::InvalidRecoveryCount(indices.len()))
                }
                if indices.len() != messages.len() {
                    return Err(DkgContractCallError::RecoveryArrayMismatch {
                        indices: indices.len(),
                        messages: messages.len(),
                    })
                }
                for &index in indices {
                    if index == 0 || index > NEOX_VALIDATOR_COUNT as u64 {
                        return Err(DkgContractCallError::InvalidRecoveryIndex(index))
                    }
                }
                validate_message_lengths(self.method(), messages)?;
            }
        }
        Ok(())
    }

    fn encode_v0(&self) -> Bytes {
        match self {
            Self::Share { pvss, messages } => {
                IZkDkgV0::shareCall { pvss: pvss.clone(), messages: messages.clone() }
                    .abi_encode()
                    .into()
            }
            Self::Reshare { pvss, messages } => {
                IZkDkgV0::reshareCall { pvss: pvss.clone(), messages: messages.clone() }
                    .abi_encode()
                    .into()
            }
            Self::Recover { indices, messages } => IZkDkgV0::recoverCall {
                idxs: indices.iter().copied().map(U256::from).collect(),
                messages: messages.clone(),
            }
            .abi_encode()
            .into(),
            Self::ReshareRecovered { pvss, messages } => {
                IZkDkgV0::reshareRecoveredCall { pvss: pvss.clone(), messages: messages.clone() }
                    .abi_encode()
                    .into()
            }
        }
    }

    fn encode_v1(&self, proof: &DkgGroth16Proof) -> Bytes {
        let DkgGroth16Proof { proof, commitments, commitment_pok } = proof;
        match self {
            Self::Share { pvss, messages } => IZkDkgV1::shareCall {
                pvss: pvss.clone(),
                messages: messages.clone(),
                proof: *proof,
                commitments: *commitments,
                commitment_pok: *commitment_pok,
            }
            .abi_encode()
            .into(),
            Self::Reshare { pvss, messages } => IZkDkgV1::reshareCall {
                pvss: pvss.clone(),
                messages: messages.clone(),
                proof: *proof,
                commitments: *commitments,
                commitment_pok: *commitment_pok,
            }
            .abi_encode()
            .into(),
            Self::Recover { indices, messages } => IZkDkgV1::recoverCall {
                idxs: indices.iter().copied().map(U256::from).collect(),
                messages: messages.clone(),
                proof: *proof,
                commitments: *commitments,
                commitment_pok: *commitment_pok,
            }
            .abi_encode()
            .into(),
            Self::ReshareRecovered { pvss, messages } => IZkDkgV1::reshareRecoveredCall {
                pvss: pvss.clone(),
                messages: messages.clone(),
                proof: *proof,
                commitments: *commitments,
                commitment_pok: *commitment_pok,
            }
            .abi_encode()
            .into(),
        }
    }
}

fn validate_message_lengths(
    method: DkgContractMethod,
    messages: &[Bytes],
) -> Result<(), DkgContractCallError> {
    for (index, message) in messages.iter().enumerate() {
        if message.len() != NEOX_DKG_MESSAGE_LEN {
            return Err(DkgContractCallError::InvalidMessageLength {
                method,
                index,
                actual: message.len(),
            })
        }
    }
    Ok(())
}

/// Invalid DKG calldata or a mismatch with the on-chain verifier version.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgContractCallError {
    /// Only the two contract versions deployed by Neo X are supported.
    #[error("unsupported Neo X DKG ZK version {0}")]
    UnsupportedZkVersion(u64),
    /// ZK-v1 calldata cannot be constructed without its Groth16 proof.
    #[error("Neo X DKG ZK-v1 call is missing its Groth16 proof")]
    MissingProof,
    /// Supplying proof coordinates to the proofless ZK-v0 ABI is almost certainly a caller bug.
    #[error("Neo X DKG ZK-v0 call unexpectedly included a Groth16 proof")]
    UnexpectedProof,
    /// A seven-member Neo X PVSS has one fixed encoded size.
    #[error("invalid Neo X DKG PVSS length {0}")]
    InvalidPvssLength(usize),
    /// Share-family calls must encrypt one message for every pending validator.
    #[error("invalid {method:?} message count: expected {expected}, got {actual}")]
    InvalidMessageCount {
        /// Contract method being encoded.
        method: DkgContractMethod,
        /// Required message count.
        expected: usize,
        /// Supplied message count.
        actual: usize,
    },
    /// Every encrypted share has one fixed ECIES wire shape.
    #[error("invalid {method:?} message {index} length: expected 124, got {actual}")]
    InvalidMessageLength {
        /// Contract method being encoded.
        method: DkgContractMethod,
        /// Zero-based message position.
        index: usize,
        /// Supplied message byte length.
        actual: usize,
    },
    /// The deployed recovery circuits support one or two absent members.
    #[error("invalid Neo X DKG recovery count {0}: expected one or two")]
    InvalidRecoveryCount(usize),
    /// Each recovered member must have exactly one encrypted message.
    #[error("Neo X DKG recovery array mismatch: {indices} indices, {messages} messages")]
    RecoveryArrayMismatch {
        /// Supplied recovery indices.
        indices: usize,
        /// Supplied encrypted messages.
        messages: usize,
    },
    /// Contract participant indices are one-based and bounded by the validator count.
    #[error("invalid Neo X DKG recovery index {0}")]
    InvalidRecoveryIndex(u64),
}

/// Executes `KeyManagement.ZK_VERSION()` against one exact canonical state/header snapshot.
///
/// The getter is a Solidity constant implemented behind an upgradeable proxy, so no raw storage
/// slot can identify the deployed ABI. This mirrors Geth's `DoCallAtState`: fees, nonce checks,
/// EIP-3607, and block gas-limit validation are disabled, and the resulting state is discarded.
pub fn read_dkg_zk_version_at_state(
    state: &dyn StateProvider,
    header: &Header,
    evm_config: &NeoXEvmConfig,
) -> Result<u64, DkgZkVersionStateError> {
    let mut evm_env = evm_config.evm_env(header).unwrap_or_else(|infallible| match infallible {});
    evm_env.cfg_env.disable_block_gas_limit = true;
    evm_env.cfg_env.disable_eip3607 = true;
    evm_env.cfg_env.disable_base_fee = true;
    evm_env.cfg_env.disable_nonce_check = true;
    evm_env.cfg_env.disable_fee_charge = true;
    evm_env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);
    let chain_id = evm_env.cfg_env.chain_id;

    let database = StateProviderDatabase::new(state);
    let mut evm = evm_config.evm_with_env(database, evm_env);
    let result = evm
        .transact(TxEnv {
            caller: Address::ZERO,
            gas_limit: DKG_GETTER_GAS_LIMIT,
            kind: TxKind::Call(KEY_MANAGEMENT_PROXY_ADDRESS),
            data: Bytes::copy_from_slice(&DKG_ZK_VERSION_SELECTOR),
            chain_id: Some(chain_id),
            ..Default::default()
        })
        .map_err(|error| DkgZkVersionStateError::Execution(error.to_string()))?;

    match result.result {
        ExecutionResult::Success { output, .. } => {
            decode_dkg_zk_version(&output.into_data()).map_err(Into::into)
        }
        // Pinned Geth treats an implementation without this selector as ZK-v0. Its ABI decoder
        // observes an empty result for an empty-data revert, so preserve that compatibility only
        // for the exact empty-revert shape.
        ExecutionResult::Revert { output, .. } if output.is_empty() => Ok(0),
        ExecutionResult::Revert { output, .. } => Err(DkgZkVersionStateError::Reverted { output }),
        ExecutionResult::Halt { reason, .. } => {
            Err(DkgZkVersionStateError::Halted(reason.to_string()))
        }
    }
}

/// Failure to execute or decode canonical `KeyManagement.ZK_VERSION()`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DkgZkVersionStateError {
    /// State-backed EVM execution failed before producing a contract result.
    #[error("failed to execute canonical Neo X KeyManagement.ZK_VERSION(): {0}")]
    Execution(String),
    /// A non-empty revert must never be interpreted as a deployed verifier version.
    #[error("canonical Neo X KeyManagement.ZK_VERSION() reverted with {output:?}")]
    Reverted {
        /// Raw revert bytes returned by the proxy implementation.
        output: Bytes,
    },
    /// The getter exhausted execution or hit an exceptional EVM condition.
    #[error("canonical Neo X KeyManagement.ZK_VERSION() halted: {0}")]
    Halted(String),
    /// The getter returned a malformed ABI word.
    #[error(transparent)]
    InvalidOutput(#[from] DkgZkVersionError),
}

/// Decodes `ZK_VERSION()` output, treating an empty pre-version response as Geth's ZK-v0.
pub fn decode_dkg_zk_version(output: &[u8]) -> Result<u64, DkgZkVersionError> {
    if output.is_empty() {
        return Ok(0)
    }
    if output.len() != 32 {
        return Err(DkgZkVersionError::InvalidOutputLength(output.len()))
    }
    u64::try_from(U256::from_be_slice(output)).map_err(|_| DkgZkVersionError::Overflow)
}

/// Invalid return data from `KeyManagement.ZK_VERSION()`.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DkgZkVersionError {
    /// ABI-encoded `uint256` output must occupy one word.
    #[error("invalid Neo X DKG ZK-version output length {0}")]
    InvalidOutputLength(usize),
    /// The returned version did not fit the node's 64-bit representation.
    #[error("Neo X DKG ZK version exceeds u64")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use reth_ethereum_primitives::EthPrimitives;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};

    fn pvss() -> Bytes {
        vec![0x11; NEOX_DKG_PVSS_LEN].into()
    }

    fn messages(count: usize) -> Vec<Bytes> {
        (0..count).map(|index| vec![index as u8; NEOX_DKG_MESSAGE_LEN].into()).collect()
    }

    fn proof() -> DkgGroth16Proof {
        DkgGroth16Proof {
            proof: core::array::from_fn(|index| U256::from(index + 1)),
            commitments: [U256::from(9), U256::from(10)],
            commitment_pok: [U256::from(11), U256::from(12)],
        }
    }

    fn execute_zk_version_getter(bytecode: Bytes) -> Result<u64, DkgZkVersionStateError> {
        let provider = MockEthProvider::<EthPrimitives>::new();
        provider.add_account(
            KEY_MANAGEMENT_PROXY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).with_bytecode(bytecode),
        );
        let evm_config = NeoXEvmConfig::new(reth_neox_chainspec::NeoXChainSpec::mainnet().unwrap());
        let header = evm_config.chain_spec().inner.genesis_header.clone_header();
        read_dkg_zk_version_at_state(&provider, &header, &evm_config)
    }

    #[test]
    fn encodes_deployed_zk_v0_selectors() {
        let calls = [
            (DkgContractCall::Share { pvss: pvss(), messages: messages(7) }, hex!("d7026d83")),
            (DkgContractCall::Reshare { pvss: pvss(), messages: messages(7) }, hex!("685836a1")),
            (
                DkgContractCall::Recover { indices: vec![1], messages: messages(1) },
                hex!("e58dec2b"),
            ),
            (
                DkgContractCall::ReshareRecovered { pvss: pvss(), messages: messages(7) },
                hex!("8c1a2bd6"),
            ),
        ];
        for (call, selector) in calls {
            let encoded = call.abi_encode(0, None).unwrap();
            assert_eq!(encoded[..4], selector);
        }
    }

    #[test]
    fn encodes_and_decodes_deployed_zk_v1_calls() {
        let proof = proof();
        let calls = [
            (DkgContractCall::Share { pvss: pvss(), messages: messages(7) }, hex!("a86e37d3")),
            (DkgContractCall::Reshare { pvss: pvss(), messages: messages(7) }, hex!("1d619b13")),
            (
                DkgContractCall::Recover { indices: vec![2, 7], messages: messages(2) },
                hex!("1ae3feed"),
            ),
            (
                DkgContractCall::ReshareRecovered { pvss: pvss(), messages: messages(7) },
                hex!("15e70aa5"),
            ),
        ];
        let encoded = calls
            .iter()
            .map(|(call, selector)| {
                let encoded = call.abi_encode(1, Some(&proof)).unwrap();
                assert_eq!(encoded[..4], *selector);
                encoded
            })
            .collect::<Vec<_>>();

        let share = &encoded[0];
        let decoded = IZkDkgV1::shareCall::abi_decode_validate(share).unwrap();
        assert_eq!(decoded.pvss.len(), NEOX_DKG_PVSS_LEN);
        assert_eq!(decoded.messages, messages(7));
        assert_eq!(decoded.proof, proof.proof);

        let recover = &encoded[2];
        let decoded = IZkDkgV1::recoverCall::abi_decode_validate(recover).unwrap();
        assert_eq!(decoded.idxs, vec![U256::from(2), U256::from(7)]);
        assert_eq!(decoded.messages, messages(2));
    }

    #[test]
    fn rejects_version_and_contract_shape_mismatches() {
        let share = DkgContractCall::Share { pvss: pvss(), messages: messages(7) };
        assert_eq!(share.abi_encode(1, None), Err(DkgContractCallError::MissingProof));
        assert_eq!(share.abi_encode(0, Some(&proof())), Err(DkgContractCallError::UnexpectedProof));
        assert_eq!(share.abi_encode(2, None), Err(DkgContractCallError::UnsupportedZkVersion(2)));

        let invalid = DkgContractCall::Recover { indices: vec![0], messages: messages(1) };
        assert_eq!(invalid.abi_encode(0, None), Err(DkgContractCallError::InvalidRecoveryIndex(0)));
        let invalid = DkgContractCall::Recover { indices: vec![1, 2], messages: messages(1) };
        assert_eq!(
            invalid.abi_encode(0, None),
            Err(DkgContractCallError::RecoveryArrayMismatch { indices: 2, messages: 1 })
        );
        let invalid = DkgContractCall::Recover {
            indices: vec![1],
            messages: vec![Bytes::from_static(&[0_u8; NEOX_DKG_MESSAGE_LEN - 1])],
        };
        assert_eq!(
            invalid.abi_encode(0, None),
            Err(DkgContractCallError::InvalidMessageLength {
                method: DkgContractMethod::Recover,
                index: 0,
                actual: NEOX_DKG_MESSAGE_LEN - 1,
            })
        );
    }

    /// Only an empty response carries Geth's legacy-implementation meaning. Its `Arguments.Unpack`
    /// applies no total-length check and `big.Int.Uint64()` truncates, so the oracle reads a longer
    /// response from its first word and an oversized version from its low bits. Both are rejected
    /// here; see the ZK-version section of `docs/neox/README.md`.
    #[test]
    fn decodes_zk_version_with_geth_v0_fallback() {
        assert_eq!(decode_dkg_zk_version(&[]), Ok(0));
        assert_eq!(decode_dkg_zk_version(&U256::from(1).to_be_bytes::<32>()), Ok(1));
        assert_eq!(
            decode_dkg_zk_version(&[0_u8; 31]),
            Err(DkgZkVersionError::InvalidOutputLength(31))
        );
        assert_eq!(
            decode_dkg_zk_version(&[0_u8; 64]),
            Err(DkgZkVersionError::InvalidOutputLength(64))
        );
        assert_eq!(decode_dkg_zk_version(&U256::from(u64::MAX).to_be_bytes::<32>()), Ok(u64::MAX));
        assert_eq!(
            decode_dkg_zk_version(&(U256::from(u64::MAX) + U256::from(1)).to_be_bytes::<32>()),
            Err(DkgZkVersionError::Overflow)
        );
        assert_eq!(DKG_ZK_VERSION_SELECTOR, hex!("604a0902"));
    }

    #[test]
    fn executes_zk_version_getter_against_state_provider() {
        // mstore(0, 1); return(0, 32)
        assert_eq!(execute_zk_version_getter(hex!("600160005260206000f3").into()), Ok(1));
    }

    #[test]
    fn accepts_only_empty_revert_as_geth_v0_fallback() {
        // revert(0, 0)
        assert_eq!(execute_zk_version_getter(hex!("60006000fd").into()), Ok(0));

        // mstore(0, 0xdeadbeef); revert(28, 4)
        assert_eq!(
            execute_zk_version_getter(hex!("63deadbeef6000526004601cfd").into()),
            Err(DkgZkVersionStateError::Reverted { output: hex!("deadbeef").into() })
        );
    }

    /// A halt reaches Geth's `unpackContractExecutionResult` with `Revert()` nil, because that is
    /// only set for `vm.ErrExecutionReverted`, and `Return()` nil, because that is nil for any
    /// failed execution. It therefore hits the same empty-response decoder error the oracle maps to
    /// version zero. Guessing a proofless ABI from an unrelated failure is refused here; see
    /// `docs/neox/README.md`.
    #[test]
    fn rejects_halted_zk_version_getter() {
        // invalid opcode
        let error = execute_zk_version_getter(hex!("fe").into()).unwrap_err();
        assert!(matches!(error, DkgZkVersionStateError::Halted(_)));

        // jump to an invalid destination, exercising a second halt reason
        let error = execute_zk_version_getter(hex!("600556").into()).unwrap_err();
        assert!(matches!(error, DkgZkVersionStateError::Halted(_)));
    }
}
