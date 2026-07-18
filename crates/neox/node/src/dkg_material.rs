//! Crash-safe DKG task material generation and prover-to-calldata bridging.

use crate::{
    DkgContractCall, DkgContractCallError, DkgContractMethod, DkgProver, DkgProverError,
    DkgProverOutput, DkgShareScalar, DkgTaskPlan,
};
use alloy_primitives::{Address, Bytes, U256};
use k256::PublicKey;
use reth_neox_antimev::{
    DkgKeyStore, DkgPvssMaterial, DkgSecretScalar, DkgStateError as DkgKeyStoreError,
};
use reth_neox_chainspec::NEOX_VALIDATOR_COUNT;
use std::fmt;
use thiserror::Error;

/// One pending validator's one-based position and registered message-encryption key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DkgRecipient {
    index: u64,
    public_key: [u8; 65],
}

impl DkgRecipient {
    /// Validates a contract participant position and uncompressed Secp256k1 public key.
    pub fn new(index: u64, public_key: [u8; 65]) -> Result<Self, DkgTaskPreparationError> {
        if index == 0 || index > NEOX_VALIDATOR_COUNT as u64 {
            return Err(DkgTaskPreparationError::InvalidRecipientIndex(index))
        }
        PublicKey::from_sec1_bytes(&public_key)
            .map_err(|_| DkgTaskPreparationError::InvalidRecipientPublicKey(index))?;
        Ok(Self { index, public_key })
    }

    /// Returns the one-based pending-validator position.
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the exact uncompressed Secp256k1 key expected by the prover helper.
    pub const fn public_key(&self) -> &[u8; 65] {
        &self.public_key
    }
}

impl fmt::Debug for DkgRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DkgRecipient").field("index", &self.index).finish_non_exhaustive()
    }
}

/// Secret task inputs separated from the long-running external prover process.
///
/// The caller must persist the mutated [`DkgKeyStore`] before proving when
/// [`Self::must_persist_store`] returns `true`. This makes a crash after transaction submission
/// recoverable without retaining a keystore lock across proof generation.
pub struct DkgTaskMaterial {
    round: u64,
    method: DkgContractMethod,
    sender: Address,
    recipients: Vec<DkgRecipient>,
    shares: Vec<DkgShareScalar>,
    pvss: Option<Bytes>,
    recovery_indices: Vec<u64>,
    must_persist_store: bool,
}

impl DkgTaskMaterial {
    /// Returns the implicit `KeyManagement` round for this call.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the contract method represented by this material.
    pub const fn method(&self) -> DkgContractMethod {
        self.method
    }

    /// Returns the number of encrypted messages the prover must produce.
    pub const fn message_count(&self) -> usize {
        self.shares.len()
    }

    /// Reports whether task generation mutated secret state that must be saved before proving.
    pub const fn must_persist_store(&self) -> bool {
        self.must_persist_store
    }
}

impl fmt::Debug for DkgTaskMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DkgTaskMaterial")
            .field("round", &self.round)
            .field("method", &self.method)
            .field("sender", &self.sender)
            .field(
                "recipient_indices",
                &self.recipients.iter().map(|item| item.index).collect::<Vec<_>>(),
            )
            .field("share_count", &self.shares.len())
            .field("pvss_len", &self.pvss.as_ref().map(|pvss| pvss.len()))
            .field("must_persist_store", &self.must_persist_store)
            .finish()
    }
}

/// Generates one task's secret shares and public PVSS without invoking the external prover.
///
/// A share or recovered-reshare task mutates the keystore. The caller must atomically encrypt and
/// persist that state before passing the returned material to [`prove_dkg_task_material`].
pub fn generate_dkg_task_material(
    store: &mut DkgKeyStore,
    sender: Address,
    chain_id: U256,
    plan: &DkgTaskPlan,
    recipients: Vec<DkgRecipient>,
) -> Result<DkgTaskMaterial, DkgTaskPreparationError> {
    let Some(store_validator) = store.validator_address() else {
        return Err(DkgTaskPreparationError::UnboundKeyStore)
    };
    if store_validator != sender {
        return Err(DkgTaskPreparationError::ValidatorMismatch {
            expected: store_validator,
            actual: sender,
        })
    }
    let expected_round =
        store.round().checked_add(1).ok_or(DkgTaskPreparationError::RoundOverflow)?;
    if plan.round != expected_round {
        return Err(DkgTaskPreparationError::RoundMismatch {
            store_round: store.round(),
            task_round: plan.round,
        })
    }
    validate_recipients(plan, &recipients)?;

    let (pvss, shares, must_persist_store) = match plan.method {
        DkgContractMethod::Share => {
            let (pvss, shares) = pvss_parts(store.prepare_share(chain_id)?)?;
            (Some(pvss), shares, true)
        }
        DkgContractMethod::Reshare => {
            let (pvss, shares) = pvss_parts(store.prepare_reshare()?)?;
            (Some(pvss), shares, false)
        }
        DkgContractMethod::Recover => {
            let shares = store
                .prepare_recovery(&plan.recovery_indices)?
                .iter()
                .map(DkgShareScalar::from)
                .collect();
            (None, shares, false)
        }
        DkgContractMethod::ReshareRecovered => {
            let (pvss, shares) = pvss_parts(store.prepare_recovered_reshare()?)?;
            (Some(pvss), shares, true)
        }
    };

    Ok(DkgTaskMaterial {
        round: plan.round,
        method: plan.method,
        sender,
        recipients,
        shares,
        pvss,
        recovery_indices: plan.recovery_indices.clone(),
        must_persist_store,
    })
}

/// Encrypts task shares, generates any required Groth16 proof, and returns stable ABI calldata.
pub async fn prove_dkg_task_material(
    prover: &DkgProver,
    zk_version: u64,
    material: DkgTaskMaterial,
) -> Result<Bytes, DkgTaskPreparationError> {
    let public_keys =
        material.recipients.iter().map(|recipient| recipient.public_key).collect::<Vec<_>>();
    let output =
        prover.prepare(material.sender, zk_version, &public_keys, &material.shares).await?;
    encode_dkg_task_output(&material, zk_version, output)
}

fn pvss_parts(
    material: DkgPvssMaterial,
) -> Result<(Bytes, Vec<DkgShareScalar>), DkgTaskPreparationError> {
    let (pvss, shares) = material.into_parts();
    let shares = shares.iter().map(DkgShareScalar::from).collect();
    Ok((pvss.into(), shares))
}

fn validate_recipients(
    plan: &DkgTaskPlan,
    recipients: &[DkgRecipient],
) -> Result<(), DkgTaskPreparationError> {
    let expected = match plan.method {
        DkgContractMethod::Recover => plan.recovery_indices.as_slice(),
        DkgContractMethod::Share |
        DkgContractMethod::Reshare |
        DkgContractMethod::ReshareRecovered => &[1, 2, 3, 4, 5, 6, 7],
    };
    let actual = recipients.iter().map(|recipient| recipient.index).collect::<Vec<_>>();
    if actual != expected {
        return Err(DkgTaskPreparationError::RecipientOrderMismatch {
            expected: expected.to_vec(),
            actual,
        })
    }
    Ok(())
}

fn encode_dkg_task_output(
    material: &DkgTaskMaterial,
    zk_version: u64,
    output: DkgProverOutput,
) -> Result<Bytes, DkgTaskPreparationError> {
    let DkgProverOutput { messages, proof } = output;
    let call = match material.method {
        DkgContractMethod::Share => DkgContractCall::Share {
            pvss: material.pvss.clone().expect("generated share material has PVSS"),
            messages,
        },
        DkgContractMethod::Reshare => DkgContractCall::Reshare {
            pvss: material.pvss.clone().expect("generated reshare material has PVSS"),
            messages,
        },
        DkgContractMethod::Recover => {
            DkgContractCall::Recover { indices: material.recovery_indices.clone(), messages }
        }
        DkgContractMethod::ReshareRecovered => DkgContractCall::ReshareRecovered {
            pvss: material.pvss.clone().expect("generated recovered-reshare material has PVSS"),
            messages,
        },
    };
    Ok(call.abi_encode(zk_version, proof.as_ref())?)
}

impl From<&DkgSecretScalar> for DkgShareScalar {
    fn from(secret: &DkgSecretScalar) -> Self {
        Self::new(*secret.as_bytes()).expect("validated DKG secret remains a valid prover scalar")
    }
}

/// Invalid local state, recipient ordering, proof output, or ABI encoding for one DKG task.
#[derive(Debug, Error)]
pub enum DkgTaskPreparationError {
    /// Runtime operation requires the encrypted store to be bound during startup.
    #[error("Neo X DKG keystore is not bound to a validator account")]
    UnboundKeyStore,
    /// The active signer must match the validator identity persisted in the encrypted store.
    #[error("Neo X DKG keystore belongs to validator {expected}, not {actual}")]
    ValidatorMismatch {
        /// Persisted validator account.
        expected: Address,
        /// Active transaction signer.
        actual: Address,
    },
    /// The local round counter cannot represent another task round.
    #[error("Neo X DKG keystore round overflow")]
    RoundOverflow,
    /// Canonical contract state and locally replayed keystore state disagree.
    #[error(
        "Neo X DKG task round {task_round} does not follow local keystore round {store_round}"
    )]
    RoundMismatch {
        /// Last locally settled round.
        store_round: u64,
        /// Planned implicit contract round.
        task_round: u64,
    },
    /// Pending-validator positions are one-based and bounded by the deployed committee size.
    #[error("invalid Neo X DKG recipient index {0}")]
    InvalidRecipientIndex(u64),
    /// Encryption keys must be valid uncompressed Secp256k1 points.
    #[error("invalid Neo X DKG recipient public key at index {0}")]
    InvalidRecipientPublicKey(u64),
    /// Keys must be passed in the exact order consumed by the contract method.
    #[error("Neo X DKG recipient order mismatch: expected {expected:?}, got {actual:?}")]
    RecipientOrderMismatch {
        /// Required one-based positions.
        expected: Vec<u64>,
        /// Supplied one-based positions.
        actual: Vec<u64>,
    },
    /// Secret-state material generation failed.
    #[error(transparent)]
    KeyStore(#[from] DkgKeyStoreError),
    /// External encryption or proof generation failed.
    #[error(transparent)]
    Prover(#[from] DkgProverError),
    /// The prover result did not encode a valid deployed contract call.
    #[error(transparent)]
    ContractCall(#[from] DkgContractCallError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DkgGroth16Proof;
    use alloy_primitives::hex;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use reth_neox_antimev::DkgMessagePrivateKey;

    fn sender() -> Address {
        Address::repeat_byte(0x11)
    }

    fn message_key(value: u8) -> DkgMessagePrivateKey {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        DkgMessagePrivateKey::new(encoded).unwrap()
    }

    fn public_key(value: u8) -> [u8; 65] {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        SecretKey::from_slice(&encoded)
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn recipients(indices: impl IntoIterator<Item = u64>) -> Vec<DkgRecipient> {
        indices
            .into_iter()
            .map(|index| DkgRecipient::new(index, public_key(index as u8)).unwrap())
            .collect()
    }

    fn plan(method: DkgContractMethod) -> DkgTaskPlan {
        DkgTaskPlan {
            round: 1,
            method,
            sender_index: 2,
            send_height: 10,
            end_height: 20,
            recovery_indices: Vec::new(),
        }
    }

    fn scalar(value: u8) -> DkgShareScalar {
        let mut encoded = [0_u8; 32];
        encoded[31] = value;
        DkgShareScalar::new(encoded).unwrap()
    }

    fn fake_material(method: DkgContractMethod) -> DkgTaskMaterial {
        let (indices, count, recovery_indices, has_pvss) = match method {
            DkgContractMethod::Recover => (vec![2, 7], 2, vec![2, 7], false),
            _ => ((1..=7).collect(), 7, Vec::new(), true),
        };
        DkgTaskMaterial {
            round: 1,
            method,
            sender: sender(),
            recipients: recipients(indices),
            shares: (1..=count).map(scalar).collect(),
            pvss: has_pvss.then(|| vec![0x22; crate::NEOX_DKG_PVSS_LEN].into()),
            recovery_indices,
            must_persist_store: false,
        }
    }

    fn output(count: usize, proof: bool) -> DkgProverOutput {
        DkgProverOutput {
            messages: (0..count)
                .map(|index| vec![index as u8; crate::NEOX_DKG_MESSAGE_LEN].into())
                .collect(),
            proof: proof.then(|| DkgGroth16Proof {
                proof: core::array::from_fn(|index| U256::from(index + 1)),
                commitments: [U256::from(9), U256::from(10)],
                commitment_pok: [U256::from(11), U256::from(12)],
            }),
        }
    }

    #[test]
    fn generates_share_material_before_external_proving() {
        let mut store = DkgKeyStore::new(message_key(9));
        store.bind_validator_address(sender()).unwrap();
        store.on_share_period_start(false);
        let material = generate_dkg_task_material(
            &mut store,
            sender(),
            U256::from(47_763),
            &plan(DkgContractMethod::Share),
            recipients(1..=7),
        )
        .unwrap();
        assert_eq!(material.round(), 1);
        assert_eq!(material.method(), DkgContractMethod::Share);
        assert_eq!(material.message_count(), 7);
        assert!(material.must_persist_store());
        assert_eq!(material.pvss.as_ref().unwrap().len(), crate::NEOX_DKG_PVSS_LEN);
        assert!(format!("{material:?}").contains("share_count: 7"));
        assert!(!format!("{material:?}").contains(&hex::encode(message_key(9).as_bytes())));
    }

    #[test]
    fn rejects_identity_round_and_recipient_order_before_mutation() {
        let mut store = DkgKeyStore::new(message_key(3));
        store.on_share_period_start(false);
        let share = plan(DkgContractMethod::Share);
        assert!(matches!(
            generate_dkg_task_material(
                &mut store,
                sender(),
                U256::from(47_763),
                &share,
                recipients(1..=7),
            ),
            Err(DkgTaskPreparationError::UnboundKeyStore)
        ));

        store.bind_validator_address(sender()).unwrap();
        let mut wrong_round = share.clone();
        wrong_round.round = 2;
        assert!(matches!(
            generate_dkg_task_material(
                &mut store,
                sender(),
                U256::from(47_763),
                &wrong_round,
                recipients(1..=7),
            ),
            Err(DkgTaskPreparationError::RoundMismatch { .. })
        ));
        assert!(matches!(
            generate_dkg_task_material(
                &mut store,
                sender(),
                U256::from(47_763),
                &share,
                recipients([2, 1, 3, 4, 5, 6, 7]),
            ),
            Err(DkgTaskPreparationError::RecipientOrderMismatch { .. })
        ));
    }

    #[test]
    fn maps_every_method_to_the_deployed_v0_selector() {
        let expected = [
            (DkgContractMethod::Share, hex!("d7026d83")),
            (DkgContractMethod::Reshare, hex!("685836a1")),
            (DkgContractMethod::Recover, hex!("e58dec2b")),
            (DkgContractMethod::ReshareRecovered, hex!("8c1a2bd6")),
        ];
        for (method, selector) in expected {
            let material = fake_material(method);
            let calldata =
                encode_dkg_task_output(&material, 0, output(material.message_count(), false))
                    .unwrap();
            assert_eq!(calldata[..4], selector);
        }
    }

    #[test]
    fn carries_zk_v1_proof_into_stable_calldata() {
        let material = fake_material(DkgContractMethod::Recover);
        let first = encode_dkg_task_output(&material, 1, output(2, true)).unwrap();
        let second = encode_dkg_task_output(&material, 1, output(2, true)).unwrap();
        assert_eq!(first[..4], hex!("1ae3feed"));
        assert_eq!(first, second);
    }
}
