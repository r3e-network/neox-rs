//! Proposal-level Anti-MEV Envelope discovery and DKG epoch classification.

use crate::{DkgPublicKey, DkgState};
use alloy_consensus::{transaction::SignerRecoverable, Transaction, Typed2718};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, B256};
use reth_ethereum_primitives::{Receipt, TransactionSigned};
use reth_neox_antimev::{
    aggregate_and_decrypt_keys, is_envelope, DecryptedKey, EnvelopeData, TpkeCiphertext, TpkeError,
    NEOX_DKG_SCALER,
};
use reth_neox_network::DbftPreCommit;
use thiserror::Error;

/// DKG key group that must contribute shares for an encrypted Envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeDkgEpoch {
    /// The active `KeyManagement` DKG round.
    Current,
    /// The retained reshared group used for earlier-round ciphertexts.
    Previous,
}

/// One valid, decryptable Envelope found in the primary's transaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiMevEnvelope {
    /// Position of the outer Envelope transaction in the pre-block.
    pub transaction_index: usize,
    /// DKG key group used to produce and aggregate shares.
    pub epoch: EnvelopeDkgEpoch,
    /// DKG round encoded by the sender.
    pub dkg_round: u32,
    /// Gas limit committed for the decrypted transaction.
    pub encrypted_gas: u32,
    /// Signed transaction hash committed outside the ciphertext.
    pub encrypted_hash: B256,
    /// Threshold-encrypted AES key.
    pub encrypted_key: TpkeCiphertext,
    /// AES-CBC encrypted EIP-2718 transaction bytes.
    pub encrypted_message: Bytes,
}

/// Ordered, valid Envelopes in one deterministically executed dBFT pre-block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiMevProposal {
    /// Active `KeyManagement` DKG round used by the proposal.
    pub current_round: u64,
    /// Decoded Envelopes in their original block order.
    pub envelopes: Vec<AntiMevEnvelope>,
}

/// Index-aligned outer pre-block data required to validate decrypted replacements.
#[derive(Debug, Clone, Copy)]
pub struct AntiMevPreBlock<'a> {
    /// Signed outer transactions in primary-proposed order.
    pub transactions: &'a [TransactionSigned],
    /// Recovered sender for every outer transaction.
    pub senders: &'a [Address],
    /// Receipts from deterministic pre-block execution.
    pub receipts: &'a [Receipt],
    /// Canonical parent base fee used to compare effective tips.
    pub parent_base_fee: u64,
}

/// Deterministic result of decrypting and statically validating one Envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiMevEnvelopeResolution {
    /// The signed inner transaction is eligible for sequential execution.
    Decrypted {
        /// Outer transaction position that this transaction may replace.
        transaction_index: usize,
        /// Exact EIP-2718 transaction recovered from the encrypted payload.
        transaction: Box<TransactionSigned>,
    },
    /// The outer Envelope must be executed because the inner transaction is unusable.
    Fallback {
        /// Outer transaction position retained during reconstruction.
        transaction_index: usize,
        /// Protocol reason why the decrypted transaction cannot replace its Envelope.
        reason: AntiMevFallbackReason,
    },
}

/// Per-Envelope failure that deterministically selects the original outer transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AntiMevFallbackReason {
    /// An earlier-round ciphertext was proposed after the reshared key disappeared.
    #[error("previous Neo X DKG public key is unavailable")]
    MissingPreviousDkgKey,
    /// No threshold-sized validator subset recovered every key for this epoch.
    #[error("{epoch:?} Neo X DKG shares could not be aggregated: {error}")]
    ShareAggregation {
        /// DKG epoch whose shares failed.
        epoch: EnvelopeDkgEpoch,
        /// Threshold-cryptography failure.
        error: TpkeError,
    },
    /// The recovered point could not decrypt a strictly padded AES-CBC payload.
    #[error("Envelope AES payload could not be decrypted: {0}")]
    AesDecryption(TpkeError),
    /// Decrypted bytes were not exactly one signed EIP-2718 transaction.
    #[error("Envelope plaintext is not one exact signed EIP-2718 transaction")]
    TransactionDecoding,
    /// Neo X's static transaction pool does not accept blob transactions.
    #[error("decrypted blob transactions are unsupported")]
    UnsupportedBlobTransaction,
    /// The inner transaction cannot replace a different sender nonce.
    #[error("decrypted nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Outer Envelope nonce.
        expected: u64,
        /// Decrypted transaction nonce.
        actual: u64,
    },
    /// The inner transaction pays a lower effective tip than its Envelope.
    #[error("decrypted effective tip is underpriced: expected at least {minimum}, got {actual}")]
    Underpriced {
        /// Outer Envelope effective tip at the parent base fee.
        minimum: u128,
        /// Decrypted transaction effective tip at the parent base fee.
        actual: u128,
    },
    /// The inner transaction signature could not recover an account.
    #[error("decrypted transaction has an invalid sender signature")]
    SenderRecovery,
    /// Envelope and inner transaction were not signed by the same account.
    #[error("decrypted sender mismatch: expected {expected}, got {actual}")]
    SenderMismatch {
        /// Recovered outer Envelope sender.
        expected: Address,
        /// Recovered decrypted transaction sender.
        actual: Address,
    },
    /// The signed inner transaction differs from the hash committed in cleartext.
    #[error("decrypted transaction hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Hash committed by the outer Envelope.
        expected: B256,
        /// Hash of the signed decrypted transaction.
        actual: B256,
    },
    /// The inner gas limit differs from the Envelope cleartext commitment.
    #[error("decrypted gas mismatch: expected {expected}, got {actual}")]
    GasMismatch {
        /// Gas limit committed by the outer Envelope.
        expected: u64,
        /// Decrypted transaction gas limit.
        actual: u64,
    },
    /// The pre-block Envelope did not consume enough gas to reserve the inner gas limit.
    #[error("decrypted gas {required} exceeds Envelope allocation {allocated}")]
    GasNotAllocated {
        /// Decrypted transaction gas limit.
        required: u64,
        /// Gas consumed by the outer Envelope in the verified pre-block.
        allocated: u64,
    },
}

/// Proposal-wide structural error that prevents deterministic Envelope resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AntiMevResolutionError {
    /// The proposal was classified against a different current DKG round.
    #[error("Anti-MEV DKG round mismatch: proposal {proposal}, state {state}")]
    DkgRoundMismatch {
        /// Round used while classifying Envelope payloads.
        proposal: u64,
        /// Current round read from the parent state.
        state: u64,
    },
    /// Transactions, recovered senders, and pre-block receipts must remain index-aligned.
    #[error(
        "Anti-MEV pre-block data length mismatch: {transactions} transactions, {senders} senders, {receipts} receipts"
    )]
    BlockDataLengthMismatch {
        /// Outer transaction count.
        transactions: usize,
        /// Recovered outer sender count.
        senders: usize,
        /// Pre-block receipt count.
        receipts: usize,
    },
    /// A manually constructed proposal referenced no transaction at its recorded position.
    #[error("Envelope transaction index {index} is outside a {transactions}-transaction block")]
    EnvelopeIndexOutOfBounds {
        /// Invalid Envelope position.
        index: usize,
        /// Outer transaction count.
        transactions: usize,
    },
    /// Reth receipts must contain a monotonic cumulative gas sequence.
    #[error(
        "pre-block cumulative gas decreased at receipt {index}: previous {previous}, current {current}"
    )]
    NonMonotonicCumulativeGas {
        /// Receipt position containing the decrease.
        index: usize,
        /// Prior cumulative gas.
        previous: u64,
        /// Current cumulative gas.
        current: u64,
    },
}

impl AntiMevProposal {
    /// Discovers Envelopes exactly as Neo X Geth's pre-block path does.
    ///
    /// Malformed reserved calldata remains an ordinary outer transaction. Valid ciphertexts from
    /// the active round use the current key; nonzero earlier rounds use the retained reshared key.
    pub fn from_transactions(transactions: &[TransactionSigned], current_round: u64) -> Self {
        let mut envelopes = Vec::new();
        for (transaction_index, transaction) in transactions.iter().enumerate() {
            if !is_envelope(transaction.ty(), transaction.to(), transaction.input()) {
                continue
            }
            let Ok(data) = EnvelopeData::decode(transaction.input()) else { continue };
            let encoded_round = u64::from(data.dkg_round);
            if encoded_round == 0 || encoded_round > current_round {
                continue
            }
            let epoch = if encoded_round == current_round {
                EnvelopeDkgEpoch::Current
            } else {
                EnvelopeDkgEpoch::Previous
            };
            envelopes.push(AntiMevEnvelope {
                transaction_index,
                epoch,
                dkg_round: data.dkg_round,
                encrypted_gas: data.encrypted_gas,
                encrypted_hash: data.encrypted_hash,
                encrypted_key: data.encrypted_key,
                encrypted_message: Bytes::copy_from_slice(data.encrypted_message),
            });
        }
        Self { current_round, envelopes }
    }

    /// Number of semantically valid Envelope payloads used for `PreCommit` bounds.
    pub const fn len(&self) -> usize {
        self.envelopes.len()
    }

    /// Returns whether this proposal has no decryptable Envelope payloads.
    pub const fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }

    /// Returns ciphertexts for one DKG key group in original Envelope order.
    pub fn ciphertexts(&self, epoch: EnvelopeDkgEpoch) -> Vec<TpkeCiphertext> {
        self.envelopes
            .iter()
            .filter(|envelope| envelope.epoch == epoch)
            .map(|envelope| envelope.encrypted_key)
            .collect()
    }

    /// Aggregates dBFT `PreCommit` shares, decrypts Envelope payloads, and applies Geth-compatible
    /// static replacement checks.
    ///
    /// Cryptographic or transaction-level failures resolve only the affected epoch or Envelope to
    /// its outer transaction. Misaligned block inputs are rejected because they would make the
    /// receipt gas allocation and sender binding nondeterministic.
    pub fn decrypt_and_validate(
        &self,
        contributions: &[(u32, &DbftPreCommit)],
        dkg_state: &DkgState,
        threshold: usize,
        pre_block: AntiMevPreBlock<'_>,
    ) -> Result<Vec<AntiMevEnvelopeResolution>, AntiMevResolutionError> {
        if dkg_state.current.round != self.current_round {
            return Err(AntiMevResolutionError::DkgRoundMismatch {
                proposal: self.current_round,
                state: dkg_state.current.round,
            })
        }
        if pre_block.transactions.len() != pre_block.senders.len() ||
            pre_block.transactions.len() != pre_block.receipts.len()
        {
            return Err(AntiMevResolutionError::BlockDataLengthMismatch {
                transactions: pre_block.transactions.len(),
                senders: pre_block.senders.len(),
                receipts: pre_block.receipts.len(),
            })
        }
        for envelope in &self.envelopes {
            if envelope.transaction_index >= pre_block.transactions.len() {
                return Err(AntiMevResolutionError::EnvelopeIndexOutOfBounds {
                    index: envelope.transaction_index,
                    transactions: pre_block.transactions.len(),
                })
            }
        }

        let mut gas_allocations = Vec::with_capacity(pre_block.receipts.len());
        let mut previous = 0_u64;
        for (index, receipt) in pre_block.receipts.iter().enumerate() {
            let current = receipt.cumulative_gas_used;
            let Some(allocated) = current.checked_sub(previous) else {
                return Err(AntiMevResolutionError::NonMonotonicCumulativeGas {
                    index,
                    previous,
                    current,
                })
            };
            gas_allocations.push(allocated);
            previous = current;
        }

        let current_keys = decrypt_epoch_keys(
            self,
            EnvelopeDkgEpoch::Current,
            Some(&dkg_state.current),
            contributions,
            threshold,
        );
        let previous_keys = decrypt_epoch_keys(
            self,
            EnvelopeDkgEpoch::Previous,
            dkg_state.previous.as_ref(),
            contributions,
            threshold,
        );
        let mut current_index = 0;
        let mut previous_index = 0;
        let mut resolutions = Vec::with_capacity(self.envelopes.len());
        for envelope in &self.envelopes {
            let key = match envelope.epoch {
                EnvelopeDkgEpoch::Current => {
                    let result = current_keys.as_ref().map(|keys| keys[current_index]);
                    current_index += 1;
                    result
                }
                EnvelopeDkgEpoch::Previous => {
                    let result = previous_keys.as_ref().map(|keys| keys[previous_index]);
                    previous_index += 1;
                    result
                }
            };
            let transaction_index = envelope.transaction_index;
            let resolution = match key {
                Err(reason) => {
                    AntiMevEnvelopeResolution::Fallback { transaction_index, reason: *reason }
                }
                Ok(key) => match decrypt_transaction(&key, envelope) {
                    Err(reason) => {
                        AntiMevEnvelopeResolution::Fallback { transaction_index, reason }
                    }
                    Ok(transaction) => match validate_decrypted_transaction(
                        envelope,
                        &transaction,
                        &pre_block.transactions[transaction_index],
                        pre_block.senders[transaction_index],
                        gas_allocations[transaction_index],
                        pre_block.parent_base_fee,
                    ) {
                        Ok(()) => AntiMevEnvelopeResolution::Decrypted {
                            transaction_index,
                            transaction: Box::new(transaction),
                        },
                        Err(reason) => {
                            AntiMevEnvelopeResolution::Fallback { transaction_index, reason }
                        }
                    },
                },
            };
            resolutions.push(resolution);
        }
        Ok(resolutions)
    }
}

fn decrypt_epoch_keys(
    proposal: &AntiMevProposal,
    epoch: EnvelopeDkgEpoch,
    public_key: Option<&DkgPublicKey>,
    contributions: &[(u32, &DbftPreCommit)],
    threshold: usize,
) -> Result<Vec<DecryptedKey>, AntiMevFallbackReason> {
    let ciphertexts = proposal.ciphertexts(epoch);
    if ciphertexts.is_empty() {
        return Ok(Vec::new())
    }
    let Some(public_key) = public_key else {
        return Err(AntiMevFallbackReason::MissingPreviousDkgKey)
    };
    let contributions = contributions
        .iter()
        .map(|(index, pre_commit)| {
            let shares = match epoch {
                EnvelopeDkgEpoch::Current => pre_commit.current_round.clone(),
                EnvelopeDkgEpoch::Previous => pre_commit.previous_round.clone(),
            };
            (*index, shares)
        })
        .collect::<Vec<_>>();
    aggregate_and_decrypt_keys(
        &ciphertexts,
        &public_key.global_public_key,
        &contributions,
        threshold,
        NEOX_DKG_SCALER,
    )
    .map_err(|error| AntiMevFallbackReason::ShareAggregation { epoch, error })
}

fn decrypt_transaction(
    key: &DecryptedKey,
    envelope: &AntiMevEnvelope,
) -> Result<TransactionSigned, AntiMevFallbackReason> {
    let plaintext = key
        .decrypt_message(&envelope.encrypted_message)
        .map_err(AntiMevFallbackReason::AesDecryption)?;
    TransactionSigned::decode_2718_exact(&plaintext)
        .map_err(|_| AntiMevFallbackReason::TransactionDecoding)
}

fn validate_decrypted_transaction(
    envelope: &AntiMevEnvelope,
    decrypted: &TransactionSigned,
    outer: &TransactionSigned,
    outer_sender: Address,
    allocated_gas: u64,
    parent_base_fee: u64,
) -> Result<(), AntiMevFallbackReason> {
    if decrypted.is_eip4844() {
        return Err(AntiMevFallbackReason::UnsupportedBlobTransaction)
    }
    if decrypted.nonce() != outer.nonce() {
        return Err(AntiMevFallbackReason::NonceMismatch {
            expected: outer.nonce(),
            actual: decrypted.nonce(),
        })
    }
    let minimum = outer.effective_tip_per_gas(parent_base_fee).unwrap_or_default();
    let actual = decrypted.effective_tip_per_gas(parent_base_fee).unwrap_or_default();
    if actual < minimum {
        return Err(AntiMevFallbackReason::Underpriced { minimum, actual })
    }
    let decrypted_sender =
        decrypted.recover_signer().map_err(|_| AntiMevFallbackReason::SenderRecovery)?;
    if decrypted_sender != outer_sender {
        return Err(AntiMevFallbackReason::SenderMismatch {
            expected: outer_sender,
            actual: decrypted_sender,
        })
    }
    let actual_hash = *decrypted.tx_hash();
    if actual_hash != envelope.encrypted_hash {
        return Err(AntiMevFallbackReason::HashMismatch {
            expected: envelope.encrypted_hash,
            actual: actual_hash,
        })
    }
    let expected_gas = u64::from(envelope.encrypted_gas);
    let actual_gas = decrypted.gas_limit();
    if actual_gas != expected_gas {
        return Err(AntiMevFallbackReason::GasMismatch {
            expected: expected_gas,
            actual: actual_gas,
        })
    }
    if actual_gas > allocated_gas {
        return Err(AntiMevFallbackReason::GasNotAllocated {
            required: actual_gas,
            allocated: allocated_gas,
        })
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{hex, Address, Signature, TxKind};
    use reth_ethereum_primitives::{Transaction as EthereumTransaction, TxType as EthereumTxType};
    use reth_neox_antimev::{
        DecryptionShare, ENCRYPTED_DATA_PREFIX, ENVELOPE_TARGET, G1_EIP2537_LEN,
        MIN_ENCRYPTED_MESSAGE_LEN,
    };
    use reth_primitives_traits::crypto::secp256k1::sign_message;

    const CIPHERTEXT: [u8; 192] = hex!(
        "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
         966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
         8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
         8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
         cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
         17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
    );
    const THRESHOLD_PUBLIC: [u8; 48] = hex!(
        "a9aff13809f72c4c35e2196675fd26a0d0d077ca35c6d4f05bd471deba419f66\
         a303935358a8abf7a8ef3b76e67072c2"
    );
    const THRESHOLD_CIPHERTEXT: [u8; 192] = hex!(
        "8418bd4bd31c6edc5b4c62e92d5f4823ec68866e7b8b41726c0dfd30ca6132c5\
         c117c02251bc725c44348741141a4d0da19380790417c8ee14a30e3ff44f06f6\
         df21976cd24894cf784da5708fde08d0e02b51be1e375dee205f4a98198c5e3e\
         8b947bc9dfb76541a6c5e3672d97119eb86699d2eae60459c39593ffb48fe9ce\
         34f29959376387ab4e7054bcaba5110418508378f8d1e20a606287ab36d9a167\
         9b7a16747fd14ba12909fab4bbc9fc5ba39a04ef61dbdb29097a2d5403826897"
    );
    const THRESHOLD_SHARES: [(u32, [u8; 48]); 5] = [
        (
            1,
            hex!(
                "83539765592bf2bde85abfed46ca18c9fd18eba94b8d180aa608aac4d15db124\
                 d665b79ac3c01ed2d06216197b34f08b"
            ),
        ),
        (
            2,
            hex!(
                "8cb3077295c815d275c08515a1aad8f9f1f66c1f9d0326f89cee56344de23bf9\
                 6cd955315a460f0c6b83c2560a0f8d49"
            ),
        ),
        (
            4,
            hex!(
                "94a618b9b24c336a530362cec808f81699a5bb6c8f994d2b9393a9df82bd4c16\
                 b3b8987337c97fa9d1058320784aabe5"
            ),
        ),
        (
            6,
            hex!(
                "807fb76b7fb43d0c49ea7eebcf3ac01c5a6e88d2d9ab872b65845b15ae6c379\
                 b5c753f4213f4f22db50ed1e65ac2e44f"
            ),
        ),
        (
            7,
            hex!(
                "85651e6c1ed980dcbe3745e699c5c6d265c3332c83922680e5d9834ccd9fc96a\
                 e83fac254c7ac514adc35cdab1a98793"
            ),
        ),
    ];

    fn envelope(round: u32, target: Address) -> TransactionSigned {
        let mut input = Vec::new();
        input.extend_from_slice(&ENCRYPTED_DATA_PREFIX);
        input.extend_from_slice(&round.to_be_bytes());
        input.extend_from_slice(&35_000_u32.to_be_bytes());
        input.extend_from_slice(B256::repeat_byte(round as u8).as_slice());
        input.extend_from_slice(&CIPHERTEXT);
        input.resize(input.len() + MIN_ENCRYPTED_MESSAGE_LEN, 0x42);
        TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                to: TxKind::Call(target),
                input: input.into(),
                ..Default::default()
            }),
            Signature::test_signature(),
        )
    }

    fn signed_legacy(transaction: TxLegacy) -> TransactionSigned {
        let transaction = EthereumTransaction::Legacy(transaction);
        let signature =
            sign_message(B256::repeat_byte(0x11), transaction.signature_hash()).unwrap();
        TransactionSigned::new_unhashed(transaction, signature)
    }

    #[test]
    fn preserves_order_and_classifies_current_and_prior_rounds() {
        let transactions = [
            envelope(0, ENVELOPE_TARGET),
            envelope(7, ENVELOPE_TARGET),
            envelope(8, ENVELOPE_TARGET),
            envelope(9, ENVELOPE_TARGET),
            envelope(8, Address::ZERO),
        ];
        let proposal = AntiMevProposal::from_transactions(&transactions, 8);
        assert_eq!(proposal.len(), 2);
        assert_eq!(proposal.envelopes[0].transaction_index, 1);
        assert_eq!(proposal.envelopes[0].epoch, EnvelopeDkgEpoch::Previous);
        assert_eq!(proposal.envelopes[1].transaction_index, 2);
        assert_eq!(proposal.envelopes[1].epoch, EnvelopeDkgEpoch::Current);
        assert_eq!(proposal.ciphertexts(EnvelopeDkgEpoch::Current).len(), 1);
        assert_eq!(proposal.ciphertexts(EnvelopeDkgEpoch::Previous).len(), 1);
    }

    #[test]
    fn aggregates_geth_quorum_before_falling_back_on_invalid_aes() {
        let outer = envelope(8, ENVELOPE_TARGET);
        let outer_sender = outer.recover_signer().unwrap();
        let proposal = AntiMevProposal {
            current_round: 8,
            envelopes: vec![AntiMevEnvelope {
                transaction_index: 0,
                epoch: EnvelopeDkgEpoch::Current,
                dkg_round: 8,
                encrypted_gas: 35_000,
                encrypted_hash: B256::ZERO,
                encrypted_key: TpkeCiphertext::decode(&THRESHOLD_CIPHERTEXT).unwrap(),
                encrypted_message: Bytes::new(),
            }],
        };
        let dkg_state = DkgState {
            current: DkgPublicKey {
                round: 8,
                commitment: [0; G1_EIP2537_LEN],
                global_public_key: THRESHOLD_PUBLIC,
            },
            previous: None,
        };
        let pre_commits = THRESHOLD_SHARES
            .iter()
            .map(|(_, share)| DbftPreCommit {
                current_round: vec![DecryptionShare::decode(share).unwrap()],
                previous_round: Vec::new(),
                data: Bytes::new(),
            })
            .collect::<Vec<_>>();
        let contributions = THRESHOLD_SHARES
            .iter()
            .zip(&pre_commits)
            .map(|((index, _), pre_commit)| (*index, pre_commit))
            .collect::<Vec<_>>();
        let receipts = [Receipt {
            tx_type: EthereumTxType::Legacy,
            cumulative_gas_used: 35_000,
            ..Default::default()
        }];

        let resolutions = proposal
            .decrypt_and_validate(
                &contributions,
                &dkg_state,
                5,
                AntiMevPreBlock {
                    transactions: std::slice::from_ref(&outer),
                    senders: &[outer_sender],
                    receipts: &receipts,
                    parent_base_fee: 1,
                },
            )
            .unwrap();
        assert_eq!(
            resolutions,
            [AntiMevEnvelopeResolution::Fallback {
                transaction_index: 0,
                reason: AntiMevFallbackReason::AesDecryption(
                    TpkeError::InvalidAesCiphertextLength { actual: 0 }
                ),
            }]
        );
    }

    #[test]
    fn enforces_static_sender_hash_tip_nonce_and_gas_binding() {
        let inner = signed_legacy(TxLegacy {
            nonce: 7,
            gas_price: 20,
            gas_limit: 35_000,
            to: TxKind::Call(Address::repeat_byte(0x44)),
            ..Default::default()
        });
        let outer = signed_legacy(TxLegacy {
            nonce: 7,
            gas_price: 10,
            gas_limit: 80_000,
            to: TxKind::Call(ENVELOPE_TARGET),
            input: Bytes::from_static(b"Envelope"),
            ..Default::default()
        });
        let envelope = AntiMevEnvelope {
            transaction_index: 0,
            epoch: EnvelopeDkgEpoch::Current,
            dkg_round: 8,
            encrypted_gas: 35_000,
            encrypted_hash: *inner.tx_hash(),
            encrypted_key: TpkeCiphertext::decode(&CIPHERTEXT).unwrap(),
            encrypted_message: Bytes::new(),
        };
        let outer_sender = outer.recover_signer().unwrap();

        assert_eq!(
            validate_decrypted_transaction(&envelope, &inner, &outer, outer_sender, 35_000, 5),
            Ok(())
        );
        assert_eq!(
            validate_decrypted_transaction(&envelope, &inner, &outer, outer_sender, 34_999, 5),
            Err(AntiMevFallbackReason::GasNotAllocated { required: 35_000, allocated: 34_999 })
        );
    }
}
