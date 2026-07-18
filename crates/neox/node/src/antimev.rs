//! Proposal-level Anti-MEV Envelope discovery and DKG epoch classification.

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{Bytes, B256};
use reth_ethereum_primitives::TransactionSigned;
use reth_neox_antimev::{is_envelope, EnvelopeData, TpkeCiphertext};

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
            if encoded_round > current_round {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxLegacy;
    use alloy_primitives::{hex, Address, Signature, TxKind};
    use reth_ethereum_primitives::Transaction as EthereumTransaction;
    use reth_neox_antimev::{ENCRYPTED_DATA_PREFIX, ENVELOPE_TARGET, MIN_ENCRYPTED_MESSAGE_LEN};

    const CIPHERTEXT: [u8; 192] = hex!(
        "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
         966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
         8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
         8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
         cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
         17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
    );

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

    #[test]
    fn preserves_order_and_classifies_current_and_prior_rounds() {
        let transactions = [
            envelope(7, ENVELOPE_TARGET),
            envelope(8, ENVELOPE_TARGET),
            envelope(9, ENVELOPE_TARGET),
            envelope(8, Address::ZERO),
        ];
        let proposal = AntiMevProposal::from_transactions(&transactions, 8);
        assert_eq!(proposal.len(), 2);
        assert_eq!(proposal.envelopes[0].transaction_index, 0);
        assert_eq!(proposal.envelopes[0].epoch, EnvelopeDkgEpoch::Previous);
        assert_eq!(proposal.envelopes[1].transaction_index, 1);
        assert_eq!(proposal.envelopes[1].epoch, EnvelopeDkgEpoch::Current);
        assert_eq!(proposal.ciphertexts(EnvelopeDkgEpoch::Current).len(), 1);
        assert_eq!(proposal.ciphertexts(EnvelopeDkgEpoch::Previous).len(), 1);
    }
}
