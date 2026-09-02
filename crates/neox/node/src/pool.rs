//! Neo X transaction-pool construction and parent-state policy validation.

use alloy_consensus::{Transaction, Typed2718};
use alloy_primitives::{Address, U256};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_neox_antimev::{
    encrypted_gas, is_envelope, EnvelopeData, TpkeError, MIN_ENCRYPTED_GAS_LIMIT,
};
use reth_neox_evm::{
    policy_blacklist_storage_key, policy_storage_key, POLICY_BASE_FEE_SLOT,
    POLICY_ENVELOPE_FEE_SLOT, POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT,
    POLICY_PROXY_ADDRESS,
};
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_node_builder::{
    components::{PoolBuilder, TxPoolBuilder},
    BuilderContext, FullNodeTypes, NodeTypes,
};
use reth_primitives_traits::SealedBlock;
use reth_provider::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore,
    error::{InvalidPoolTransactionError, PoolTransactionError},
    CoinbaseTipOrdering, EthPooledTransaction, EthTransactionValidator, Pool, PoolTransaction,
    TransactionOrigin, TransactionValidationOutcome, TransactionValidationTaskExecutor,
    TransactionValidator,
};
use std::{any::Any, fmt};
use thiserror::Error;
use tracing::{debug, info};

/// Builds an Ethereum-format pool with Neo X `PolicyProxy` validation.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeoXPoolBuilder;

/// Pins one state snapshot for standard Ethereum and Neo X policy validation.
pub struct NeoXTransactionValidator<Client, Evm> {
    inner: EthTransactionValidator<Client, EthPooledTransaction, Evm>,
    provider: Client,
}

impl<Client, Evm> fmt::Debug for NeoXTransactionValidator<Client, Evm> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("NeoXTransactionValidator").finish_non_exhaustive()
    }
}

impl<Client, Evm> NeoXTransactionValidator<Client, Evm>
where
    Client: ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks> + StateProviderFactory,
    Evm: ConfigureEvm,
{
    /// Runs stateful Ethereum checks followed by Neo X checks on the same pinned state.
    /// The caller must first run `validate_stateless`.
    fn validate_stateful_with_neox(
        &self,
        origin: TransactionOrigin,
        transaction: EthPooledTransaction,
        state: &dyn StateProvider,
    ) -> TransactionValidationOutcome<EthPooledTransaction> {
        let outcome = self.inner.validate_stateful(origin, transaction, state);
        let Some(valid) = outcome.as_valid_transaction() else { return outcome };
        let transaction = valid.transaction();
        let error = validate_envelope_ciphertext(
            transaction.ty(),
            transaction.kind().to().copied(),
            transaction.input(),
        )
        .and_then(|()| validate_policy(transaction, state))
        .err();
        let Some(error) = error else { return outcome };
        let TransactionValidationOutcome::Valid { transaction, .. } = outcome else {
            unreachable!("valid transaction was checked above")
        };
        TransactionValidationOutcome::Invalid(transaction.into_transaction(), error)
    }

    fn provider_error(
        transaction: &EthPooledTransaction,
        error: impl fmt::Display,
    ) -> TransactionValidationOutcome<EthPooledTransaction> {
        TransactionValidationOutcome::Error(
            *transaction.hash(),
            Box::new(NeoXPoolPolicyError::Provider(error.to_string())),
        )
    }
}

/// Rejects a decoded Envelope whose TPKE commitments do not contain the same scalar.
///
/// Reserved calldata that fails Envelope decoding remains an ordinary outer transaction, matching
/// the reference client's proposal classification. Transaction types excluded from Anti-MEV
/// Envelope handling likewise retain their ordinary transaction-pool behavior; consensus execution
/// applies its separate target/calldata Policy predicate.
pub(crate) fn validate_envelope_ciphertext(
    tx_type: u8,
    target: Option<Address>,
    input: &[u8],
) -> Result<(), InvalidPoolTransactionError> {
    if !is_envelope(tx_type, target, input) {
        return Ok(())
    }
    let Ok(envelope) = EnvelopeData::decode(input) else { return Ok(()) };
    envelope
        .encrypted_key
        .verify()
        .map_err(|error| NeoXPoolPolicyError::InvalidEnvelopeCiphertext(error).into())
}

impl<Client, Evm> TransactionValidator for NeoXTransactionValidator<Client, Evm>
where
    Client: ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
        + StateProviderFactory
        + Sync,
    Evm: ConfigureEvm,
{
    type Transaction = EthPooledTransaction;
    type Block =
        <EthTransactionValidator<Client, EthPooledTransaction, Evm> as TransactionValidator>::Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        if let Err(error) = self.inner.validate_stateless(origin, &transaction) {
            return TransactionValidationOutcome::Invalid(transaction, error)
        }
        let state = match self.provider.latest() {
            Ok(state) => state,
            Err(error) => return Self::provider_error(&transaction, error),
        };
        self.validate_stateful_with_neox(origin, transaction, state.as_ref())
    }

    async fn validate_transactions(
        &self,
        transactions: impl IntoIterator<Item = (TransactionOrigin, Self::Transaction), IntoIter: Send>
            + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let transactions = transactions.into_iter().collect::<Vec<_>>();
        let mut state = None;
        transactions
            .into_iter()
            .map(|(origin, transaction)| {
                if let Err(error) = self.inner.validate_stateless(origin, &transaction) {
                    return TransactionValidationOutcome::Invalid(transaction, error)
                }
                let state = state.get_or_insert_with(|| {
                    self.provider.latest().map_err(|error| error.to_string())
                });
                match state {
                    Ok(state) => {
                        self.validate_stateful_with_neox(origin, transaction, state.as_ref())
                    }
                    Err(error) => Self::provider_error(&transaction, error),
                }
            })
            .collect()
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction, IntoIter: Send> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_transactions(
            transactions.into_iter().map(|transaction| (origin, transaction)),
        )
        .await
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        TransactionValidator::on_new_head_block(&self.inner, new_tip_block)
    }
}

impl<Types, Node, Evm> PoolBuilder<Node, Evm> for NeoXPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: reth_chainspec::EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = reth_ethereum_primitives::TransactionSigned>,
    >,
    Node: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = Pool<
        TransactionValidationTaskExecutor<NeoXTransactionValidator<Node::Provider, Evm>>,
        CoinbaseTipOrdering<EthPooledTransaction>,
        DiskFileBlobStore,
    >;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();
        let blobs_disabled = ctx.config().txpool.disable_blobs_support ||
            ctx.config().txpool.blobpool_max_count == 0;
        let blob_store = reth_node_builder::components::create_blob_store(ctx)?;

        let builder =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .set_eip4844(!blobs_disabled)
                .kzg_settings(ctx.kzg_settings()?)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee);
        let validator = builder.build::<EthPooledTransaction, _>(blob_store.clone());

        if validator.eip4844() {
            let kzg_settings = validator.kzg_settings().clone();
            ctx.task_executor().spawn_blocking_task(async move {
                let _ = kzg_settings.get();
                debug!(target: "reth::cli", "Initialized KZG settings");
            });
        }

        let validator = TransactionValidationTaskExecutor::spawn(
            NeoXTransactionValidator { inner: validator, provider: ctx.provider().clone() },
            ctx.task_executor(),
            ctx.config().txpool.additional_validation_tasks,
        );
        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "reth::cli", "Neo X policy-aware transaction pool initialized");
        debug!(target: "reth::cli", "Spawned Neo X txpool maintenance task");
        Ok(transaction_pool)
    }
}

fn validate_policy(
    tx: &EthPooledTransaction,
    state: &dyn StateProvider,
) -> Result<(), InvalidPoolTransactionError> {
    let blocked = state
        .storage(POLICY_PROXY_ADDRESS, policy_blacklist_storage_key(tx.sender()).into())
        .map_err(|error| NeoXPoolPolicyError::Provider(error.to_string()))?
        .unwrap_or_default();
    if !blocked.is_zero() {
        return Err(NeoXPoolPolicyError::BlockedSender(tx.sender()).into());
    }

    let base_fee = read_policy_slot(state, POLICY_BASE_FEE_SLOT)?;
    let base_fee_u64 =
        u64::try_from(base_fee).map_err(|_| NeoXPoolPolicyError::BaseFeeOutOfRange(base_fee))?;
    let mut minimum_tip = read_policy_slot(state, POLICY_MIN_GAS_TIP_CAP_SLOT)?;
    let envelope = is_envelope(tx.ty(), tx.kind().to().copied(), tx.input());

    if envelope {
        let maximum_gas = read_policy_slot(state, POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT)?;
        if U256::from(tx.gas_limit()) > maximum_gas {
            return Err(NeoXPoolPolicyError::EnvelopeGasAbovePolicy {
                gas_limit: tx.gas_limit(),
                maximum_gas,
            }
            .into());
        }

        let inner_gas = encrypted_gas(tx.input());
        if inner_gas < MIN_ENCRYPTED_GAS_LIMIT {
            return Err(NeoXPoolPolicyError::EncryptedGasBelowMinimum(inner_gas).into());
        }
        if tx.gas_limit() < u64::from(inner_gas) {
            return Err(NeoXPoolPolicyError::EnvelopeGasBelowEncrypted {
                gas_limit: tx.gas_limit(),
                inner_gas,
            }
            .into());
        }

        minimum_tip =
            minimum_tip.saturating_add(read_policy_slot(state, POLICY_ENVELOPE_FEE_SLOT)?);
    }

    let effective_tip = tx.effective_tip_per_gas(base_fee_u64).unwrap_or_default();
    if U256::from(effective_tip) < minimum_tip {
        return Err(
            NeoXPoolPolicyError::TipBelowPolicy { effective_tip, minimum_tip, base_fee }.into()
        );
    }
    Ok(())
}

fn read_policy_slot(
    state: &dyn StateProvider,
    slot: u64,
) -> Result<U256, InvalidPoolTransactionError> {
    state
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(slot).into())
        .map(|value| value.unwrap_or_default())
        .map_err(|error| NeoXPoolPolicyError::Provider(error.to_string()).into())
}

#[derive(Debug, Error)]
enum NeoXPoolPolicyError {
    #[error("failed to read Neo X policy state: {0}")]
    Provider(String),
    #[error("transaction sender {0} is blacklisted by Neo X PolicyProxy")]
    BlockedSender(Address),
    #[error("Neo X PolicyProxy base fee does not fit the execution header: {0}")]
    BaseFeeOutOfRange(U256),
    #[error("Envelope gas limit {gas_limit} exceeds Neo X policy maximum {maximum_gas}")]
    EnvelopeGasAbovePolicy { gas_limit: u64, maximum_gas: U256 },
    #[error("encrypted transaction gas {0} is below the Neo X minimum")]
    EncryptedGasBelowMinimum(u32),
    #[error("Envelope gas limit {gas_limit} is below encrypted transaction gas {inner_gas}")]
    EnvelopeGasBelowEncrypted { gas_limit: u64, inner_gas: u32 },
    #[error("invalid Neo X Envelope TPKE commitment: {0}")]
    InvalidEnvelopeCiphertext(TpkeError),
    #[error(
        "effective tip {effective_tip} is below Neo X policy minimum {minimum_tip} at base fee {base_fee}"
    )]
    TipBelowPolicy { effective_tip: u128, minimum_tip: U256, base_fee: U256 },
}

impl From<NeoXPoolPolicyError> for InvalidPoolTransactionError {
    fn from(error: NeoXPoolPolicyError) -> Self {
        Self::Other(Box::new(error))
    }
}

impl PoolTransactionError for NeoXPoolPolicyError {
    fn is_bad_transaction(&self) -> bool {
        matches!(self, Self::InvalidEnvelopeCiphertext(_))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{TxLegacy, TxType};
    use alloy_primitives::{hex, Signature, TxKind, B256};
    use reth_ethereum_primitives::{
        EthPrimitives, Transaction as EthereumTransaction, TransactionSigned,
    };
    use reth_neox_antimev::{
        is_envelope_policy, ENCRYPTED_DATA_PREFIX, ENVELOPE_TARGET, MIN_ENCRYPTED_MESSAGE_LEN,
        TPKE_SERIALIZED_LEN,
    };
    use reth_neox_chainspec::NeoXChainSpec;
    use reth_neox_evm::NeoXEvmConfig;
    use reth_primitives_traits::Recovered;
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
    };

    const VALID_CIPHERTEXT: [u8; TPKE_SERIALIZED_LEN] = hex!(
        "a9884044ee5f73bde4a4289d3a2b28f3a0adedb046352b8b05619da738b9b8d1\
         966be79a7203ba1ca2d41109afbc17f48fa8176be805721fa998f38061ce4ca48\
         8468ce20267e9e4fb21c1b99961a4230a3b9d94daa84d97d68bc1b3e9e58e51\
         8c167911bdfa3cca2c9f2e8822fe89c72180a23c9373e825acbd297b49682b38\
         cc3a418136a0272552e80e0f0507d82e01ad3b5e639faa0cc6e657f92a41861\
         17d27fb15ac32b1c23d765edbee01ebfe4c70c076c6f64139c4d72f80f25e8044"
    );

    fn envelope_input(ciphertext: &[u8; TPKE_SERIALIZED_LEN]) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&ENCRYPTED_DATA_PREFIX);
        input.extend_from_slice(&8_u32.to_be_bytes());
        input.extend_from_slice(&35_000_u32.to_be_bytes());
        input.extend_from_slice(B256::repeat_byte(0x42).as_slice());
        input.extend_from_slice(ciphertext);
        input.resize(input.len() + MIN_ENCRYPTED_MESSAGE_LEN, 0x42);
        input
    }

    fn pooled_legacy(input: Vec<u8>, gas_limit: u64) -> EthPooledTransaction {
        let transaction = TransactionSigned::new_unhashed(
            EthereumTransaction::Legacy(TxLegacy {
                gas_limit,
                gas_price: 1_000_000_000,
                to: TxKind::Call(ENVELOPE_TARGET),
                input: input.into(),
                ..Default::default()
            }),
            Signature::test_signature(),
        );
        EthPooledTransaction::try_from_consensus(Recovered::new_unchecked(
            transaction,
            Address::repeat_byte(0x11),
        ))
        .unwrap()
    }

    /// Ciphertext whose three points are individually valid but whose pairing relation is broken.
    ///
    /// Exported by `antimev.TestCiphertextAdmission` in `bane-labs/go-ethereum`
    /// (branch `bane-main`, commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`). Geth's
    /// `CipherText.FromBytes` accepts it and `decodeEnvelopeData` classifies the Envelope as
    /// decryptable, but Geth never calls `CipherText.Verify` and so never notices.
    const ADMISSION_CIPHERTEXT_INVALID: [u8; TPKE_SERIALIZED_LEN] = hex!(
        "93fba03e0bfc956e31ee8ea0bde3fa216b17d63decfe64438a9932f321e0bc9a\
        cc07e4a6415403c102e08271bd03b573b84a261128e5ff6d4a55b73544c2b418\
        e701142c81f9a00c7dbe18bc3fd1bdb8796e127f3815c5c31978a959c6bc98c7\
        b8f8bde02928c51639a721235b63c6fa818d48a5e043fe4f756fa4bd654a3ddc\
        20509000c1bf177474f23f48995119ba0bcbe7e695c5ac90a0599c8c851b400a\
        5592aaa2e70f3f33fc1325dca280bc8dc3fe1a12fee8a0dcc5cd69bcfa4f8179"
    );

    /// Mempool admission is where this crate diverges from the reference client.
    ///
    /// Geth's `core/txpool/validation.go` checks only the gas limit, the encrypted gas and the fee
    /// for an Envelope, so a ciphertext with a broken pairing relation enters a Geth mempool. This
    /// crate rejects it permanently. The consequence is liveness rather than a state fork: Geth's
    /// `AggregateAndDecrypt` verifies `e(PK, commitment) * e(rpk, g2)`, which holds exactly when
    /// `Verify` holds, so there is no input Geth decrypts and this crate rejects. A Geth primary
    /// admits the Envelope and then stalls on it, because `dbft.check.go` merely returns and waits
    /// for more `PreCommits` that can never help; a Reth primary never admits it.
    #[test]
    fn pool_admission_rejects_the_envelope_the_reference_client_admits() {
        let valid = envelope_input(&VALID_CIPHERTEXT);
        assert!(
            validate_envelope_ciphertext(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &valid)
                .is_ok(),
            "the untampered Envelope must be admitted"
        );

        let invalid = envelope_input(&ADMISSION_CIPHERTEXT_INVALID);
        let error =
            validate_envelope_ciphertext(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &invalid)
                .unwrap_err();
        let InvalidPoolTransactionError::Other(error) = error else {
            panic!("TPKE relation failure must use the Neo X pool error")
        };
        let error =
            error.as_any().downcast_ref::<NeoXPoolPolicyError>().expect("Neo X pool error type");
        assert!(
            matches!(
                error,
                NeoXPoolPolicyError::InvalidEnvelopeCiphertext(
                    TpkeError::InvalidCiphertextCommitment
                )
            ),
            "unexpected pool error: {error:?}"
        );
        assert!(error.is_bad_transaction(), "the rejection must be permanent");
    }

    #[test]
    fn pool_admission_rejects_only_decoded_envelopes_with_mismatched_tpke_relation() {
        let valid = envelope_input(&VALID_CIPHERTEXT);
        assert!(validate_envelope_ciphertext(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &valid,)
            .is_ok());

        let mut mismatched = VALID_CIPHERTEXT;
        mismatched[reth_neox_antimev::G1_COMPRESSED_LEN * 2] ^= 0x20;
        let mismatched = envelope_input(&mismatched);
        let error =
            validate_envelope_ciphertext(TxType::Eip1559 as u8, Some(ENVELOPE_TARGET), &mismatched)
                .unwrap_err();
        let InvalidPoolTransactionError::Other(error) = error else {
            panic!("TPKE relation failure must use the Neo X pool error")
        };
        let error =
            error.as_any().downcast_ref::<NeoXPoolPolicyError>().expect("Neo X pool error type");
        assert!(matches!(
            error,
            NeoXPoolPolicyError::InvalidEnvelopeCiphertext(TpkeError::InvalidCiphertextCommitment)
        ));
        assert!(error.is_bad_transaction());

        assert!(validate_envelope_ciphertext(
            TxType::Legacy as u8,
            Some(Address::ZERO),
            &mismatched,
        )
        .is_ok());

        let mut malformed = valid;
        let ciphertext_offset = ENCRYPTED_DATA_PREFIX.len() + 4 + 4 + 32;
        malformed[ciphertext_offset] = 0;
        assert!(validate_envelope_ciphertext(
            TxType::Legacy as u8,
            Some(ENVELOPE_TARGET),
            &malformed,
        )
        .is_ok());

        assert!(is_envelope_policy(Some(ENVELOPE_TARGET), &mismatched));
        assert!(validate_envelope_ciphertext(
            TxType::Eip4844 as u8,
            Some(ENVELOPE_TARGET),
            &mismatched,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn stateless_invalid_transactions_bypass_state_and_neox_validation() {
        let provider = MockEthProvider::<EthPrimitives>::default().with_genesis_block();
        let evm_config = NeoXEvmConfig::new(NeoXChainSpec::mainnet().unwrap());
        let inner = EthTransactionValidatorBuilder::new(provider.clone(), evm_config)
            .build(InMemoryBlobStore::default());
        let validator = NeoXTransactionValidator { inner, provider: provider.clone() };

        let mut mismatched = VALID_CIPHERTEXT;
        mismatched[reth_neox_antimev::G1_COMPRESSED_LEN * 2] ^= 0x20;
        let stateless_invalid = pooled_legacy(envelope_input(&mismatched), 0);
        let stateless_valid = pooled_legacy(Vec::new(), 21_000);
        provider.set_snap_state_reads_fail(true);

        let outcome = validator
            .validate_transaction(TransactionOrigin::External, stateless_invalid.clone())
            .await;
        assert!(matches!(
            outcome.as_invalid(),
            Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
        ));

        let outcomes = validator
            .validate_transactions([
                (TransactionOrigin::External, stateless_invalid.clone()),
                (TransactionOrigin::Local, stateless_invalid),
            ])
            .await;
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| matches!(
            outcome.as_invalid(),
            Some(InvalidPoolTransactionError::IntrinsicGasTooLow)
        )));

        let empty = validator
            .validate_transactions(Vec::<(TransactionOrigin, EthPooledTransaction)>::new())
            .await;
        assert!(empty.is_empty());

        assert!(validator
            .validate_transaction(TransactionOrigin::External, stateless_valid)
            .await
            .is_error());
    }
}
