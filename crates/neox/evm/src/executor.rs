//! Neo X block execution, `PolicyProxy` validation, and native persistence calls.

use crate::{
    governance_on_persist_selector, on_persist_v2_selector, policy_blacklist_storage_key,
    policy_storage_key, NeoXEvmFactory, GOVERNANCE_PROXY_ADDRESS, KEY_MANAGEMENT_PROXY_ADDRESS,
    POLICY_ENVELOPE_FEE_SLOT, POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT,
    POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS,
    SYSTEM_ADDRESS,
};
use alloc::string::{String, ToString};
use alloy_consensus::{Transaction, TransactionEnvelope, TxReceipt};
use alloy_eips::{eip2718::Encodable2718, eip7685::Requests};
use alloy_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockValidationError, ExecutableTx, GasOutput, StateDB,
    },
    eth::{
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
        spec::{EthExecutorSpec, EthSpec},
        EthBlockExecutionCtx, EthBlockExecutor, EthTxResult,
    },
    Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
};
use alloy_primitives::{Address, Bytes, Log, U256};
use reth_neox_antimev::{encrypted_gas, is_envelope, MIN_ENCRYPTED_GAS_LIMIT};
use reth_neox_chainspec::NeoXChainSpec;
use revm::{
    context::{Block, TxEnv},
    Database, DatabaseCommit, Inspector,
};
use thiserror::Error;

/// Neo X block executor built around the Ethereum transaction and receipt machinery.
#[expect(missing_debug_implementations)]
pub struct NeoXBlockExecutor<'a, Evm, Spec, R: ReceiptBuilder> {
    inner: EthBlockExecutor<'a, Evm, Spec, R>,
    dkg_block: u64,
    anti_mev_block: u64,
    envelope_count: u64,
    envelope_limit: u64,
}

impl<'a, Evm, Spec, R> NeoXBlockExecutor<'a, Evm, Spec, R>
where
    R: ReceiptBuilder,
{
    /// Creates a Neo X executor for one block.
    pub fn new(
        evm: Evm,
        ctx: EthBlockExecutionCtx<'a>,
        spec: Spec,
        receipt_builder: R,
        dkg_block: u64,
        anti_mev_block: u64,
    ) -> Self
    where
        Spec: Clone,
    {
        Self {
            inner: EthBlockExecutor::new(evm, ctx, spec, receipt_builder),
            dkg_block,
            anti_mev_block,
            envelope_count: 0,
            envelope_limit: 0,
        }
    }
}

impl<E, Spec, R> BlockExecutor for NeoXBlockExecutor<'_, E, Spec, R>
where
    E: Evm<DB: StateDB, Tx = TxEnv>,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    <R::Transaction as TransactionEnvelope>::TxType: Send + 'static,
    TxEnv: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;
    type Result = EthTxResult<E::HaltReason, <R::Transaction as TransactionEnvelope>::TxType>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()?;
        let block_number = self.inner.evm.block().number();
        if block_number >= U256::from(self.anti_mev_block) {
            self.envelope_limit = self
                .inner
                .evm
                .db_mut()
                .storage(
                    POLICY_PROXY_ADDRESS,
                    policy_storage_key(POLICY_MAX_ENVELOPES_PER_BLOCK_SLOT),
                )
                .map_err(BlockExecutionError::other)?
                .saturating_to();
        }
        let dkg_active = block_number >= U256::from(self.dkg_block);
        apply_on_persist_calls(&mut self.inner.evm, dkg_active)
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        let envelope = is_envelope(tx_env.tx_type, tx_env.kind.to().copied(), tx_env.data.as_ref());
        if envelope && self.inner.evm.block().number() >= U256::from(self.anti_mev_block) {
            enforce_envelope_count(&mut self.envelope_count, self.envelope_limit)?;
        }
        validate_policy(&mut self.inner.evm, &tx_env)?;
        self.inner.execute_transaction_without_commit((tx_env, recovered))
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.inner.commit_transaction(output)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        let mut inner = self.inner;
        let requests = if inner
            .spec
            .is_prague_active_at_timestamp(inner.evm.block().timestamp().saturating_to())
        {
            // Neo X has no beacon deposit contract and commits the empty requests hash. The
            // standard Prague queue calls are retained for byte-for-byte Geth compatibility; the
            // canonical system-contract accounts are absent and therefore return no requests.
            let mut requests = Requests::default();
            inner.system_caller.append_post_execution_changes(&mut inner.evm, &mut requests)?;
            requests
        } else {
            Requests::default()
        };

        // Neo X has no Ethash/PoS balance increments. Governance.onPersist accounts for validator
        // and voter rewards before transactions, and the canonical withdrawals list is empty.
        let gas_used = if inner.evm.cfg_env().enable_amsterdam_eip8037 {
            inner.max_block_gas_used()
        } else {
            inner.cumulative_tx_gas_used
        };

        Ok((
            inner.evm,
            BlockExecutionResult {
                receipts: inner.receipts,
                requests,
                gas_used,
                blob_gas_used: inner.blob_gas_used,
            },
        ))
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.inner.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.inner.evm
    }

    fn receipts(&self) -> &[Self::Receipt] {
        &self.inner.receipts
    }
}

/// Factory producing Neo X block executors.
#[derive(Debug, Clone)]
pub struct NeoXBlockExecutorFactory<R = AlloyReceiptBuilder, Spec = EthSpec> {
    receipt_builder: R,
    spec: Spec,
    evm_factory: NeoXEvmFactory,
    anti_mev_block: u64,
}

impl<R, Spec> NeoXBlockExecutorFactory<R, Spec> {
    /// Creates a block-executor factory for a Neo X chain.
    pub const fn new(receipt_builder: R, spec: Spec, dkg_block: u64, anti_mev_block: u64) -> Self {
        Self { receipt_builder, spec, evm_factory: NeoXEvmFactory::new(dkg_block), anti_mev_block }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }
}

impl<R> NeoXBlockExecutorFactory<R, alloc::sync::Arc<NeoXChainSpec>> {
    /// Creates a factory from the canonical Neo X chain specification.
    pub fn from_chain_spec(receipt_builder: R, spec: alloc::sync::Arc<NeoXChainSpec>) -> Self {
        let dkg_block = spec.neox.dkg_block;
        let anti_mev_block = spec.neox.anti_mev_block;
        Self::new(receipt_builder, spec, dkg_block, anti_mev_block)
    }
}

impl<R, Spec> BlockExecutorFactory for NeoXBlockExecutorFactory<R, Spec>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
    Spec: EthExecutorSpec + 'static,
    <R::Transaction as TransactionEnvelope>::TxType: Send + 'static,
    TxEnv: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
    Self: 'static,
{
    type EvmFactory = NeoXEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type TxExecutionResult = EthTxResult<
        revm::context_interface::result::HaltReason,
        <R::Transaction as TransactionEnvelope>::TxType,
    >;
    type Executor<'a, DB: StateDB, I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>> =
        NeoXBlockExecutor<'a, <NeoXEvmFactory as EvmFactory>::Evm<DB, I>, &'a Spec, &'a R>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>,
    {
        NeoXBlockExecutor::new(
            evm,
            ctx,
            &self.spec,
            &self.receipt_builder,
            self.evm_factory.dkg_block(),
            self.anti_mev_block,
        )
    }
}

fn apply_on_persist_calls(
    evm: &mut impl Evm<DB: DatabaseCommit>,
    dkg_active: bool,
) -> Result<(), BlockExecutionError> {
    if dkg_active {
        apply_system_call(evm, KEY_MANAGEMENT_PROXY_ADDRESS, on_persist_v2_selector())?;
    }
    let governance_selector =
        if dkg_active { on_persist_v2_selector() } else { governance_on_persist_selector() };
    apply_system_call(evm, GOVERNANCE_PROXY_ADDRESS, governance_selector)
}

fn apply_system_call(
    evm: &mut impl Evm<DB: DatabaseCommit>,
    contract: Address,
    selector: [u8; 4],
) -> Result<(), BlockExecutionError> {
    let result = evm
        .transact_system_call(SYSTEM_ADDRESS, contract, Bytes::copy_from_slice(&selector))
        .map_err(|error| NeoXExecutionError::SystemCallEvm { contract, error: error.to_string() })
        .map_err(BlockExecutionError::other)?;
    if !result.result.is_success() {
        return Err(
            BlockValidationError::other(NeoXExecutionError::SystemCallFailed { contract }).into()
        )
    }
    evm.db_mut().commit(result.state);
    Ok(())
}

fn validate_policy(evm: &mut impl Evm<Tx = TxEnv>, tx: &TxEnv) -> Result<(), BlockExecutionError> {
    let blacklist_key = policy_blacklist_storage_key(tx.caller);
    let blocked = evm
        .db_mut()
        .storage(POLICY_PROXY_ADDRESS, blacklist_key)
        .map_err(BlockExecutionError::other)?;
    if !blocked.is_zero() {
        return Err(BlockValidationError::other(NeoXExecutionError::BlockedSender {
            sender: tx.caller,
        })
        .into())
    }

    let mut minimum_tip = evm
        .db_mut()
        .storage(POLICY_PROXY_ADDRESS, policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT))
        .map_err(BlockExecutionError::other)?;
    if is_envelope(tx.tx_type, tx.kind.to().copied(), tx.data.as_ref()) {
        let maximum_gas = evm
            .db_mut()
            .storage(POLICY_PROXY_ADDRESS, policy_storage_key(POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT))
            .map_err(BlockExecutionError::other)?;
        if U256::from(tx.gas_limit) > maximum_gas {
            return Err(BlockValidationError::other(NeoXExecutionError::EnvelopeGasAbovePolicy {
                gas_limit: tx.gas_limit,
                maximum_gas,
            })
            .into())
        }

        let inner_gas = encrypted_gas(tx.data.as_ref());
        if inner_gas < MIN_ENCRYPTED_GAS_LIMIT {
            return Err(BlockValidationError::other(NeoXExecutionError::EncryptedGasBelowMinimum {
                inner_gas,
            })
            .into())
        }
        if tx.gas_limit < u64::from(inner_gas) {
            return Err(BlockValidationError::other(NeoXExecutionError::EnvelopeGasBelowEncrypted {
                gas_limit: tx.gas_limit,
                inner_gas,
            })
            .into())
        }

        let envelope_fee = evm
            .db_mut()
            .storage(POLICY_PROXY_ADDRESS, policy_storage_key(POLICY_ENVELOPE_FEE_SLOT))
            .map_err(BlockExecutionError::other)?;
        minimum_tip = minimum_tip.saturating_add(envelope_fee);
    }
    let base_fee = u128::from(evm.block().basefee());
    let fee_cap_tip = tx.gas_price.saturating_sub(base_fee);
    let priority_tip = tx.gas_priority_fee.unwrap_or(tx.gas_price);
    let effective_tip = fee_cap_tip.min(priority_tip);
    if U256::from(effective_tip) < minimum_tip {
        return Err(BlockValidationError::other(NeoXExecutionError::GasTipBelowPolicy {
            sender: tx.caller,
            effective_tip,
            minimum_tip,
        })
        .into())
    }
    Ok(())
}

fn enforce_envelope_count(count: &mut u64, limit: u64) -> Result<(), BlockExecutionError> {
    if *count >= limit {
        return Err(BlockValidationError::other(NeoXExecutionError::EnvelopeNumberLimitReached {
            limit,
        })
        .into())
    }
    *count += 1;
    Ok(())
}

/// Consensus-invalid Neo X execution failures.
#[derive(Debug, Error)]
pub enum NeoXExecutionError {
    /// The block contains more Envelope transactions than policy permits.
    #[error("Envelope transaction count exceeds PolicyProxy limit {limit}")]
    EnvelopeNumberLimitReached {
        /// Maximum Envelopes permitted in the block.
        limit: u64,
    },
    /// An Envelope's outer gas limit exceeds the policy maximum.
    #[error("Envelope gas limit {gas_limit} exceeds PolicyProxy maximum {maximum_gas}")]
    EnvelopeGasAbovePolicy {
        /// Outer transaction gas limit.
        gas_limit: u64,
        /// Maximum Envelope gas limit stored by `PolicyProxy`.
        maximum_gas: U256,
    },
    /// An Envelope reserves less than the minimum gas for its encrypted transaction.
    #[error("encrypted transaction gas limit {inner_gas} is below {MIN_ENCRYPTED_GAS_LIMIT}")]
    EncryptedGasBelowMinimum {
        /// Gas encoded in the unencrypted Envelope prefix.
        inner_gas: u32,
    },
    /// An Envelope cannot cover the gas declared for its encrypted transaction.
    #[error("Envelope gas limit {gas_limit} is below encrypted transaction gas {inner_gas}")]
    EnvelopeGasBelowEncrypted {
        /// Outer transaction gas limit.
        gas_limit: u64,
        /// Gas encoded in the unencrypted Envelope prefix.
        inner_gas: u32,
    },
    /// A transaction signer is present in `PolicyProxy`'s blacklist mapping.
    #[error("transaction sender {sender} is blacklisted by PolicyProxy")]
    BlockedSender {
        /// Recovered transaction signer.
        sender: Address,
    },
    /// A transaction's effective priority fee is below the on-chain minimum.
    #[error(
        "transaction sender {sender} effective tip {effective_tip} is below PolicyProxy minimum {minimum_tip}"
    )]
    GasTipBelowPolicy {
        /// Recovered transaction signer.
        sender: Address,
        /// Effective priority fee after applying the base fee and fee cap.
        effective_tip: u128,
        /// Minimum priority fee stored by `PolicyProxy`.
        minimum_tip: U256,
    },
    /// A system-contract call could not be executed by revm.
    #[error("system call to {contract} failed in the EVM: {error}")]
    SystemCallEvm {
        /// Target system-contract proxy.
        contract: Address,
        /// Underlying EVM error text.
        error: String,
    },
    /// A system-contract call halted or reverted.
    #[error("system call to {contract} reverted or halted")]
    SystemCallFailed {
        /// Target system-contract proxy.
        contract: Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GOVERNANCE_REWARD_PROXY_ADDRESS;
    use alloy_consensus::{Header, TxType};
    use alloy_evm::{
        revm::{
            bytecode::Bytecode,
            context::{BlockEnv, CfgEnv},
            database::CacheDB,
            database_interface::EmptyDB,
            primitives::hardfork::SpecId,
            state::AccountInfo,
        },
        EvmEnv,
    };
    use alloy_primitives::{TxKind, B256};
    use alloy_trie::{
        root::{state_root_unhashed, storage_root_unhashed},
        TrieAccount, EMPTY_ROOT_HASH,
    };

    fn evm_with_policy(minimum_tip: u64, blocked: Option<Address>) -> impl Evm<Tx = TxEnv> {
        evm_with_envelope_policy(minimum_tip, 0, u64::MAX, blocked)
    }

    fn evm_with_envelope_policy(
        minimum_tip: u64,
        envelope_fee: u64,
        maximum_envelope_gas: u64,
        blocked: Option<Address>,
    ) -> impl Evm<Tx = TxEnv> {
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT),
            U256::from(minimum_tip),
        )
        .unwrap();
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_storage_key(POLICY_ENVELOPE_FEE_SLOT),
            U256::from(envelope_fee),
        )
        .unwrap();
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_storage_key(POLICY_MAX_ENVELOPE_GAS_LIMIT_SLOT),
            U256::from(maximum_envelope_gas),
        )
        .unwrap();
        if let Some(sender) = blocked {
            db.insert_account_storage(
                POLICY_PROXY_ADDRESS,
                policy_blacklist_storage_key(sender),
                U256::from(1),
            )
            .unwrap();
        }
        let block_env = BlockEnv { number: U256::from(1), basefee: 100, ..Default::default() };
        NeoXEvmFactory::new(100)
            .create_evm(db, EvmEnv::new(CfgEnv::new_with_spec(SpecId::SHANGHAI), block_env))
    }

    fn envelope_tx(tx_type: TxType, gas_limit: u64, inner_gas: u32, gas_price: u128) -> TxEnv {
        let mut data = vec![0_u8; reth_neox_antimev::MIN_ENVELOPE_DATA_LEN];
        data[..4].copy_from_slice(&reth_neox_antimev::ENCRYPTED_DATA_PREFIX);
        data[8..12].copy_from_slice(&inner_gas.to_be_bytes());
        TxEnv {
            tx_type: tx_type as u8,
            caller: Address::repeat_byte(0x67),
            gas_limit,
            gas_price,
            kind: TxKind::Call(reth_neox_antimev::ENVELOPE_TARGET),
            data: Bytes::from(data),
            ..Default::default()
        }
    }

    fn cache_state_root(db: &CacheDB<EmptyDB>) -> B256 {
        state_root_unhashed(db.cache.accounts.iter().filter_map(|(address, account)| {
            let storage_root = storage_root_unhashed(
                account
                    .storage
                    .iter()
                    .filter(|(_, value)| !value.is_zero())
                    .map(|(slot, value)| ((*slot).into(), *value)),
            );
            if account.info.is_empty() && storage_root == EMPTY_ROOT_HASH {
                None
            } else {
                Some((
                    *address,
                    TrieAccount {
                        nonce: account.info.nonce,
                        balance: account.info.balance,
                        storage_root,
                        code_hash: account.info.code_hash,
                    },
                ))
            }
        }))
    }

    #[test]
    fn policy_rejects_blacklisted_sender() {
        let sender = Address::repeat_byte(0x42);
        let mut evm = evm_with_policy(0, Some(sender));
        let tx = TxEnv { caller: sender, gas_price: 100, ..Default::default() };

        let error = validate_policy(&mut evm, &tx).unwrap_err();
        assert!(matches!(
            error.as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::BlockedSender { sender: actual }) if *actual == sender)
        ));
    }

    #[test]
    fn policy_enforces_effective_tip() {
        let sender = Address::repeat_byte(0x24);
        let mut evm = evm_with_policy(5, None);
        let underpriced = TxEnv {
            caller: sender,
            gas_price: 104,
            gas_priority_fee: Some(10),
            ..Default::default()
        };
        let exact = TxEnv { gas_price: 105, ..underpriced.clone() };

        assert!(matches!(
            validate_policy(&mut evm, &underpriced)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::GasTipBelowPolicy { effective_tip: 4, .. }))
        ));
        assert!(validate_policy(&mut evm, &exact).is_ok());
    }

    #[test]
    fn envelope_count_rejects_zero_and_allows_exact_limit() {
        let mut count = 0;
        assert!(matches!(
            enforce_envelope_count(&mut count, 0)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::EnvelopeNumberLimitReached { limit: 0 }))
        ));

        assert!(enforce_envelope_count(&mut count, 2).is_ok());
        assert!(enforce_envelope_count(&mut count, 2).is_ok());
        assert_eq!(count, 2);
        assert!(enforce_envelope_count(&mut count, 2).is_err());
        assert_eq!(count, 2);
    }

    #[test]
    fn envelope_policy_enforces_outer_and_inner_gas_limits() {
        let mut evm = evm_with_envelope_policy(0, 0, 30_000, None);
        let excessive = envelope_tx(TxType::Legacy, 30_001, 21_000, 100);
        assert!(matches!(
            validate_policy(&mut evm, &excessive)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::EnvelopeGasAbovePolicy {
                        gas_limit: 30_001,
                        ..
                    }))
        ));

        let below_minimum = envelope_tx(TxType::Legacy, 30_000, 20_999, 100);
        assert!(matches!(
            validate_policy(&mut evm, &below_minimum)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::EncryptedGasBelowMinimum {
                        inner_gas: 20_999
                    }))
        ));

        let uncovered = envelope_tx(TxType::Legacy, 21_000, 22_000, 100);
        assert!(matches!(
            validate_policy(&mut evm, &uncovered)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::EnvelopeGasBelowEncrypted {
                        gas_limit: 21_000,
                        inner_gas: 22_000,
                    }))
        ));
    }

    #[test]
    fn envelope_fee_is_added_to_minimum_tip() {
        let mut evm = evm_with_envelope_policy(5, 3, 30_000, None);
        let underpriced = envelope_tx(TxType::Eip1559, 30_000, 21_000, 107);
        assert!(matches!(
            validate_policy(&mut evm, &underpriced)
                .unwrap_err()
                .as_validation(),
            Some(BlockValidationError::Other(inner))
                if matches!(inner.downcast_ref::<NeoXExecutionError>(),
                    Some(NeoXExecutionError::GasTipBelowPolicy {
                        effective_tip: 7,
                        minimum_tip,
                        ..
                    }) if *minimum_tip == U256::from(8))
        ));

        let exact = TxEnv { gas_price: 108, ..underpriced };
        assert!(validate_policy(&mut evm, &exact).is_ok());
    }

    #[test]
    fn blob_and_set_code_transactions_are_not_envelopes() {
        let mut evm = evm_with_envelope_policy(0, 1_000, 0, None);
        for tx_type in [TxType::Eip4844, TxType::Eip7702] {
            let tx = envelope_tx(tx_type, 30_000, 21_000, 100);
            assert!(!is_envelope(tx.tx_type, tx.kind.to().copied(), tx.data.as_ref()));
            assert!(validate_policy(&mut evm, &tx).is_ok());
        }
    }

    #[test]
    fn finish_does_not_mint_ethereum_block_reward() {
        let spec = NeoXChainSpec::mainnet().unwrap();
        let block_env = BlockEnv {
            number: U256::from(1),
            beneficiary: GOVERNANCE_REWARD_PROXY_ADDRESS,
            gas_limit: 30_000_000,
            ..Default::default()
        };
        let evm = NeoXEvmFactory::new(spec.neox.dkg_block).create_evm(
            CacheDB::new(EmptyDB::default()),
            EvmEnv::new(CfgEnv::new_with_spec(SpecId::SHANGHAI), block_env),
        );
        let ommers: [Header; 0] = [];
        let ctx = EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &ommers,
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(0),
            slot_number: None,
        };
        let executor = NeoXBlockExecutor::new(
            evm,
            ctx,
            spec,
            AlloyReceiptBuilder::default(),
            3_623_040,
            2_088_000,
        );

        let (mut evm, result) = executor.finish().unwrap();
        assert_eq!(result.gas_used, 0);
        assert!(evm.db_mut().basic(GOVERNANCE_REWARD_PROXY_ADDRESS).unwrap().is_none());
    }

    #[test]
    fn canonical_genesis_governance_accepts_only_system_on_persist() {
        let spec = NeoXChainSpec::mainnet().unwrap();
        let mut db = CacheDB::new(EmptyDB::default());
        for (address, account) in &spec.inner.genesis.alloc {
            let code = Bytecode::new_raw(account.code.clone().unwrap_or_default());
            db.insert_account_info(
                *address,
                AccountInfo::new(
                    account.balance,
                    account.nonce.unwrap_or_default(),
                    code.hash_slow(),
                    code,
                ),
            );
            for (slot, value) in account.storage_slots() {
                db.insert_account_storage(*address, U256::from_be_bytes(slot.0), value).unwrap();
            }
        }
        assert!(db
            .basic(GOVERNANCE_PROXY_ADDRESS)
            .unwrap()
            .is_some_and(|account| account.code_hash != alloy_primitives::KECCAK256_EMPTY));

        let block_env = BlockEnv {
            number: U256::from(1),
            beneficiary: GOVERNANCE_REWARD_PROXY_ADDRESS,
            timestamp: U256::from(5),
            gas_limit: 30_000_000,
            basefee: 1_000_000_000,
            difficulty: U256::from(2),
            prevrandao: Some(B256::ZERO),
            ..Default::default()
        };
        let cfg_env = CfgEnv::new_with_spec(SpecId::SHANGHAI).with_chain_id(spec.inner.chain.id());
        let mut evm = NeoXEvmFactory::new(spec.neox.dkg_block)
            .create_evm(db, EvmEnv::new(cfg_env, block_env));

        assert_eq!(cache_state_root(evm.db()), spec.inner.genesis_header.state_root);

        let wrong_caller = evm
            .transact_system_call(
                Address::ZERO,
                GOVERNANCE_PROXY_ADDRESS,
                Bytes::copy_from_slice(&governance_on_persist_selector()),
            )
            .unwrap();
        assert!(!wrong_caller.result.is_success());

        apply_on_persist_calls(&mut evm, false).expect("canonical onPersist must succeed");
        // Canonical MainNet block 1 is transaction-free and retains the genesis state root after
        // onPersist. This is a differential replay assertion against Neo X Geth.
        assert_eq!(cache_state_root(evm.db()), spec.inner.genesis_header.state_root);
    }
}
