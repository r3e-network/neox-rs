//! revm factory implementing the Neo X DKG execution fork.

use crate::{policy_blacklist_storage_key, POLICY_PROXY_ADDRESS};
use alloc::vec::Vec;
use alloy_evm::{
    eth::{EthEvm, EthEvmContext},
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::{
        context::{result::ResultAndState, BlockEnv, Context, DBErrorMarker, TxEnv},
        context_interface::{
            context::{ContextError, ContextTr},
            journaled_state::JournalTr,
            result::{EVMError, HaltReason},
            Cfg,
        },
        handler::PrecompileProvider,
        inspector::{Inspector, NoOpInspector},
        interpreter::{
            interpreter::EthInterpreter,
            interpreter_action::CallInputs,
            interpreter_types::{InterpreterTypes, MemoryTr, StackTr},
            Gas, Host, Instruction, InstructionContext, InstructionExecResult, InstructionResult,
            InterpreterResult,
        },
        precompile::{PrecompileSpecId, Precompiles},
        primitives::hardfork::SpecId,
        MainBuilder, MainContext,
    },
    Database, Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::{Address, Bytes, U256};
use core::cmp::max;
use reth_evm::PrecompileSet;

/// MCOPY opcode introduced by EIP-5656.
const MCOPY_OPCODE: u8 = 0x5e;
/// MCOPY's static gas component; copying and memory expansion are charged dynamically.
const MCOPY_STATIC_GAS: u16 = 3;

/// EVM factory that activates the Neo X DKG execution fork at a configured block height.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NeoXEvmFactory {
    dkg_block: u64,
}

impl NeoXEvmFactory {
    /// Creates a Neo X EVM factory with the DKG activation block.
    pub const fn new(dkg_block: u64) -> Self {
        Self { dkg_block }
    }

    /// Returns the configured DKG activation block.
    pub const fn dkg_block(self) -> u64 {
        self.dkg_block
    }

    fn dkg_active(self, block: &BlockEnv) -> bool {
        block.number >= U256::from(self.dkg_block)
    }

    fn create<DB, I>(&self, db: DB, input: EvmEnv, inspector: I, inspect: bool) -> NeoXEvm<DB, I>
    where
        DB: Database,
        I: Inspector<EthEvmContext<DB>, EthInterpreter>,
    {
        let spec = input.cfg_env.spec;
        let dkg_active = self.dkg_active(&input.block_env);
        // Neo X exposes KZG and all EIP-2537 BLS precompiles from DKG onward. Its Cancun set also
        // retains BLS, while Osaka follows the regular Osaka set (including P256VERIFY).
        let precompiles = if dkg_active && !spec.is_enabled_in(SpecId::OSAKA) {
            Precompiles::prague()
        } else {
            Precompiles::new(PrecompileSpecId::from_spec_id(spec))
        };
        let mut evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(inspector)
            .with_precompiles(NeoXPrecompiles::new(PrecompilesMap::from_static(precompiles)));

        // DKG is otherwise Shanghai-compatible. Only MCOPY is activated early; BLOBHASH,
        // BLOBBASEFEE, transient storage and the Cancun SELFDESTRUCT behavior remain inactive.
        if dkg_active && !spec.is_enabled_in(SpecId::CANCUN) {
            evm.instruction.insert_instruction(
                MCOPY_OPCODE,
                Instruction::new(neox_mcopy),
                MCOPY_STATIC_GAS,
            );
        }

        NeoXEvm::new(EthEvm::new(evm, inspect))
    }
}

impl EvmFactory for NeoXEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> = NeoXEvm<DB, I>;
    type Tx = TxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = NeoXPrecompiles;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        self.create(db, input, NoOpInspector {}, false)
    }

    fn create_evm_with_inspector<DB, I>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I>
    where
        DB: Database,
        I: Inspector<Self::Context<DB>, EthInterpreter>,
    {
        self.create(db, input, inspector, true)
    }
}

/// EVM precompile provider that applies the Neo X Policy blacklist at call-frame creation.
///
/// Geth checks precompiles before the blacklist branch. For every other call target, a non-zero
/// `Policy.isBlackListed[target]` value produces a call-level revert before target bytecode runs.
#[derive(Debug)]
pub struct NeoXPrecompiles {
    inner: PrecompilesMap,
}

impl NeoXPrecompiles {
    const fn new(inner: PrecompilesMap) -> Self {
        Self { inner }
    }

    /// Returns whether `address` is a configured precompile.
    pub fn contains(&self, address: &Address) -> bool {
        self.inner.get(address).is_some()
    }

    /// Applies a transformation to one precompile while preserving the policy-aware provider.
    pub fn apply_precompile<F>(&mut self, address: &Address, f: F)
    where
        F: FnOnce(Option<DynPrecompile>) -> Option<DynPrecompile>,
    {
        self.inner.apply_precompile(address, f);
    }

    /// Maps cacheable precompiles, used by Reth's execution prewarm cache.
    pub fn map_cacheable_precompiles<F>(&mut self, f: F)
    where
        F: FnMut(&Address, DynPrecompile) -> DynPrecompile,
    {
        self.inner.map_cacheable_precompiles(f);
    }
}

impl core::ops::Deref for NeoXPrecompiles {
    type Target = PrecompilesMap;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for NeoXPrecompiles {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl PrecompileSet for NeoXPrecompiles {
    fn addresses(&self) -> impl Iterator<Item = &Address> {
        self.inner.addresses()
    }

    fn get(&self, address: &Address) -> Option<impl alloy_evm::precompiles::Precompile + '_> {
        self.inner.get(address)
    }

    fn move_precompiles(
        &mut self,
        moves: Vec<(Address, Address)>,
    ) -> Result<(), alloy_evm::precompiles::MovePrecompileError> {
        self.inner.move_precompiles(moves)
    }

    fn map_cacheable_precompiles<F>(&mut self, f: F)
    where
        F: FnMut(&Address, DynPrecompile) -> DynPrecompile,
    {
        self.inner.map_cacheable_precompiles(f);
    }

    fn apply_precompile<F>(&mut self, address: &Address, f: F)
    where
        F: FnOnce(Option<DynPrecompile>) -> Option<DynPrecompile>,
    {
        self.inner.apply_precompile(address, f);
    }
}

impl<DB> PrecompileProvider<EthEvmContext<DB>> for NeoXPrecompiles
where
    DB: Database,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: SpecId) -> bool {
        <PrecompilesMap as PrecompileProvider<EthEvmContext<DB>>>::set_spec(&mut self.inner, spec)
    }

    fn run(
        &mut self,
        context: &mut EthEvmContext<DB>,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, alloc::string::String> {
        // Delegate first so precompiles remain exempt, exactly as in geth's EVM.Call branches.
        if self.inner.get(&inputs.bytecode_address).is_some() {
            return <PrecompilesMap as PrecompileProvider<EthEvmContext<DB>>>::run(
                &mut self.inner,
                context,
                inputs,
            );
        }

        // Geth returns successfully before the blacklist branch for a zero-value CALL to an
        // account that does not exist under EIP-158. Preserve that edge case; CALLCODE,
        // DELEGATECALL, STATICCALL, and calls carrying value still reach the policy check.
        if inputs.scheme.is_call() &&
            inputs.value.transfer().is_some_and(|value| value.is_zero()) &&
            context.cfg().spec().is_enabled_in(SpecId::SPURIOUS_DRAGON) &&
            context
                .journal()
                .evm_state()
                .get(&inputs.bytecode_address)
                .is_some_and(|account| account.is_loaded_as_not_existing())
        {
            return Ok(None)
        }

        let key = policy_blacklist_storage_key(inputs.bytecode_address);
        let journal_value = context
            .journal()
            .evm_state()
            .get(&POLICY_PROXY_ADDRESS)
            .and_then(|account| account.storage.get(&key).map(|slot| slot.present_value));
        let blocked = if let Some(value) = journal_value {
            !value.is_zero()
        } else {
            match context.db_mut().storage(POLICY_PROXY_ADDRESS, key) {
                Ok(value) => !value.is_zero(),
                Err(error) => {
                    *context.error() = Err(ContextError::Db(error));
                    return Ok(None)
                }
            }
        };

        if blocked {
            return Ok(Some(InterpreterResult::new(
                InstructionResult::Revert,
                Bytes::new(),
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir),
            )))
        }

        <PrecompilesMap as PrecompileProvider<EthEvmContext<DB>>>::run(
            &mut self.inner,
            context,
            inputs,
        )
    }

    fn warm_addresses(&self) -> &alloy_primitives::map::AddressSet {
        <PrecompilesMap as PrecompileProvider<EthEvmContext<DB>>>::warm_addresses(&self.inner)
    }

    fn contains(&self, address: &Address) -> bool {
        self.inner.get(address).is_some()
    }
}

/// Neo X EVM: an Ethereum EVM with Neo X call-frame blacklist enforcement.
///
/// Transaction-level Policy checks are performed by the block executor and transaction pool. RPC
/// simulation uses Geth-compatible `SkipTransactionChecks` semantics and therefore does not run
/// those checks through `transact_raw`; target blacklist checks remain active in call frames.
pub struct NeoXEvm<DB: Database, I> {
    inner: EthEvm<DB, I, NeoXPrecompiles>,
}

impl<DB: Database, I> core::fmt::Debug for NeoXEvm<DB, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NeoXEvm").finish_non_exhaustive()
    }
}

impl<DB: Database, I> NeoXEvm<DB, I> {
    /// Wraps an Ethereum EVM in the Neo X call-frame blacklist policy.
    const fn new(inner: EthEvm<DB, I, NeoXPrecompiles>) -> Self {
        Self { inner }
    }

}

impl<DB, I> Evm for NeoXEvm<DB, I>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>, EthInterpreter>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = NeoXPrecompiles;
    type Inspector = I;

    fn block(&self) -> &Self::BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &alloy_evm::revm::context::CfgEnv<Self::Spec> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // RPC simulation follows Geth's SkipTransactionChecks path. Transaction-level Policy
        // checks remain enforced by the pool and block executor; call-frame target blacklist
        // checks are still applied by NeoXPrecompiles.
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // System calls do not pass through `preCheck` in the reference client and carry no fees.
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled)
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        self.inner.components_mut()
    }
}

/// Neo X's pre-Cancun MCOPY implementation.
///
/// This is byte-for-byte equivalent to revm's EIP-5656 operation except that activation is
/// controlled by [`NeoXEvmFactory`] instead of `SpecId::CANCUN`.
fn neox_mcopy<IT: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, IT>,
) -> InstructionExecResult {
    alloy_evm::revm::interpreter::popn!([dst, src, len], context.interpreter);

    let len = alloy_evm::revm::interpreter::as_usize_or_fail!(context.interpreter, len);
    alloy_evm::revm::interpreter::gas!(
        context.interpreter,
        context.host.gas_params().mcopy_cost(len)
    );

    if len == 0 {
        return Ok(())
    }

    let dst = alloy_evm::revm::interpreter::as_usize_or_fail!(context.interpreter, dst);
    let src = alloy_evm::revm::interpreter::as_usize_or_fail!(context.interpreter, src);
    context.interpreter.resize_memory(context.host.gas_params(), max(dst, src), len)?;
    context.interpreter.memory.copy(dst, src, len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::{
        revm::{
            bytecode::Bytecode,
            database::{BenchmarkDB, CacheDB},
            database_interface::{EmptyDB, EEADDRESS, FFADDRESS},
            primitives::TxKind,
            state::AccountInfo,
        },
        Evm,
    };
    use alloy_primitives::{address, U256};

    const DKG_BLOCK: u64 = 100;
    const KZG_ADDRESS: alloy_primitives::Address =
        address!("000000000000000000000000000000000000000a");
    const BLS_G1_ADD_ADDRESS: alloy_primitives::Address =
        address!("000000000000000000000000000000000000000b");

    /// Pins Geth-compatible `SkipTransactionChecks` behavior for bare `transact_raw` calls.
    ///
    /// Transaction-level Policy checks belong to the transaction pool and block executor; RPC
    /// simulation must not reject an underpriced or blacklisted sender before EVM execution.
    #[test]
    fn simulation_skips_transaction_policy_checks() {
        use crate::{policy_storage_key, POLICY_MIN_GAS_TIP_CAP_SLOT, POLICY_PROXY_ADDRESS};
        use alloy_evm::revm::{context::CfgEnv, database::CacheDB};

        const MINIMUM_TIP: u64 = 5;

        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_storage_key(POLICY_MIN_GAS_TIP_CAP_SLOT),
            U256::from(MINIMUM_TIP),
        )
        .unwrap();

        let block_env = BlockEnv { number: U256::from(1), basefee: 100, ..Default::default() };
        let env = EvmEnv::new(CfgEnv::new_with_spec(SpecId::SHANGHAI), block_env.clone());
        let mut evm = NeoXEvmFactory::new(DKG_BLOCK).create_evm(db.clone(), env);

        // Geth's RPC simulation path skips transaction-level Policy checks. The unfunded sender may
        // still produce a normal EVM execution error, but it must not produce a Policy error.
        let underpriced = TxEnv {
            caller: Address::repeat_byte(0x24),
            gas_price: 104,
            gas_priority_fee: Some(10),
            ..Default::default()
        };
        let result = evm.transact_raw(underpriced);
        assert!(
            !matches!(&result, Err(EVMError::Custom(message)) if message.contains("PolicyProxy")),
            "RPC simulation unexpectedly enforced transaction Policy: {result:?}"
        );

        // A zero-fee call follows the same skip path.
        let zero_fee = TxEnv {
            caller: Address::repeat_byte(0x24),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };
        assert!(!matches!(
            evm.transact_raw(zero_fee),
            Err(EVMError::Custom(message)) if message.contains("PolicyProxy")
        ));
    }

    fn shanghai_env(block_number: u64) -> EvmEnv {
        let mut env: EvmEnv<SpecId, BlockEnv> = EvmEnv::default();
        env.cfg_env.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
        env.block_env.number = U256::from(block_number);
        env
    }

    #[test]
    fn pre_dkg_uses_shanghai_precompiles() {
        let mut evm = NeoXEvmFactory::new(DKG_BLOCK)
            .create_evm(EmptyDB::default(), shanghai_env(DKG_BLOCK - 1));

        assert!(evm.precompiles_mut().get(&KZG_ADDRESS).is_none());
        assert!(evm.precompiles_mut().get(&BLS_G1_ADD_ADDRESS).is_none());
    }

    #[test]
    fn dkg_exposes_kzg_and_bls_before_cancun() {
        let mut evm =
            NeoXEvmFactory::new(DKG_BLOCK).create_evm(EmptyDB::default(), shanghai_env(DKG_BLOCK));

        assert!(evm.precompiles_mut().get(&KZG_ADDRESS).is_some());
        assert!(evm.precompiles_mut().get(&BLS_G1_ADD_ADDRESS).is_some());
    }

    #[test]
    fn dkg_executes_mcopy_without_cancun_semantics() {
        // PUSH0 PUSH0 PUSH0 MCOPY STOP: a zero-length copy exercises activation without memory
        // expansion obscuring the result.
        let bytecode = Bytecode::new_legacy([0x5f, 0x5f, 0x5f, MCOPY_OPCODE, 0x00].into());
        let tx = TxEnv::builder()
            .caller(EEADDRESS)
            .kind(TxKind::Call(FFADDRESS))
            .gas_limit(100_000)
            .build()
            .expect("valid test transaction");
        let factory = NeoXEvmFactory::new(DKG_BLOCK);

        let mut pre_dkg = factory
            .create_evm(BenchmarkDB::new_bytecode(bytecode.clone()), shanghai_env(DKG_BLOCK - 1));
        let pre_dkg_result = pre_dkg.transact(tx.clone()).expect("database is infallible");
        assert!(!pre_dkg_result.result.is_success());

        let mut at_dkg =
            factory.create_evm(BenchmarkDB::new_bytecode(bytecode), shanghai_env(DKG_BLOCK));
        let at_dkg_result = at_dkg.transact(tx).expect("database is infallible");
        assert!(at_dkg_result.result.is_success());
    }

    #[test]
    fn blacklist_reverts_internal_calls_without_aborting_the_parent() {
        use crate::{policy_blacklist_storage_key, POLICY_PROXY_ADDRESS};
        use alloy_evm::revm::{context::CfgEnv, Database, DatabaseCommit};

        let caller = address!("1000000000000000000000000000000000000001");
        let dispatcher = address!("2000000000000000000000000000000000000002");
        let target = address!("3000000000000000000000000000000000000003");

        // The target writes storage slot zero. The dispatcher ignores CALL's boolean result, so a
        // Policy revert must leave the outer transaction successful while suppressing this write.
        let target_code = Bytecode::new_legacy([0x60, 0x01, 0x60, 0x00, 0x55, 0x00].into());
        let mut dispatcher_code = vec![
            0x60, 0x00, // return size
            0x60, 0x00, // return offset
            0x60, 0x00, // input size
            0x60, 0x00, // input offset
            0x60, 0x00, // value
            0x73, // target address
        ];
        dispatcher_code.extend_from_slice(target.as_slice());
        dispatcher_code.extend_from_slice(&[0x63, 0x01, 0x86, 0xa0, 0xf1, 0x00]); // gas, CALL, STOP

        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            caller,
            AccountInfo::new(
                U256::from(10_u64.pow(18)),
                0,
                Default::default(),
                Bytecode::default(),
            ),
        );
        db.insert_account_info(
            dispatcher,
            AccountInfo::new(
                U256::ZERO,
                0,
                Bytecode::new_legacy(dispatcher_code.clone().into()).hash_slow(),
                Bytecode::new_legacy(dispatcher_code.into()),
            ),
        );
        db.insert_account_info(
            target,
            AccountInfo::new(U256::ZERO, 0, target_code.hash_slow(), target_code),
        );
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_blacklist_storage_key(target),
            U256::from(1),
        )
        .unwrap();

        let block = BlockEnv { number: U256::from(1), gas_limit: 1_000_000, ..Default::default() };
        let env = EvmEnv::new(CfgEnv::new_with_spec(SpecId::SHANGHAI), block);
        let mut evm = NeoXEvmFactory::new(DKG_BLOCK).create_evm(db, env);
        let tx = TxEnv {
            caller,
            kind: TxKind::Call(dispatcher),
            gas_limit: 500_000,
            gas_price: 0,
            ..Default::default()
        };

        let result = evm.transact(tx).expect("outer transaction should succeed");
        assert!(result.result.is_success());
        evm.db_mut().commit(result.state);
        assert_eq!(evm.db_mut().storage(target, U256::ZERO).unwrap(), U256::ZERO);
    }

    #[test]
    fn blacklist_blocks_top_level_targets_but_not_precompiles() {
        use crate::{policy_blacklist_storage_key, POLICY_PROXY_ADDRESS};
        use alloy_evm::revm::{context::CfgEnv, database::CacheDB, database_interface::EmptyDB};

        let caller = address!("1000000000000000000000000000000000000001");
        let target = address!("3000000000000000000000000000000000000003");
        let ecrecover = address!("0000000000000000000000000000000000000001");
        let target_code = Bytecode::new_legacy(Bytes::from_static(&[0x00]));

        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            caller,
            AccountInfo::new(
                U256::from(10_u64.pow(18)),
                0,
                Default::default(),
                Bytecode::default(),
            ),
        );
        db.insert_account_info(
            target,
            AccountInfo::new(U256::ZERO, 0, target_code.hash_slow(), target_code),
        );
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_blacklist_storage_key(target),
            U256::from(1),
        )
        .unwrap();
        db.insert_account_storage(
            POLICY_PROXY_ADDRESS,
            policy_blacklist_storage_key(ecrecover),
            U256::from(1),
        )
        .unwrap();

        let env = EvmEnv::new(
            CfgEnv::new_with_spec(SpecId::SHANGHAI),
            BlockEnv { number: U256::from(1), gas_limit: 1_000_000, ..Default::default() },
        );
        let mut evm = NeoXEvmFactory::new(DKG_BLOCK).create_evm(db, env);

        let blocked = evm
            .transact(TxEnv {
                caller,
                kind: TxKind::Call(target),
                gas_limit: 100_000,
                gas_price: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(matches!(
            blocked.result,
            alloy_evm::revm::context_interface::result::ExecutionResult::Revert { .. }
        ));

        let precompile = evm
            .transact(TxEnv {
                caller,
                kind: TxKind::Call(ecrecover),
                gas_limit: 100_000,
                gas_price: 0,
                ..Default::default()
            })
            .unwrap();
        assert!(precompile.result.is_success());
    }
}
