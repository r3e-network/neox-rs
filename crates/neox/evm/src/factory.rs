//! revm factory implementing the Neo X DKG execution fork.

use crate::executor::validate_policy;
use alloy_evm::{
    eth::{EthEvm, EthEvmContext},
    precompiles::PrecompilesMap,
    revm::{
        context::{result::ResultAndState, BlockEnv, Context, DBErrorMarker, TxEnv},
        context_interface::{
            result::{EVMError, HaltReason},
            Cfg,
        },
        inspector::{Inspector, NoOpInspector},
        interpreter::{
            interpreter::EthInterpreter,
            interpreter_types::{InterpreterTypes, MemoryTr, StackTr},
            Host, Instruction, InstructionContext, InstructionExecResult,
        },
        precompile::{PrecompileSpecId, Precompiles},
        primitives::hardfork::SpecId,
        MainBuilder, MainContext,
    },
    Database, Evm, EvmEnv, EvmFactory,
};
use alloy_primitives::{Address, Bytes, U256};
use core::cmp::max;

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
            .with_precompiles(PrecompilesMap::from_static(precompiles));

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
    type Precompiles = PrecompilesMap;

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

/// Neo X EVM: an Ethereum EVM that additionally enforces the on-chain fee policy on every
/// transaction, including RPC simulation.
///
/// The reference client places this check in `preCheck`, which every state transition passes
/// through. Applying it only during block execution would let `eth_call` and `eth_estimateGas`
/// succeed for Envelopes that the reference client rejects and that the transaction pool would
/// refuse on submission.
pub struct NeoXEvm<DB: Database, I> {
    inner: EthEvm<DB, I, PrecompilesMap>,
}

impl<DB: Database, I> core::fmt::Debug for NeoXEvm<DB, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NeoXEvm").finish_non_exhaustive()
    }
}

impl<DB: Database, I> NeoXEvm<DB, I> {
    /// Wraps an Ethereum EVM in the Neo X fee policy.
    pub const fn new(inner: EthEvm<DB, I, PrecompilesMap>) -> Self {
        Self { inner }
    }

    /// Returns whether the reference client's `preCheck` would reach the fee policy for `tx`.
    ///
    /// Mirrors the guards the policy block sits behind: it is London-gated, and skipped entirely
    /// when the base fee is disabled and both fee fields are zero, which is the `eth_call` default.
    /// The two fee comparisons are deliberately *not* re-implemented here. `preCheck` reaches the
    /// policy only after `ErrTipAboveFeeCap` and `ErrFeeCapTooLow` have passed, so declining to run
    /// the policy in those cases leaves revm to raise its own canonical errors, and guarantees the
    /// effective-tip subtraction in the policy cannot underflow.
    fn reaches_fee_policy(&self, tx: &TxEnv) -> bool
    where
        I: Inspector<EthEvmContext<DB>, EthInterpreter>,
    {
        let cfg = self.inner.cfg_env();
        if !cfg.spec.is_enabled_in(SpecId::LONDON) {
            return false;
        }
        let priority_fee = tx.gas_priority_fee.unwrap_or_default();
        if cfg.is_base_fee_check_disabled() && tx.gas_price == 0 && priority_fee == 0 {
            return false;
        }
        tx.gas_price >= priority_fee && tx.gas_price >= u128::from(self.inner.block().basefee)
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
    type Precompiles = PrecompilesMap;
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
        if self.reaches_fee_policy(&tx) {
            validate_policy(&mut self.inner, &tx)
                .map_err(|error| EVMError::Custom(error.to_string()))?;
        }
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
            database::BenchmarkDB,
            database_interface::{EmptyDB, EEADDRESS, FFADDRESS},
            primitives::TxKind,
        },
        Evm,
    };
    use alloy_primitives::{address, U256};

    const DKG_BLOCK: u64 = 100;
    const KZG_ADDRESS: alloy_primitives::Address =
        address!("000000000000000000000000000000000000000a");
    const BLS_G1_ADD_ADDRESS: alloy_primitives::Address =
        address!("000000000000000000000000000000000000000b");

    /// Pins that the fee policy applies to bare `transact_raw` calls, which is the path RPC
    /// simulation takes.
    ///
    /// The reference client checks the policy in `preCheck`, so `eth_call` and `eth_estimateGas`
    /// reject an underpriced Envelope rather than returning a result the transaction pool would
    /// then refuse. Enforcing this only in the block executor made simulation permissive.
    #[test]
    fn fee_policy_applies_to_simulation_not_just_block_execution() {
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

        // Effective tip is 4 against a minimum of 5, so the policy must reject before execution.
        let underpriced = TxEnv {
            caller: Address::repeat_byte(0x24),
            gas_price: 104,
            gas_priority_fee: Some(10),
            ..Default::default()
        };
        let error = evm.transact_raw(underpriced.clone()).unwrap_err();
        assert!(
            matches!(&error, EVMError::Custom(message) if message.contains("is below PolicyProxy minimum")),
            "expected a policy rejection, got {error:?}"
        );

        // A tip that meets the minimum must clear the policy. Execution still fails on the unfunded
        // sender, so assert only that the failure is no longer the policy error.
        let funded = TxEnv { gas_price: 105, ..underpriced };
        assert!(!matches!(evm.transact_raw(funded), Err(EVMError::Custom(_))));

        // A zero-fee call must not hit the policy. `preCheck` skips it because the base fee is
        // disabled and both fee fields are zero; here the fee-cap gate declines independently,
        // since a fee cap under the base fee is a case `preCheck` rejects before the policy.
        // `disable_base_fee` itself is only a field when revm's `optional_no_base_fee` feature is
        // on, which the RPC crates enable but this crate's own subgraph does not, so the skip is
        // asserted through the gate rather than by setting the config.
        let mut lenient = NeoXEvmFactory::new(DKG_BLOCK)
            .create_evm(db, EvmEnv::new(CfgEnv::new_with_spec(SpecId::SHANGHAI), block_env));
        let zero_fee = TxEnv {
            caller: Address::repeat_byte(0x24),
            gas_price: 0,
            gas_priority_fee: None,
            ..Default::default()
        };
        assert!(!matches!(lenient.transact_raw(zero_fee), Err(EVMError::Custom(_))));
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
}
