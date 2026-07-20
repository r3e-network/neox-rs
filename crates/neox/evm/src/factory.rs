//! revm factory implementing the Neo X DKG execution fork.

use alloy_evm::{
    eth::{EthEvm, EthEvmContext},
    precompiles::PrecompilesMap,
    revm::{
        context::{BlockEnv, Context, DBErrorMarker, TxEnv},
        context_interface::result::{EVMError, HaltReason},
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
    Database, EvmEnv, EvmFactory,
};
use alloy_primitives::U256;
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

    fn create<DB, I>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
        inspect: bool,
    ) -> EthEvm<DB, I, PrecompilesMap>
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

        EthEvm::new(evm, inspect)
    }
}

impl EvmFactory for NeoXEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        EthEvm<DB, I, Self::Precompiles>;
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
