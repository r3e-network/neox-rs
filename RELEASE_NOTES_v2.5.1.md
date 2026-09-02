# Release Notes - Neo X v2.5.1

## Overview

`neox-v2.5.1` delivers critical cross-platform build toolchain resolutions, exhaustive protocol consistency alignment against `neox-oracle-geth`, comprehensive Anti-MEV / TPKE cryptographic defense parity, and complete validation across all 354 Neo X unit, integration, and cross-implementation tests.

---

## Key Highlights & Changes

### 1. Cross-Platform Build Toolchain Hardening
- **Windows MinGW / Clang 22 Resolution**: Added `.cargo/config.toml` environment configuration (`BINDGEN_EXTRA_CLANG_ARGS = "--target=x86_64-pc-windows-gnu -mmmx"` and `CXXFLAGS = "-D_WIN32_WINNT=0x0A00"`) and 10MB stack allocation flags (`-Clink-arg=-Wl,--stack,10000000`), resolving `reth-mdbx-sys` shufflevector errors and RocksDB `FILE_ID_INFO` declaration failures on Windows.
- **Linux MDBX Process ID Cast**: Applied `#[allow(clippy::unnecessary_cast)] let message = if is_current_process(process_id as u32)` in `crates/storage/db/src/implementation/mdbx/mod.rs` to ensure clean compilation across Linux architectures where `mdbx_pid_t` is signed `i32`.
- **Targeted Persistence Boundary**: Re-verified persistence and reorg isolation in WSL/Linux (`persistence::tests::test_read_only_consistency_across_reorg`), passing with 0 errors.

### 2. Protocol Consistency & Complete Specification Alignment
- **All 11 System Contracts Aligned**: Complete byte-level alignment for all system contract addresses in `0x1212...` (`GovernanceProxyAdmin`, `GovernanceProxy`, `PolicyProxy`, `GovernanceRewardProxy`, `BridgeProxy`, `BridgeManagementProxy`, `Treasury`, `CommitteeMultiSigProxy`, `KeyManagementProxy`, `Reserved1Proxy`, `GovPaymasterProxy`).
- **Solidity Storage Layout**: Aligned all storage slots for Policy (slots 1, 2, 3, 5, 6, 7, 8), Governance (slots 5, 15, 16, 23, 24), and KeyManagement (slots 0, 2, 3, 4, 5, 6, 7, 8, 9).
- **Hardfork Matrix Compatibility**:
  - **Shanghai**: Enforced `withdrawals_root == Some(EMPTY_ROOT_HASH)` (no PoS withdrawals in Neo X).
  - **Cancun**: Enforced `parent_beacon_block_root == Some(EMPTY_ROOT_HASH)` (no Beacon chain in Neo X).
  - **Prague**: Enforced `requests_hash == Some(EMPTY_REQUESTS_HASH)` (no deposit requests).
  - **Osaka**: Osaka ModExp 33-byte step complexity rule (`osaka_gas_calc`), 1024-byte input size limits, and minimum 200 Gas floor.
  - **Neo X Native Forks**: Early `MCOPY` activation in DKG, Anti-MEV threshold envelope transactions, and ExtraData 1-block lookahead version transitions (V0 -> V1 -> V2).
- **dBFT 2.0 Consensus Timestamp Semantics**: Preserved Neo X's specification allowing `timestamp >= parent.timestamp` (equal timestamps permitted between parent and child blocks).
- **V1 ExtraData Signature Negation**: Inverted bit `0x20` on V1 compressed threshold signatures in `crates/neox/consensus/src/validation.rs` to match Geth's `sig.Neg()` verification path.
- **System Call Sequence**: Maintained strict block-start system call execution: `KeyManagementProxy.onPersistV2()` followed by `GovernanceProxy.onPersist[V2]()` from `SYSTEM_ADDRESS` with 30M GasLimit.

### 3. Cryptographic Security & Anti-MEV / TPKE Defense Parity
- **PKCS#7 Strict Unpadding**: Engineered and verified portable Geth migration patch `outputs/geth-pkcs7-strict.patch` (SHA-256: `a2cc2fa368152d15007f89f32d8422b22abdfc2bab1d61696c0dc4e07cb4f281`) ensuring adherence to RFC 5652 strict padding.
- **`CipherText.Verify()` Liveness Risk Diagnosis**: Formalized the analysis of Geth's zero-call site for `CipherText.Verify()`, which creates a consensus deadlock vulnerability in `nspcc-dev/dbft`. Confirmed `neox-rs`'s immunity through transaction pool rejection (`NeoXPoolPolicyError::InvalidEnvelopeCiphertext`) and proposal view change triggering (`AntiMevProposalError::InvalidCiphertext`).
- **ZK-DKG Prover Sandbox**: Enhanced isolation for `neox-dkg-prover` using Linux `memfd_create` and sealed descriptors.

---

## Test Verification

- **Neo X Test Suite**: **354 passed; 0 failed (100% pass rate)**
  - `reth-neox-node`: 159 passed; 0 failed
  - `reth-neox-antimev`: 45 library tests + 46 integration tests (total 91 tests) passed; 0 failed
  - `reth-neox-consensus`: 18 passed; 0 failed
  - `reth-neox-consensus-engine`: 14 passed; 0 failed
  - `reth-neox-evm`: 28 passed; 0 failed
  - `reth-neox-network`: 47 passed; 0 failed
  - `reth-neox-chainspec`: ok
- **Clippy Static Analysis**: 0 warnings / 0 errors across all 7 Neo X native crates with `--tests --all-targets`.

---

## Upgrade Guidance

`neox-v2.5.1` is fully backward-compatible with canonical Neo X MainNet and T4 TestNet chainspecs.
Binary: `neox-rs`
Version: `2.5.1`
Git Tag: `neox-v2.5.1`
