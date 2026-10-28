# G9 / Remaining Validation Summary

Date: 2026-09-11

## Passed

- Rust `reth-neox-chainspec` library tests: 17 passed, 0 failed.
- Rust `reth-neox-chainspec` strict activation boundary test: 1 passed, 0 failed.
- Rust `reth-neox-antimev --tests --no-fail-fast`: 95 passed, 0 failed.
- Geth strict boundary and fork-order tests: passed.
- Geth packages `params`, `crypto/tpke`, `antimev`, `consensus/dbft`: passed.
- G8 mixed-client DKG gate: `status=ok`, 9 clients, round 1 to 2, 1402 blocks checked, 0 reorgs, 0 transient RPC errors.
- G9 static configuration gate: passed; both sides use `neoXPkcs7StrictBlock` and the same activation height.

## Partially verified / environment-limited

- Python script suite: 70 tests collected; 69 passed, 12 skipped, 1 failed because the macOS installer bundle test invokes a macOS Foundation trash fallback while running on Windows. This is an environment/platform-path failure, not a protocol assertion.
- MDBX targeted persistence regression on native Ubuntu: **PASS**, exact `1 passed; 0 failed; 165 filtered out`; Ubuntu persistence subset: **14 passed; 0 failed; 152 filtered out**.
- A minimal test-only lifecycle change is present in `crates/engine/tree/src/persistence.rs`: read-only providers use `.no_watch()`, Windows releases the read-only environment before reorg, then reopens it; Linux retains the stronger snapshot-isolation assertions. This does not touch protocol or production MDBX paths.
- Native Windows exact rerun still **FAILS** at the primary reorg commit (`persistence.rs:749`) with errno 1224: `The requested operation cannot be performed on a file with a user-mapped section open.` This persists even after removing the secondary MDBX environment, so it is isolated to the Windows/libmdbx mapped-file truncate behavior, not the protocol or secondary watcher. Do not change production commit lifecycle or mark Windows persistence PASS.
- Historical full-suite failures also included `signer must exist at block 1` and MDBX `Resource temporarily unavailable (11)`; these remain separate unresolved full-suite issues.

## Not proven by these checks

- 100% protocol equivalence across every historical block, transaction, RPC, consensus, P2P, storage, and platform path.
- Production G9 activation at height 10,000,000; the configuration and boundary semantics are prepared, but production governance/deployment remains an operational gate.

- Windows native exact after single-environment cfg refactor: still FAIL, 0 passed/1 failed at `persistence.rs:749` with MDBX errno 1224 (`user-mapped section open`). The refactor compiles and does not alter production code; classify as known Windows/libmdbx platform limitation.
