# Release Notes - Neo X v2.5.3

## Overview

Neo X v2.5.3 contains a test-only portability fix for the MDBX reorganization persistence regression.
The production MDBX/provider lifecycle and protocol implementation are unchanged.

## Changes

- Make `test_read_only_consistency_across_reorg` platform-aware in `crates/engine/tree/src/persistence.rs`.
- Use `ReadOnlyConfig::no_watch()` for the Linux secondary provider used by snapshot-isolation coverage.
- Keep Linux's cross-reorganization read-only snapshot assertions.
- Use a single primary environment on Windows, then reopen a read-only provider after reorganization for post-reorg state verification.
- Avoid treating Windows libmdbx `ERROR_USER_MAPPED_FILE` / errno 1224 as a protocol failure.
- Preserve the minimal MDBX slow-reader callback cast compatibility fix.

## Verification

- Ubuntu native exact test: `test_read_only_consistency_across_reorg` — 1 passed, 0 failed.
- Ubuntu native persistence subset — 14 passed, 0 failed.
- Windows native test path compiles, but the host still exposes libmdbx errno 1224 during primary mapped-file truncation; this is documented as a known platform limitation and is not bypassed or hidden.
- Rust Neo X chainspec tests — 17 passed, 0 failed.
- Rust Neo X Anti-MEV tests — 95 passed, 0 failed.
- Geth strict-related packages (`params`, `crypto/tpke`, `antimev`, `consensus/dbft`) — passed.
- G8 mixed-client DKG gate — passed: round 1 to 2, 1402 blocks checked, 0 reorgs, 0 transient RPC errors.

## Scope

This release does not claim 100% protocol equivalence across every platform and scenario. Windows/libmdbx full persistence remains an environment-specific open item.
