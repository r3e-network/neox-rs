# Upstream drift audit and Reth 2.5.2 sync — 2026-09-20

Scope: a drift audit of both pinned oracles since the [2026-08-29 sync](2026-08-29-UPSTREAM-SYNC.md),
and the resulting Reth sync. Method as before: `paradigmxyz/reth` (`main`) and
`bane-labs/go-ethereum` (`bane-main`) fetched read-only into throwaway remotes; nothing pushed
from them.

## Headline

| | |
|---|---|
| Neo X Geth oracle | **2 commits** — `f0e236838b` → `a09b77da24` (PR #657). **Tooling only, not applied.** |
| Reth drift | **207 commits** (`3bc71d43f7` → `4dd0cc021a`), Reth **2.5.1 → 2.5.2**. |
| Core change | **revm 42 → 43.0.2** migration + alloy 2.4.2 / alloy-evm 0.39 / alloy-hardforks 0.4.8. |
| Merge | `e5b80c423f`, clean rehearse + real merge with 4 textual conflicts (§2). |
| Result | Synced to `4dd0cc021a`; Neo X packages compile, clippy/fmt clean, 0 test failures. |

## 1. Neo X Geth — 2 commits, tooling, not applied

`f0e236838b` → `a09b77da24` (PR #657 "fix-missing-state"):

| commit | subject |
|---|---|
| `94ac981b11` | cmd/geth: fix an incorrect db close |
| `a09b77da24` | Merge PR #657 |

The only production change is in `cmd/geth/chaincmd.go` `initGenesis`: the deferred cleanup now
closes `triedb` before `chaindb` (the correct ordering for their dependency). This is
command-line tool lifecycle, **not** consensus/protocol/execution code. Genesis hashes at the
tip re-verify unchanged (`bdb5f93f…`, `2b49c4d6…`). The Rust client has no corresponding
chaincmd logic and its DB layer is MDBX, so **nothing is applied**; the geth baseline stays
`f0e236838b`.

## 2. Reth — 207 commits, 2.5.1 → 2.5.2

The drift is dominated by the **revm 43 migration** (`revm 42.0.1 → 43.0.2`,
`revm-inspectors 0.42.2 → 0.43.0`, `alloy-evm 0.38 → 0.39`, `alloy 2.4.1 → 2.4.2`,
`alloy-hardforks 0.2.13 → 0.4.8`), re-landed after the revert recorded in the 2026-08-28 audit,
plus the storage-overlay/snap-sync work that continued through the range. 391 files changed.

### 2a. Merge and conflict resolution (`e5b80c423f`)

Four textual conflicts, all resolved:

- **Cargo.toml** — the fork keeps its `aes-gcm`/`ahash` workspace deps; upstream's version bump
  (2.5.2) applied around them.
- **`crates/engine/primitives/src/config.rs`** — kept both the fork's
  `with_persistence_thresholds` test and upstream's new default/zero-threshold tests (identical
  defaults: 50/30/100).
- **`crates/engine/tree/src/persistence.rs`** — see §3.
- **`crates/node/core/src/args/engine.rs`** — adopted upstream's clear-then-set persistence
  window (correct for overrides smaller than the default) while keeping the fork's
  strict-threshold test.

### 2b. Workspace-dependency changes the fork had to carry

Reth 2.5.2 dropped several workspace deps the fork still uses:

- **`k256`** — restored (`0.13`, `ecdsa`): fork's dBFT ECDSA signing path (signer, validator,
  DKG).
- **`sha3`** — restored (`0.10.5`): fork's keystore/DKG hashing.
- **`gmp` default feature (bin/reth)** — removed from the default set. `gmp-mpfr-sys` (modexp
  EIP-198 acceleration) does not support Windows MSVC, and feature-unification forces the whole
  workspace through it. Modexp falls back to the behaviourally identical aurora-engine backend;
  `--features gmp` remains available on platforms that support it.

## 3. revm 43 migration in the fork

### 3a. `crates/neox/evm/src/executor.rs`

`NeoXBlockExecutor` delegates to `EthBlockExecutor` and implements `BlockExecutor`. revm 43
added a `Evm::Spec: Into<SpecId> + Clone` bound on that impl. Fixed by adding the bound to the
delegating impl and importing `SpecId`. `crates/neox/evm/factory.rs` (which reaches into revm
internals) compiled and tested unchanged.

### 3b. `crates/engine/tree/src/persistence.rs` — Windows/Linux split re-based on 2.5.2

The merge kept the fork's `cfg(windows)` split (from the earlier portable-reorg work), but it
still used 2.5.1 APIs (`BalNotificationStream`, `ProviderFactory::history_by_block_number`) that
2.5.2 removed. The test was rebuilt on the 2.5.2 structure:

- **Linux** (`cfg(not(windows))`): the full upstream snapshot-isolation coverage — secondary
  provider, background reorg thread exercising `wait_for_pre_commit_readers`, reads through
  `BlockchainProvider`.
- **Windows** (`cfg(windows)`): the reorg runs synchronously on the primary environment (a
  second MDBX env is unsafe while the writer truncates mapped files) and verification goes
  through a `BlockchainProvider`.

The Windows branch still hits **os error 1224** (`ERROR_USER_MAPPED_FILE`) inside `save_blocks`
under 2.5.2 — the same static-file/overlay mmap-vs-truncate limit already recorded for
`reth-provider`; it is a platform limitation of the upstream storage layer, not a revm/Neo X
regression. The Linux path matches upstream and passes there.

## 4. Gates

Run on this Windows host (stable 1.95 MSVC, nightly rustfmt `1.10.0-nightly`, `CARGO_INCREMENTAL=0`,
MSVC env per the 2026-08-29 validation report).

| gate | result |
|---|---|
| Nightly rustfmt `--check` | pass |
| Strict clippy, Neo X set, `-D warnings` | pass (incl. doc_markdown backticks in the spec docs) |
| Neo X package tests (9 packages) | **0 failed** across all suites |
| `neox-rs` binary | builds |
| `reth-engine-tree` lib | 197/198 — the one failure is the Windows `persistence` 1224 above |
| `reth-transaction-pool` | 276 passed |
| `reth-storage-overlay` | 15 passed |
| `reth-provider`/`reth-db` at `--test-threads=4` | 223/232 + the same 9 static-file 1224 failures as before the sync |

`reth-engine-tree`/`reth-node-ethereum` **e2e integration suites** are not runnable here
(need a Linux `lo` interface), as recorded previously; they are not part of the host gate.

## 5. Explicit non-claims

- Green compile/tests is not consensus parity. The live gates (fresh-datadir MainNet sync with
  restart equality, mixed-client SNAP/ETH + dBFT, crash/reorg across persistence, DKG epoch, RPC
  differential) remain open and unchanged.
- The `reth-provider` and `reth-engine-tree` Windows 1224 failures are the documented upstream
  static-file/overlay mmap limit, not regressions from this merge.
- The Neo X Geth oracle baseline is unchanged (`f0e236838b`); its 2-commit drift is tooling only.
