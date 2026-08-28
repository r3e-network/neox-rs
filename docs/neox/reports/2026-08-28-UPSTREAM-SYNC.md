# Upstream audit and sync — Reth and Neo X Geth — 2026-08-28

Scope: a systematic audit of the pinned compatibility oracle (Neo X Geth), of upstream Reth drift
since the pinned baseline, of how that drift lands on the `neox` branch, and the sync performed as a
result. Supersedes [2026-08-28-UPSTREAM-AUDIT.md](2026-08-28-UPSTREAM-AUDIT.md), which recorded an
assessment against Reth `701b5a175a` and predated the upstream `revm 43` revert.

Method: `paradigmxyz/reth` (`main`) and `bane-labs/go-ethereum` (`bane-main`) were fetched read-only
through the local proxy into throwaway remotes. Nothing was pushed. All conclusions are reproducible
from the commits named below.

## Headline

| | |
|---|---|
| Neo X Geth oracle | **moved 2 commits** — one stale-block fetch guard, one test rewrite. Genesis blobs unchanged, so **no chain spec change**. |
| Reth drift | **33 commits** (`dc83c609a8` → `66a08aba22`). |
| `revm` | **stays at 42.0.1.** Upstream bumped to 43.0.0 (`c12b8f287f`) and **reverted it the next day** (`66a08aba22`). The earlier `sync/reth-revm43-check` migration is therefore obsolete for a tip sync. |
| Merge | **clean, zero conflicts.** All 7 upstream files Neo X touches merged without loss. |
| Oracle parity gap found | Neo X Geth added a `maxUncleDist` stale-block guard to its beacon fetcher; `neox-rs` had no equivalent on the propagated-block path. **Fixed.** |
| Result | Reth tip adopted on `sync-reth-tip-20260828`; baseline advanced in `source-baseline.toml`. |

## 1. Neo X Geth (behavior oracle) — 2 commits

`76580e6a54d7af46b6e0d8f19756cec40670805b` → `f0e236838bb334c7c0d29eeca33533ed0cfda254`

| commit | date | subject |
|---|---|---|
| `b848e852bf` | 2026-08-28 | beacon/impl: fix and improve block fetcher UTs |
| `f0e236838b` | 2026-08-28 | Merge pull request #654 from bane-labs/block-fetcher-ut |

Net diff — 2 files, +16/−256:

| file | change |
|---|---|
| `beacon/impl/fetcher/block_fetcher.go` | **+12** — production code |
| `beacon/impl/fetcher/block_fetcher_test.go` | −256 — test rewrite |

### 1a. Genesis integrity — unchanged

| file | SHA-256 at tip | matches `source-baseline.toml` |
|---|---|---|
| `config/genesis_mainnet.json` | `bdb5f93f…eac8fa5` | yes |
| `config/genesis_testnet.json` | `2b49c4d6…734a1ae` | yes |

Because the canonical genesis blobs did not move, **no canonical MainNet/T4 chain spec may change**.
The `neox-v2.5.0` Geth comparison (16 commits / 24 files, the Policy blacklist work) remains the
current oracle truth.

### 1b. The one production change — stale-block fetch guard

Two guards were added to `beacon/impl/fetcher/block_fetcher.go`, both keyed on
`maxUncleDist = 7`:

```go
// loop(), announcement path
if dist := int64(notification.number) - int64(f.chainHeight()); dist < -maxUncleDist {
    log.Debug("Peer discarded announcement by distance", ...)
    blockAnnounceDropMeter.Mark(1)
    break
}

// enqueue(), delivered header/block path
if dist := int64(number) - int64(f.chainHeight()); dist < -maxUncleDist {
    log.Debug("Discarded delivered header or block, too far away", ...)
    blockBroadcastDropMeter.Mark(1)
    f.forgetHash(hash)
    return
}
```

This is **fetch policy, not consensus**: dropping an ancient block cannot fork the chain. It is DoS
hardening — a peer may not spend the node's bounded import queue on blocks that can never become
canonical, because dBFT finalizes a block before it is propagated.

### 1c. Neo X side — the gap and the fix

| path | Neo X Geth | `neox-rs` before | `neox-rs` after |
|---|---|---|---|
| announcement (`NewBlockHashes`) | drop if `number < head − 7` | drop unless `number > head` | unchanged — already **stricter** than the oracle |
| delivered block (`NewBlock`) | drop if `number < head − 7` | **no guard** — any block was enqueued | **guard added** |

`propagated_block_disposition` classifies `number <= head` as `CompetingFinalized`, so
`propagated_block_backfill_target` returned `None` for ancient blocks and control fell through to
`enqueue_propagated_block`, which enqueues unconditionally into a queue bounded by
`PROPAGATED_BLOCK_QUEUE_CAPACITY` (2). A peer broadcasting ancient blocks could therefore consume
import slots that a useful block needed.

Fix (committed on the sync branch):

- `MAX_PROPAGATED_BLOCK_BACKWARD_DISTANCE: u64 = 7` in [`crates/neox/node/src/sync.rs`](../../crates/neox/node/src/sync.rs),
  with `propagated_block_is_too_stale()` implementing the oracle's `dist < -maxUncleDist` test using
  `head_number.saturating_sub(..)` so a head below the window cannot underflow into dropping
  everything.
- Applied in the `BeaconEvent::NewBlock` arm before the backfill-target check; drops are logged at
  `debug` and counted by the new `reth_neox_sync_propagated_blocks_dropped_total`.
- Pinned by `drops_propagated_blocks_behind_the_oracle_staleness_window`, which asserts both the
  boundary (`head − 7` inclusive) and the no-underflow case.

The announcement path is documented as intentionally stricter rather than relaxed to match, because
requiring `number > head` is a superset of the oracle's drop rule and needs no change.

## 2. Reth — 33 commits since the baseline

`dc83c609a8336c1d3e29b467ddbc9d896908bd14` (2.5.1, 2026-08-14) → `66a08aba2274d3446caf5d8849fda9b6a0e2f770` (2026-08-28)

### 2a. The `revm` round trip — the pivotal finding

| commit | subject |
|---|---|
| `c12b8f287f` | chore(deps): bump revm to 43.0.0 (#26830) |
| `66a08aba22` | revert: "chore(deps): bump revm to 43.0.0" (#26858) |

Upstream bumped `revm` to `43.0.0`, `revm-inspectors` to `0.43.0`, and `alloy-evm` to `0.39.0`, then
reverted the whole thing the next day. At the tip the workspace is back to `revm 42.0.1`,
`revm-inspectors 0.42.2`, `alloy-evm 0.38.0`.

Consequence: **no `revm 43` migration is required.** The earlier `sync/reth-revm43-check` branch
carried `476388c03a` (`Spec: Into<SpecId> + Clone` bound on the delegating `BlockExecutor`), which was
necessary only against `alloy-evm 0.39`. That work is retained on its branch and is not needed for a
tip sync. It becomes relevant again the moment upstream re-lands the bump, so `crates/neox/evm`
remains the package to watch: it reaches into revm internals (`factory.rs` imports
`precompiles::{DynPrecompile, PrecompilesMap}`, `journaled_state::JournalTr`,
`handler::PrecompileProvider`, `interpreter_types::*`, `precompile::*`).

### 2b. High relevance to Neo X

| commit | subject | why it matters here |
|---|---|---|
| `9e425fe997` | feat(net): allow updating the fork filter at runtime (#26794) | Neo X advertises a folded `eth` fork id for behind-validator backfill. A runtime fork-filter hook sits directly in that surface. |
| `4523fb457e` | feat(net): advertise eth/70 and eth/71 by default (#26824) | wire-capability change in the `crates/net/network` area the BEACON/dBFT handlers ride |
| `5d3c60191d` | fix(net): make eth/72 announcements interoperable with geth (#26670) | announcement path, adjacent to §1c |
| `5e8d2a813e` | feat(engine): remove partial persistence feature flag (#26800) | touched `crates/node/core/src/args/engine.rs`, one of the 7 files Neo X patches; merged cleanly |
| `b472a11f8c` | feat(node): allow KZG warmup without EIP-4844 pool support (#26808) | relevant to Anti-MEV blob-sidecar preservation, which keeps sidecars without a full 4844 pool |
| `f12d52de25` | fix(txpool): reject zero transaction batch size (#26806) | adjacent to Policy-aware pool validation |
| `97fba9d3d2` | feat(txpool): add consensus encoding helper (#26739) | same surface |
| `8666dcd942` | feat(revm): support additional execution witness state (#26828) | the only meaningful Reth-side change inside `crates/revm`, on the witness API the execution path exposes |

### 2c. BAL wave — engine/tree, auto-merged

`701b5a175a` (#26835), `5ba8e25567` (#26844), `e5094e1d68` (#26829), `23305f9d98` (#26832),
`24f7cd94b0` (#26831), `3eb0f03a08` (#26827), `2ea36ecf60` (revert RocksDB BAL, #26788),
`4ca70ab669` (#26837), `b77a6bfd90` (#26836). These churn `crates/engine/tree` and the BAL execution
path. `payload_validator.rs` is one of the 7 Neo X-patched files; the merge kept Neo X's
`PrecompileSet` import and applied the BAL restructure around it.

### 2d. Sync / storage / trie

`444d9fda59` (#26814 authenticated snap storage ranges), `e1ec6b53be` (#26657 snap account range
downloader), `62cd99e405` (#26810), `d892c93b3a` (#26777 prepared snapshot context), `8a8163e718`
(#26819 sparse WAL file ids), `cb7fc64c76` (#26802 materialize destroyed storage trie nodes),
`6917e61f1a` (#26809), `134089c2d3` (#26822), `c9b466c138` (#26811 remove storage wipe markers),
`853a42db1c` (#26812 rocksdb `max_open_files`), `5e8d2a813e` (#26800).

`crates/trie/common/src/added_removed_keys.rs` was deleted and `range_proof.rs` added; Neo X code
references neither (`grep` clean), and `HashedStorage::new(false)` → `HashedStorage::default()`
landed only in upstream `prewarm.rs`.

### 2e. RPC hardening / misc

`00ff650573` (#26782 reject foreign chainId), `7b3432d950` (#26767 reject timestamp overflow in
`eth_simulateV1`), `de401d9b40` (#26776 stop cancelled blocking IO tasks), `b160aa942a` (ci deps).
Directly relevant to the custom `eth_envelopeFee` / `eth_maxEnvelopeGas` / `eth_getCachedTransaction`
surface.

## 3. Merge surface — 7 upstream files

`git merge-tree --write-tree neox <reth tip>` returned exit 0 with a single tree. The real merge was
equally clean.

| file | Neo X edit | upstream commits on the same file | state after merge |
|---|---|---|---|
| `crates/engine/primitives/src/config.rs` | `with_persistence_thresholds` | — | intact |
| `crates/engine/tree/src/tree/payload_processor/prewarm.rs` | `PrecompileSet` import | `c9b466c138` | intact |
| `crates/engine/tree/src/tree/payload_validator.rs` | `PrecompileSet` import | `e5094e1d68`, `24f7cd94b0` | intact; BAL restructure applied around it |
| `crates/evm/evm/src/lib.rs` | `PrecompileSet` boundary (+64) | — | intact |
| `crates/node/core/src/args/engine.rs` | engine args (+22) | `5e8d2a813e` | intact; partial-persistence cfg removed |
| `crates/rpc/rpc-eth-api/src/helpers/config.rs` | ±6 | — | intact |
| `crates/rpc/rpc-eth-types/src/simulate.rs` | `apply_precompile_overrides<P: PrecompileSet>` | `7b3432d950` | intact |

All seven were re-verified by grep after the merge.

## 4. Applied on `sync-reth-tip-20260828`

| commit | subject |
|---|---|
| `631805e272` | docs(neox): record 2026-08-28 upstream audit and fix truncated oracle commit hash |
| `9479126665` | chore: sync Reth 2.5.1 tip `66a08aba22` |
| `e0b9fd13e0` | fix(static-file-types): make changeset-offsets sidecar I/O cross-platform |
| `acb7e7a5a9` | style(static-file-types): use `io::Error::other` |
| `9f201b223d` | fix(cli-commands): portable positioned write in snapshot piece download |
| `5f3d18ca4d` | fix(fs-util,cli-commands): Windows-portable atomic dir fsync + archive paths |
| `60395f2a60` | fix(nippy-jar): drop data-file mmap before `set_len` |
| (working tree) | feat(neox): match the oracle's `maxUncleDist` stale-block guard |

### 4a. Windows portability

The four `e0b9fd13e0`…`60395f2a60` commits are ports of fixes first proved on
`sync/reth-revm43-check`; they are unrelated to the upstream sync and are needed to build on Windows
at all. Upstream gates `reth-static-file-types::changeset_offsets` behind
`#[cfg(all(feature = "std", unix))]` while `reth-provider` consumes it unconditionally, and
`reth-fs-util::atomic_write_file` fsyncs the parent directory via `File::open(dir)`, which is
unix-only. Neither file was touched by the 33 synced commits, so the cherry-picks applied cleanly.

The host build environment also needs the rustup MSVC toolchain to win over a standalone gnullvm
install: prepend `%USERPROFILE%\.cargo\bin` and `C:\Program Files\LLVM\bin`, set `LIBCLANG_PATH`, and
provide the MSVC `cl.exe`/`link.exe` and Windows SDK `INCLUDE`/`LIB`.

## 5. Gates

<!-- GATES -->

## 6. Baseline advanced

| field | before | after |
|---|---|---|
| `reth.commit` | `dc83c609a8336c1d3e29b467ddbc9d896908bd14` | `66a08aba2274d3446caf5d8849fda9b6a0e2f770` |
| `neox_geth.commit` | `76580e6a54d7af46b6e0d8f19756cec40670805b` | `f0e236838bb334c7c0d29eeca33533ed0cfda254` |

Updated in `docs/neox/source-baseline.toml`, `docs/neox/README.md`, and the root `README.md`. Genesis
SHA-256 values are unchanged and were re-verified against the new oracle commit.

## 7. Explicit non-claims

- No canonical chain spec, genesis hash, or fork schedule changed.
- A green compile is **not** consensus parity. The live gates below are unchanged and still required
  before any release note: fresh-datadir MainNet sync to canonical hash/roots, restart/reopen
  equality, mixed-client SNAP/ETH + dBFT production, crash/unwind/controlled-reorg, and the DKG
  epoch gate.
- No live MainNet/TestNet sync was run in this audit.
- The stale-block guard changes which propagated blocks a node *imports*, never which blocks it
  considers valid, so it cannot fork the chain; it is still a peer-facing behavior change and belongs
  in the mixed-client smoke run.
