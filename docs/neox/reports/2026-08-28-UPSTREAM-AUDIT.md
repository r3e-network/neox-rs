# Upstream audit — Reth and Neo X Geth — 2026-08-28

> **Superseded.** Reth reverted the `revm 43` bump the same day (`66a08aba22`, #26858), which
> invalidates the migration premise in §5b, and the Neo X Geth oracle has since moved two commits.
> See [2026-08-28-UPSTREAM-SYNC.md](2026-08-28-UPSTREAM-SYNC.md) for the audit and sync performed
> against Reth `66a08aba22`. This file is kept as the record of the earlier assessment.

Scope: a systematic audit of the pinned compatibility oracle (Neo X Geth), of upstream Reth drift
since the pinned baseline, and of how that drift lands on the `neox` branch. This report records an
**assessment**, not an applied sync. The pinned baseline in
[`docs/neox/source-baseline.toml`](../source-baseline.toml) is deliberately left unchanged until a
sync is actually performed and passes the release gates below.

Method: `paradigmxyz/reth` and `bane-labs/go-ethereum` were fetched read-only through the local
proxy into throwaway remotes (`reth-up`, `geth-up`). `neox` was never pushed to and the working tree
was left clean. All conclusions below are reproducible from the fetched refs.

## Headline

- The Neo X Geth oracle has **not moved**: `bane-main` head is still the pinned baseline. The
  canonical MainNet and T4 genesis blobs are byte-for-byte identical to the recorded SHA-256. No
  protocol-oracle action is required, and no canonical chain spec should change.
- Reth has drifted **32 commits** since the pinned `2.5.1` baseline (`dc83c609a8` → `701b5a175a`).
- A trial merge of the Reth tip into `neox` is **textually conflict-free** (`git merge-tree` exit 0).
  The historical pattern holds: Neo X lives in dedicated crates, so upstream moves merge cleanly.
- The real cost is **not** git conflicts — it is a coordinated `revm 42 → 43` dependency major, with
  `revm-inspectors` and `alloy-evm` moving in lockstep. `crates/neox/evm` reaches into revm internals
  directly, so this bump is the one thing that can break the build even with a clean merge.
- Recommendation: adopt the Reth tip in a dedicated sync commit, but treat the `revm` migration and
  the `revmc`/LLVM build toolchain as the gating work. Do not claim compile or consensus parity until
  the local and live gates below pass.

## 1. Neo X Geth (behavior oracle) — status: stable

| Field | Recorded baseline | Live `bane-main` head | Delta |
|---|---|---|---|
| commit | `76580e6a54d7…0670805b` | `76580e6a54d7…0670805b` | **0 commits** |
| branch | `bane-main` | `bane-main` | — |
| version | `0.7.0-dev` (post `start-v0.7.0`, PR #652) | same | — |

Integrity verification against the fetched reference client:

- `config/genesis_mainnet.json` SHA-256 = `bdb5f93f…eac8fa5` — **matches** `source-baseline.toml`.
- `config/genesis_testnet.json` SHA-256 = `2b49c4d6…734a1ae` — **matches** `source-baseline.toml`.

Because the oracle has not advanced, the `neox-v2.5.0` Geth comparison (16 commits / 24 files, the
Policy blacklist work) is still the current oracle truth. Nothing here opens a protocol gap.

**Data-integrity nit (fixed alongside this audit):** the oracle commit was recorded as a 39-character
hex string (`76580e6a54d7af46b6e0d8f19756cec40670805`) in both `README.md` and
`source-baseline.toml`, missing the trailing `b`. It resolves unambiguously by prefix, so it never
broke anything, but a truncated object id is a latent footgun. Corrected to the full 40-character
`76580e6a54d7af46b6e0d8f19756cec40670805b`.

## 2. Reth — drift since baseline: 32 commits

Range `dc83c609a8` (`2.5.1`, 2026-08-14) → `701b5a175a` (2026-08-27). Grouped by Neo X relevance.

### 2a. High relevance to Neo X

- **`c12b8f287f` chore(deps): bump revm to 43.0.0 (#26830)** — the pivotal change. revm majors move
  internal trait/paths. `crates/neox/evm/src/factory.rs` imports
  `precompiles::{DynPrecompile, PrecompilesMap}`, `journaled_state::JournalTr`,
  `handler::PrecompileProvider`, `interpreter_types::{InterpreterTypes, MemoryTr, StackTr}`,
  `precompile::{PrecompileSpecId, Precompiles}`; `executor.rs` uses
  `revm::context_interface::result::HaltReason` and `revm::bytecode::Bytecode`. All are candidates for
  the migration. `revm-inspectors` 0.42.2 → 0.43.0 and `alloy-evm` 0.38.0 → newer must move together.
- **`8666dcd942` feat(revm): support additional execution witness state (#26828)** — the only
  meaningful Reth-side change inside `crates/revm` (witness.rs, +65/−13). Touches the witness API the
  execution path exposes.
- **`9e425fe997` feat(net): allow updating the fork filter at runtime (#26794)** — Neo X advertises a
  folded `eth` fork id for behind-validator backfill (see `ccb1493d0b`, `294c20b074`). A runtime
  fork-filter hook is directly in that surface; verify the folded-fork behaviour still holds after the
  merge.
- **`4523fb457e` feat(net): advertise eth/70 and eth/71 by default (#26824)** and **`5d3c60191d`
  fix(net): make eth/72 announcements interoperable with geth (#26670)** — wire-capability changes on
  the same `crates/net/network` area the BEACON/dbft handlers ride.
- **`f12d52de25` fix(txpool): reject zero transaction batch size (#26806)** and **`97fba9d3d2`
  feat(txpool): add consensus encoding helper (#26739)** — adjacent to Policy-aware pool validation in
  `crates/neox/*`.
- **`b472a11f8c` feat(node): allow KZG warmup without EIP-4844 pool support (#26808)** — relevant to
  the Anti-MEV blob-sidecar preservation path, which keeps blob sidecars without a full 4844 pool.

### 2b. BAL (block-access-list) wave — engine/tree, mostly auto-merge

`701b5a175a` (#26835), `5ba8e25567` (#26844), `e5094e1d68` (#26829), `23305f9d98` (#26832),
`24f7cd94b0` (#26831), `3eb0f03a08` (#26827), `2ea36ecf60` (revert RocksDB BAL #26788),
`4ca70ab669`/`b77a6bfd90` (rpc cleanup), `2ea36ecf60`. These churn `crates/engine/tree` (11 files) and
the BAL execution path. They merge cleanly (see §3) but sit behind a `payload_validator.rs` hunk
overlap worth an eyeball.

### 2c. Sync / storage / trie

`444d9fda59` (#26814 authenticated snap storage ranges), `e1ec6b53be` (#26657 snap account range
downloader), `62cd99e405` (#26810 account range review), `d892c93b3a` (#26777 prepared snapshot
context), `8a8163e718` (#26819 sparse WAL file ids), `cb7fc64c76` (#26802 materialize destroyed
storage trie nodes), `6917e61f1a`/`134089c2d3`/`c9b466c138` (trie perf/refactor), `853a42db1c` (#26812
rocksdb max_open_files), `5e8d2a813e` (#26800 remove partial-persistence flag). These feed the
header/backfill sync that MainNet sync depends on.

### 2d. RPC hardening / misc

`00ff650573` (#26782 reject foreign chainId), `7b3432d950` (#26767 reject timestamp overflow in
`eth_simulateV1`), `de401d9b40` (#26776 stop cancelled blocking IO tasks), `b160aa942a` (ci deps),
plus the `2ea36ecf60` revert. Directly relevant to the custom `eth_envelopeFee` /
`eth_maxEnvelopeGas` / `eth_getCachedTransaction` surface.

## 3. Merge-conflict surface — clean

`git merge-tree --write-tree HEAD reth-up/main` → **exit 0, no conflicted files**.

`neox` modifies only **7 upstream Reth files** (122 insertions / 13 deletions total):

| File | Neo X edit | Incoming Reth commits on same file | Expected state |
|---|---|---|---|
| `engine/primitives/src/config.rs` | +29 (flags) | — | clean |
| `engine/tree/.../prewarm.rs` | import-only (`PrecompileSet`) | `c9b466c138` (#26811) | clean (non-overlapping hunk) |
| `engine/tree/.../payload_validator.rs` | import-only (`PrecompileSet`) | `e5094e1d68` (#26829), `24f7cd94b0` (#26831) | clean textually; **eyeball BAL restructure** |
| `evm/evm/src/lib.rs` | +64 (`PrecompileSet` boundary) | — | clean |
| `node/core/src/args/engine.rs` | +22 (args) | `5e8d2a813e` (#26800) | clean |
| `rpc/rpc-eth-api/helpers/config.rs` | ±6 | — | clean |
| `rpc/rpc-eth-types/src/simulate.rs` | generic `apply_precompile_overrides<P: PrecompileSet>` | `7b3432d950` (#26767) | clean (different hunk) |

Textual cleanliness is a necessary but **not sufficient** condition: the `revm 43` bump produces a
merged tree whose Cargo.lock is at revm 43 while `crates/neox/evm` still targets revm 42 paths. Expect
**semantic** (compile-time) breakage in `crates/neox/evm` and possibly `crates/evm/evm`, not git
conflicts.

## 4. Build toolchain — resolved (was mispredicted)

Initial read: `crates/revm` sits on `revmc` (`llvm-prefer-static`), which would need an LLVM toolchain.
In practice this was **not** the blocker. `reth-revm` `default = ["std"]` does not enable `revmc`, so it
never entered the `neox-rs --bins` build graph.

The actual gate on this host was PATH ordering: a standalone `Rust stable LLVM 1.95` (host
`x86_64-pc-windows-gnullvm`) shadowed the rustup `stable-x86_64-pc-windows-msvc` toolchain, so `cc-rs`
correctly targeted `windows-gnu` and pulled the `llvm-mingw` clang — which then failed on `mmintrin.h`
and the UCRT `FILE_ID_INFO` gap. The machine already had everything needed: VS 2022 Community C++
(`14.44.35207`), Windows SDK `10.0.26100.0`, and LLVM 22 with `libclang.dll` for bindgen.

Fix (no installs): build inside `vcvars64.bat` with `~/.cargo/bin` and `C:\Program Files\LLVM\bin`
prepended to `PATH` and `LIBCLANG_PATH` set, so the rustup MSVC `cargo`/`rustc` and the MSVC-targeting
clang win. Under that environment `reth-mdbx-sys` (bindgen) and `librocksdb-sys` (cl.exe) both compile.

## 5. Recommended sync plan (gated)

1. Cut `sync/reth-2.5.x-<date>` from `neox`. `git merge reth-up/main` — expect a clean merge;
   reconcile only `Cargo.lock`.
2. Bump workspace `revm` 42.0.1 → 43.0.0, `revm-inspectors` → 0.43.0, and follow the required
   `alloy-evm` version. Then migrate `crates/neox/evm` (`factory.rs`, `executor.rs`, `config.rs`) and
   `crates/evm/evm` to the revm 43 trait/path changes.
3. Local gates (stable Rust 1.95, `+nightly fmt`):
   - `cargo +stable check -p reth-neox-evm` first — this is where revm 43 bites; isolate it before a
     full workspace build.
   - `cargo +stable build --locked -p neox-rs --bins`
   - Neo X package set tests + `reth-trie*` + strict Clippy `-D warnings`.
   - Re-assert the folded-`eth` fork-id and Policy-blacklist regressions against revm 43.
4. Live gates before any release note (unchanged from prior syncs): fresh-datadir MainNet sync to
   canonical hash/roots; restart/reopen equality; mixed-client SNAP/ETH + dBFT production; crash/
   unwind/controlled-reorg across the partial-persistence boundary.

## 5b. Migration performed — 2026-08-28 (branch `sync/reth-revm43-check`)

Executed the sync + revm 43 migration on a scratch branch (`neox` untouched, nothing pushed):

- `git merge` of Reth tip `701b5a175a` — **clean, zero conflicts**; root `Cargo.toml` picked up
  `revm 43.0.0`, `revm-inspectors 0.43.0`, `alloy-evm 0.39.0`.
- The Rust-side migration cost was **exactly one line**. `crates/neox/evm/src/executor.rs:72`:
  alloy-evm 0.39's `BlockExecutor for EthBlockExecutor` added the bound
  `E: Evm<Spec: Into<SpecId> + Clone>`. Neo X's delegating `BlockExecutor` impl was missing it, so the
  three `EthBlockExecutor` calls (`apply_pre_execution_changes`,
  `execute_transaction_without_commit`, `commit_transaction`) failed E0599. Added
  `Spec: Into<revm::primitives::hardfork::SpecId> + Clone` to the `E: Evm<...>` bound.
- `cargo check` (stable 1.95) green on: `reth-neox-evm`, `reth-neox-consensus`, `reth-neox-antimev`,
  `reth-neox-network`, `reth-neox-chainspec`, `reth-neox-consensus-engine`.
- `cargo check -p neox-rs --bins` under the host's default toolchain failed in the **native build
  scripts only** — `reth-mdbx-sys` (llvm-mingw clang cannot parse MSVC-style `mmintrin.h` SIMD) and
  `librocksdb-sys` (`FILE_ID_INFO` absent from the UCRT SDK) — because the standalone gnullvm `rustc`
  was shadowing the rustup MSVC one (see §4). The sync does not touch the libmdbx/librocksdb C sources
  (empty upstream diff for `crates/storage/libmdbx-rs`), so this is environmental, not a revm change.
- With the toolchain PATH fixed, `cargo build -p neox-rs --bin neox-rs` cleared the native gate
  (`reth-mdbx-sys` and `librocksdb-sys` compiled) but then hit **two pre-existing Windows portability
  bugs** — both present at the pinned baseline, unrelated to the revm sync (they fail identically on
  `neox` because the node was never built on Windows here):
  - `b48b774222` — `reth-static-file-types` `changeset_offsets` module was `#[cfg(all(std, unix))]`
    and its reader used `FileExt::read_exact_at`, while `reth-provider` consumes the reader/writer
    unconditionally; `ChangesetOffsetWriter` also stored an append-only handle, so `set_len`/`truncate`
    hit `ERROR_ACCESS_DENIED` on Windows. Ported to portable `Mutex<File>` seek+read, a read+write
    writer handle with seek-to-end append, and widened the gate to `feature = "std"`. All 6 unit tests
    pass on Windows.
  - `4b3195ab52` — `reth-cli-commands` snapshot piece download used `FileExt::write_all_at`; switched
    the thread-local worker handle to `&mut File` with seek+`write_all`.
- Result: **`target/debug/neox-rs.exe` (148 MB) built and runs** — `--version`, `--help`, and the
  `node`/`download` subcommands work; `--version` reports Commit SHA `4b3195ab52`, matching this branch.

Net: the full node binary now builds and runs on Windows from the synced revm 43 tree. The three
branches commits are `be38d8b2f8` (merge) + `476388c03a` (revm 43) + `b48b774222`/`4b3195ab52`
(Windows ports). What still separates this from a `neox` merge is **behavioral**, not build-level:
strict Clippy, the full Neo X test package set, and the live MainNet sync / mixed-client / DKG gates in
§5 step 4 — a green compile is not consensus parity.

## 5c. Local behavioral + lint gates (Windows, this run)

Ran under the same MSVC `vcvars64` environment (rustup stable 1.95).

- **Neo X package tests** — `-p reth-neox-{chainspec,consensus,consensus-engine,antimev,evm,network,node} -p reth-static-file-types -p neox-rs`: **361 passed, 0 failed**.
- **csoff port validation** — `reth-static-file-types` changeset tests **6/6 pass** on Windows; `reth-provider` lib compiles and its unit tests run (it consumes the reader/writer unconditionally).
- **`reth-cli-commands`** — first pass 127/4-failed; the 4 are now **fixed** (`923fb0fc9e`) → **131 passed, 0 failed**. Root causes turned out to be real cross-platform bugs, not test-only:
  - `init_state::without_evm` (2): `reth-fs-util::atomic_write_file` fsyncs the **parent directory** via `File::open(dir)+sync_all`, which is unix-only (Windows → `ERROR_ACCESS_DENIED`). This broke every nippy-jar static-file commit, so `init_genesis` failed. Now gated `#[cfg(unix)]`.
  - `download::manifest` (2): archive member paths and `output_files[].path` came from `PathBuf::to_string_lossy()`, yielding `"db\\mdbx.dat"` on Windows into a portable archive index. Now normalized to `'`-joined components.
- **`reth-nippy-jar::tests::test_pruner`** — was a Windows-only failure (reth's own test called `set_len` while a `DataReader` mmap was alive → `ERROR_USER_MAPPED_FILE`, Unix tolerates it). Fixed (`e4b62a1f1d`) by `drop(reader)` before the truncate. All **8 `reth-nippy-jar` lib tests pass on Windows**.
- **Strict clippy** (`--all-targets -- -D warnings`) over the node package set (`reth-neox-*`, `neox-rs`, `reth-{static-file-types,cli-commands,fs-util,nippy-jar,provider,cli-util,db}`): **exit 0, clean**. Approach chosen to minimize the fork's upstream-patch surface:
  - `clippy::missing_const_for_fn` (nursery) fired on error-only / no-op `&self` fns in **vendored** reth (`cli-util sigsegv::install`, `db is_zfs`). A toolchain pin cannot dodge it (MSRV `1.95` is exactly the firing version; CI is rolling `@stable`), so it is **disarmed at `[workspace.lints.clippy]`** (`missing_const_for_fn = "allow"`, TODO comment) following the repo's own `redundant_field_names = "allow"` precedent. Both upstream source edits were reverted (`7551880291`).
  - Kept fixes live almost entirely in **fork-owned** files and address precise lints (not blanket allows): `io::Error::other` (static-file-types), needless borrow (`chainspec/spec.rs`), `use libc as _;` under `cfg(not(unix))` (neox-node), redundant clone + const stubs (neox-node `dkg_prover`), and cfg-gating two test-only items (dkg_migrate `use super::*`→`cfg(unix)`; `load_signer`→`cfg(all(test, target_os="linux"))`).
  - One deliberate exception kept in upstream src: the `as u32` redundant-cast removal in `reth-db` — `unnecessary_cast` is a valuable correctness lint, so weakening it workspace-wide to avoid one vendored line is the worse trade. Net upstream-src surface is now a single trivial line.

Net: after the Windows ports, **every Windows gate is green** — Neo X package set (361),
`reth-cli-commands` (131), `reth-nippy-jar` (8) all pass, and the whole node package set passes
`cargo clippy --all-targets -D warnings`. The `reth-fs-util` dir-fsync fix was in particular a real
storage crash-safety portability bug (it broke all static-file commits on Windows), not just a test
fix. What still separates this from a `neox` merge is the **live behavioral** gate only — MainNet
sync-to-canonical-hash, restart/reopen equality, mixed-client SNAP/ETH + dBFT, and DKG (§5 step 4) —
which cannot be exercised here.

## 6. Explicit non-claims

- This audit does **not** change the compatibility baseline or any canonical chain spec.
- A clean compile and a runnable binary (§5b) are **not** proof of consensus equivalence. The two
  Windows ports change sidecar/download file IO that must be re-exercised by the full Neo X test set
  and the live sync gates before any parity claim.
- No live MainNet/TestNet sync was run in this audit.
