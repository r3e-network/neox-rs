# Full validation, refactor, and iteration — 2026-08-29

Scope: a full verification pass over `neox` at `182d654db1` on the Windows host, the refactors
remaining from the [2026-07-21 code-quality audit](code-quality-audit-2026-07-21.md) that were
safe to land, and the environment repairs the pass surfaced. Gate results are recorded per the
established method; nothing here changes consensus behavior, chain specs, or wire bytes.

## Headline

| | |
|---|---|
| Neo X gates | fmt (after applying drift), strict clippy, 362/362 package tests, binary build, 62/62 script tests — **all green** |
| Script suite | **0 failures** — the 5 `test_install_sh.py` failures recorded on 2026-08-28 as a permanent MSYS artifact are **fixed** (see §2c) |
| Upstream-touched packages | 11 of 13 fully green; `reth-db` 37/38, `reth-provider` 224/233 — failures reclassified from "temp-file contention" to two deterministic Windows artifacts (§3) |
| Refactors landed | glob re-exports → explicit lists (antimev + evm), lock-poison policy documented, installer tests made host-correct |
| Live gates | unchanged and still open (fresh-datadir MainNet sync, mixed-client DKG, differential RPC) |

## 1. Environment repairs (host, no repo change)

### 1a. The standalone gnullvm toolchain still shadows rustup

The condition recorded in the 2026-08-28 sync report §4a recurs whenever a shell starts without
the corrected PATH: `rustc -vV` reports `x86_64-pc-windows-gnullvm` because
`C:\Program Files\Rust stable LLVM 1.95\bin` precedes `~/.cargo/bin`, and cc-rs then compiles
librocksdb-sys with `--target=x86_64-pc-windows-gnu` and fails. Two further gaps beyond §4a:

- **MSVC `link.exe` is not on PATH at all.** With the MSVC toolchain selected, rustc falls back to
  Git's `/usr/bin/link.exe` (coreutils), which fails with `missing operand after '\377\376'`.
  The VS2022 `Hostx64/x64` directory must be prepended.
- **`cargo +nightly fmt` silently ran stable rustfmt.** The standalone install's rustfmt wins
  resolution; the reliable invocation is `RUSTFMT=<nightly-toolchain>/bin/rustfmt.exe cargo
  +nightly fmt`. The nightly `rustfmt`/`clippy` components also had to be re-added.

A working shell setup: prepend `~/.cargo/bin`, MSVC LLVM `bin`, VS2022 MSVC
`bin\Hostx64\x64`, and the nightly toolchain `bin`; export `LIBCLANG_PATH`; import
`INCLUDE`/`LIB`/`LIBPATH` from `vcvars64.bat`. `CARGO_INCREMENTAL=0` as before.

### 1b. Working-tree shell scripts were CRLF despite `eol=lf`

All 26 tracked `.sh` files had CRLF on disk while the index and `.gitattributes`
(`*.sh text eol=lf`, added by `182d654db1`) require LF. Git reports them clean because the
normalized blobs match, so a checkout never heals them; any direct `bash <script>` run failed on
`$'\r'`. The working tree was rewritten to LF (`git status` stays clean — no commit).

## 2. Gate results

### 2a. Neo X packages

| gate | command | result |
|---|---|---|
| Nightly rustfmt | `RUSTFMT=<nightly> cargo +nightly fmt --all -- --check` | **pass** after applying 3 files of pre-existing drift (§2d) |
| Strict clippy | `cargo clippy <Neo X set> --all-targets -- -D warnings` | pass, exit 0 |
| Package tests | `cargo test --no-fail-fast -p reth-neox-{chainspec,consensus,consensus-engine,antimev,evm,network,node} -p reth-static-file-types -p neox-rs` | **362 passed, 0 failed** |
| Binary | `cargo build -p neox-rs --bins` | pass |
| Operational scripts | `python -m unittest discover -s scripts/tests -t scripts/tests` | **62 tests: 50 passed, 12 skipped, 0 failed** |

### 2b. Packages the 33 synced commits touch

`cargo test --no-fail-fast -p reth-{trie,trie-common,trie-db,trie-parallel,trie-sparse,cli-commands,static-file,static-file-types,nippy-jar,fs-util,db-common}` — **all pass**
(82, 155, 10, 2, 12, 131+, 2, 14, 8, pass, 11 across the suite binaries).

`reth-db` and `reth-provider` results in §3.

### 2c. The installer-script test failures are fixed — prior classification corrected

The 2026-08-28 report recorded 5 `test_install_sh.py` failures as "a pre-existing MSYS
path-invocation artifact" and reverted a fix attempt as "tuning fork-owned tests to this host".
That conclusion was wrong on two counts; the real causes were ordinary Windows defects in the
test itself, each fixable without weakening any assertion:

1. **A bare `"bash"` from a Windows parent resolves through CreateProcess, which searches
   System32 before PATH** — so every spawn launched WSL bash (`shutil.which` misleadingly
   reports Git Bash because it only scans PATH). WSL bash cannot see the Windows fixture paths
   the harness passes. Fixed by spawning `shutil.which("bash")` (Git Bash, the target the test's
   own `bash_script_path` docstring describes). No change on POSIX.
2. **`write_text` translated fixture newlines to CRLF on Windows**, so the fake `curl`/`uname`
   scripts and `.sha256`/JSON/TSV fixtures carried `\r`. Fixed with `newline="\n"` (byte-identical
   on POSIX).
3. **PATH fragments were joined with a hardcoded `:`** — on Windows that must be `os.pathsep`.
   No change on POSIX.

Result: 62/62 non-skipped tests pass. The suite was not weakened; assertions are unchanged.

### 2d. Formatting drift

Nightly rustfmt (1.10.0-nightly `e457a7b0d`) flagged 3 files whose formatting predated the
current nightly: `crates/cli/commands/src/download/fetch.rs`,
`crates/neox/node/src/sync.rs`, `crates/static-file/types/src/changeset_offsets.rs`.
`cargo +nightly fmt --all` applied; check now exits 0.

## 3. `reth-db` / `reth-provider` — failures reclassified

At `--test-threads=4`, `reth-db` is 37/38 and `reth-provider` 224/233. The 2026-08-28 report
attributed the earlier failures to temp-file contention and claimed every failure passed alone.
Re-examined today: the failures are **deterministic and reproduce in isolation**, so the
contention explanation was wrong. Two distinct causes:

- `reth-db` `lockfile::tests::test_lock` — panics at `ProcessUID::new(1).unwrap()`. The test
  assumes Unix PID-1 semantics (an always-queryable `init`); on Windows PID 1 has no readable
  start time and `sysinfo` returns `None`. Not fixable without changing the upstream test's
  platform assumption; not a regression (path untouched by the sync).
- `reth-provider` (9 tests: static-file truncation/prune writer tests and
  `remove_block_and_execution_above_returns_persistence_frontiers`) — all fail with
  `Os error 1224` (`ERROR_USER_MAPPED_FILE`): the prune path calls `set_len` on a nippy-jar data
  file while a `DataReader` mmap of the same file is still alive inside the provider. Unix
  tolerates resizing mapped files; Windows rejects it. `60395f2a60` fixed the one site *inside
  reth-nippy-jar's own tests*; the provider-level prune path (which reads through the provider's
  jar cache while the writer truncates) has the same Unix assumption. This is the fork's known
  Windows storage-port surface, not something the 2026-08-28 sync regressed; it should be
  tracked as a Windows prune/mmap limitation — ideally fixed by dropping cached readers before
  truncation, which needs a designed pass over `StaticFileJarCache` ownership, not a spot patch.

## 4. Refactors landed

### 4a. Glob re-exports replaced with explicit lists (audit item #4)

`crates/neox/antimev/src/lib.rs` (7 globs, 71 names) and `crates/neox/evm/src/lib.rs` (1 glob,
46 names) now re-export each public item explicitly, so widening or shrinking the public surface
is a reviewable diff. Two internal consumers that reached `pub(crate) DkgKeyGroup` through the
glob's visibility cap (`dkg_keystore.rs`, `geth_keystore.rs`) now import it from
`dkg_state` directly — strictly tighter than before. All workspace consumers compile unchanged;
the in-tree binary was re-verified against the new lists.

### 4b. Lock-poison policy documented (audit item #3)

The previously implicit split is now stated in the module docs of both sides:
`reth-neox-network` (protocol state, caches, event receivers) fails fast with `expect` on
poison because a mutated-consensus invariant is unsafe to continue from;
`reth-neox-node/signer.rs` (`DkgPrivateShares`) recovers via `PoisonError::into_inner` because
signing shares are availability-oriented cache state that canonical PVSS verification re-checks.
No behavior change.

## 5. Explicit non-claims

- No consensus, crypto, storage-format, or wire behavior changed. The only runtime-code edits
  are two `use`-statement rewrites and module documentation.
- The `reth-db`/`reth-provider` Windows failures are environment/platform artifacts of upstream
  tests, recorded here with root causes; they are not counted as regressions, but equally they
  are not "green" — any release claim must note them.
- Live gates remain open: fresh-datadir MainNet sync with restart equality, mixed-client
  SNAP/ETH + dBFT production, crash/unwind/reorg across persistence, DKG epoch gate, RPC
  differential gate.
- Audit items still open: persistent fuzz targets, doctests for public construction/validation
  APIs, and the guarded `sync.rs` driver decomposition (4,062 lines at this pass; audit §1
  requires state-ownership design before moving more code).
