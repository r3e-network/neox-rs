# Upstream sync — Reth 2.8.1 (pre-evm2) + Neo X Geth `b51d712adf` (2026-10-28)

Follow-up to [2026-10-18-UPSTREAM-SYNC-RETH-2.7.md](2026-10-18-UPSTREAM-SYNC-RETH-2.7.md).
Branch: `sync-reth-main-20261028`.

## Verdict

The fork now tracks Reth upstream main `0e9de4b95dc0` (`2.8.1`, 252 commits after the previous
`8868180a0e` baseline) and the Neo X Geth `bane-main` tip
`b51d712adf36544fce939767c9a08a4060117a59`. The Neo X crates compiled against the merged tree
without source changes; the only Neo X edit is one test fixture.

The Reth merge deliberately stops one commit before `9d1638f328 refactor!: replace revm with evm2
(#25002)`. That commit removes revm and alloy-evm, and the Neo X EVM cannot be ported to evm2 yet
without a call-frame hook that evm2 doesn't provide (see [evm2 blocker](#evm2-blocker)). The
32 upstream commits from `9d1638f328` to the observed tip `f1cc50e4fc` are not merged.

## Reth 2.8.1 (through `0e9de4b95d`)

- Merge source: `0e9de4b95dc010d9d54c1ea17884102a9d717669` (2026-10-24), the parent of the evm2
  switch. Workspace version `2.8.1`, revm `43.0.3`, alloy-evm `0.39`, `rust-version` 1.95.
  640 files changed (+38,137 / −18,120).
- Notable upstream changes: resumable interrupted pipeline unwinds (#28067), state-import and
  history-lookup fixes (#28053), static-file read-error propagation (#28064), complete trie range
  changesets (#27615), snap-sync root checks against headers (#27987), network peer-trust and
  dial-capacity fixes (#27843, #27946–#27951), WebSocket origin allowlists (#27952), CLI argument
  validation and error surfacing (#27978–#27984), and a block-builder executor customization hook
  (#28011).
- Conflicts:
  - `AGENTS.md`: kept the Neo X fork's host/build guidance.
  - `Cargo.lock`: took upstream's, then refreshed by cargo.
  - `engine/tree` `prewarm.rs` and `payload_validator.rs`: merged the import lists, keeping the
    fork's `PrecompileSet` bridge alongside upstream's new imports.
  - `node/builder` `launch/common.rs`: took upstream's extended unwind condition
    (`partial_trie_unwind_target`, `storage_unwind`, `pending_pipeline_unwind`) and kept the fork's
    Windows `clear_cached_readers()` call after the unwind.
  - `provider` static-file `writer.rs` `truncate()`: took upstream's `ensure_above_pruned_anchor`
    guard and kept the fork's `clear_cached_readers()`.
- Neo X test fixture: upstream #27682 makes the Ethereum pool validator take its block gas limit
  from the tip header. `MockEthProvider`'s default genesis has a 5,000 gas limit, so
  `stateless_invalid_transactions_bypass_state_and_neox_validation` rejected its 21,000-gas
  transfer statelessly. The test now builds the mock from Neo X MainNet's chain spec, which also
  makes the fixture realistic. Pool behavior is unchanged.

## Neo X Geth `b51d712adf`

Two commits since `9dec1dc364`: `66b1c842cc privnet: add Ethereum system contract allocation` and
its merge. Only `privnet/{four,seven,single,zk}/genesis_privnet.json` changed (+28 lines each).
MainNet/T4 genesis bytes, consensus, and execution code are unchanged, so no Rust change is needed;
the vendored genesis fingerprints remain valid.

## evm2 blocker

`9d1638f328` replaces revm with `evm2` (git dependency, `rust-version` 1.96). Reth's
`EvmFactory` becomes `Types: evm2::EvmTypes` + `precompiles(spec)` + `configure_evm`, and custom
opcodes move to compile-time `OpcodeConfig` overlays. Most Neo X features map cleanly:

| Neo X feature (`crates/neox/evm`) | evm2 mapping |
|---|---|
| DKG-fork early MCOPY | `OpcodeConfig` overlay selected by Neo X `SpecId` |
| DKG precompile set (Prague set before Osaka) | `precompiles(spec)` |
| `NeoXBlockExecutor` (Policy base fee, envelope limits, `onPersist`, no reward) | reth block-executor layer, largely unchanged |
| **Policy blacklist at call-frame creation** | **no equivalent** |

Geth checks the Policy blacklist after the value transfer for every non-precompile CALL,
CALLCODE, DELEGATECALL, and STATICCALL target, including empty-code accounts, and reverts with gas
unchanged (`core/vm/evm.go`). evm2's `execute_call_message` goes depth check → checkpoint →
transfer → precompile (only if `PrecompileProvider::contains`, which has no state access) →
empty code returns `Stop` → interpreter. There is no call-frame hook, including on current evm2
main, so the blacklist cannot be expressed without either:

1. a small hook in a forked or vendored evm2 after the precompile check (cleanest, keeps exact
   Geth semantics);
2. a catch-all `PrecompileProvider` that claims every address and re-dispatches (fragile, changes
   empty-account and gas paths); or
3. staying on the pre-evm2 base until upstream adds a hook.

Until one is chosen, merging past `9d1638f328` would break consensus-critical Neo X execution.
Post-switch upstream fixes worth carrying once ported: `3c8b4e8435` (retain recreated account state
in cache), `5fc3a81d34` (bound safe-no-sync rollback), `4c1584b78d` (precompile cache across
big-block segments), `7a2968a9d9` (group proof targets by child).

## Windows environment rebuild

The host had lost its rustup install. Rustup was reinstalled with `stable` and `nightly`
`x86_64-pc-windows-msvc` toolchains (rustfmt, clippy), and the default host set to MSVC. A
PowerShell wrapper `$env:TEMP\neox-msvc-env.ps1` replaces the Bash script for this session:

```powershell
$vcvars = 'D:\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$vars = cmd /c "`"$vcvars`" >nul 2>&1 && set"
foreach ($line in $vars) {
    if ($line -match '^(INCLUDE|LIB|LIBPATH|Path|VCToolsInstallDir|WindowsSdkDir|UCRTVersion|WindowsSDKVersion)=(.*)$') {
        Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
    }
}
$cargoBin = "$env:USERPROFILE\.cargo\bin"
# MSVC bin\HostX64\x64 ahead of System32 makes the rustup proxy crash (0xC0000005), so it goes last.
# llvm-mingw's clang.exe on PATH makes bindgen use MinGW headers (mmintrin.h parse errors).
$entries = $env:Path -split ';' | Where-Object { $_ -and $_ -notlike '*Rust stable LLVM*' -and $_ -notlike '*LLVM-MinGW*' }
$msvcBin = $entries | Where-Object { $_ -like '*\VC\Tools\MSVC\*\bin\HostX64\x64' }
$env:Path = (@($cargoBin) + ($entries | Where-Object { $_ -notin $msvcBin }) + $msvcBin) -join ';'
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc'
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
$env:CARGO_INCREMENTAL = '0'
$env:RUSTFMT = "$env:USERPROFILE\.rustup\toolchains\nightly-x86_64-pc-windows-msvc\bin\rustfmt.exe"
$env:HTTPS_PROXY = 'http://127.0.0.1:7890'
$env:HTTP_PROXY = 'http://127.0.0.1:7890'
```

## Verification (Windows)

| Gate | Result |
|---|---|
| Neo X tests (`reth-neox-*`, `neox-rs`) | **427 passed, 0 failed** |
| `cargo check -p reth-engine-tree -p reth-node-builder -p reth-provider --tests` | pass |
| `reth-provider --lib` | **252 passed, 0 failed** |
| nightly rustfmt `--check` | clean (one merged import list reflowed) |
| clippy (Neo X crates, `neox-rs`, engine tree, node builder, provider) | no errors; Neo X warning `items_after_test_module` in `bin/neox-rs` predates the merge and is fixed separately; upstream doc-backtick warnings from the newer nightly are left to upstream |
| `scripts/tests/test_baseline_docs.py` | pass |

Not re-run for this sync: the Linux workspace check, live MainNet differential, and mixed-client
dBFT/DKG gates from the 2.7 report. Run them before a release cut from this base.

Artifacts: `outputs/sync-20261028-neox-tests-2.log`, `outputs/sync-20261028-clippy.log`,
`outputs/sync-20261028-provider-tests.log`.
