# Upstream sync — Reth 2.7.0 + Neo X Geth `9dec1dc364` (2026-10-18)

Follow-up to the [full review](2026-10-18-FULL-REVIEW.md) and
[second pass](2026-10-18-SECOND-PASS.md). Merge commit: `c3aade484c`.

## Verdict

The fork now tracks Reth upstream main `8868180a0e72` (`2.7.0`, 185 commits after the previous
`4dd0cc021a` baseline) and the current Neo X Geth `bane-main` tip
`9dec1dc364d3db117bd87eb3613cc4de970912e2` (`0.7.0-dev`). The merged client opens the existing
8.03M-block archive datadir without a migration, follows MainNet live, and remains clean on the
head and cross-fork execution differentials. No new consensus defect was introduced or found.

## Reth 2.7.0

- 416 files changed, 185 upstream commits; workspace version `2.7.0`, revm `43.0.3`, alloy-evm
  `0.39`.
- Conflicts were limited to five files:
  - `AGENTS.md`: kept the Neo X fork's host/build guidance.
  - `release-reproducible.yml`: took upstream's repository-agnostic guard.
  - Ethereum e2e `forkchoice.rs`: took upstream's `E2ETestSetupExt` test rewrite.
  - `payload/basic`: took upstream's move of `CancelOnDrop` to `reth-tasks`.
  - RPC precompile map: kept the fork's generic `PrecompileSet` helper (needed by
    `NeoXPrecompiles`) and removed dead Amsterdam builder constants that upstream deleted.
- Neo X adaptation: `StateProviderDatabase` now needs `into_evm_state_provider()`; applied at the
  four call sites in `producer.rs`, `proposal.rs`, `reconstruction.rs`, and `dkg_call.rs`.
- No Neo X engine, RPC, or storage behavior was dropped by the merge; the Windows static-file
  cache fix and TD checkpoint are retained.

## Neo X Geth `9dec1dc364`

The oracle moved from `f0e236838b` to `9dec1dc364` (715 commits: four first-parent Neo X fork
merges plus upstream mainline).

- **Genesis**: upstream `8fde8c492f` removed `blobSchedule.osaka` from both genesis files, aligning
  with Reth. The vendored files were replaced with the exact oracle bytes:
  - MainNet `5226a767c0f608cdb3e56a336225890703baad4dfcdcb6518ba965f59fbfc8b1`
  - T4 `538dc0fa25402227591034af314c1f448e4432a16c9aa0bccbeb8e114efa1aa1`
  - Genesis **block** hashes are unchanged (`2ee57478…` / `221f7d0a…`), and the node resolves the
    same Osaka blob parameters from Reth/alloy defaults.
- **`fix-gas-used` (`9dec1dc364`)**: Geth now sets `finalGASUsed` from `gasPool.Used()` instead of
  a stale local counter. The Rust client already reports cumulative successful transaction gas
  (`cumulative_tx_gas_used`), so no change was required; the live execution differential covers the
  class of blocks affected.
- **BAL / withdrawals (`72579cf`, `9c4410e`, `07ad807`)**: Amsterdam-gated. `amsterdamTime` is absent
  on both Neo X networks, so these paths remain dormant. Rust's existing BAL support is unchanged.
- **Proposal waiting (`cc7af69`)**: a Geth validator/syncing liveness tweak; no wire-format or
  consensus change. The Rust sync task is already asynchronous and does not hold the proposal lock
  while syncing.
- **Local PKCS#7 patch**: the fork's oracle checkout is still based on the previous `f0e236838b`
  tree with the uncommitted strict-PKCS#7 patch; `9dec1dc364` was fetched and verified from
  `origin/bane-main`, and the `antimev/`/`crypto/tpke/` files used by the vectors are unchanged
  between the two commits. The divergence and the G9 activation gate remain as documented in the
  full review.

## Verification

| Gate | Result |
|---|---|
| Neo X tests (Windows) | **425 passed, 0 failed** |
| `reth-provider --lib` (Windows) | **239 passed, 0 failed** |
| `reth-static-file --lib` | **2 passed, 0 failed** |
| `cargo check -p reth-node-ethereum --tests` | pass |
| Linux `cargo check` (WSL: provider, node, binary) | pass |
| Linux `cargo check --workspace --all-targets --exclude reth` | pass (all crates, examples, test targets) |
| `reth-engine-primitives --lib` / `reth-engine-tree --lib` | 17 / 211 passed |
| nightly rustfmt `--check` | clean |
| strict clippy (`reth-provider`, Neo X crates, `neox-rs`, engine/node crates) | clean |
| existing archive datadir (8.03M blocks) | opens and serves RPC without migration |
| live MainNet head differential | **40 checks, 0 mismatches, skew 0** at `0x7aac97`; re-run after the genesis swap at `0x7aacc8` and with the final binary at `0x7aad5d` |
| eight-block cross-fork differential (final tree) | **0 mismatches** (71–105 checks per block, pre-DKG → Osaka → recent) |

Artifacts: `outputs/review-fork-differential-reth27-final.json`,
`outputs/merge-tests-1.log`, `outputs/merge-provider-tests.log`, `outputs/merge-clippy.log`,
`outputs/workspace-check-linux-no-reth.log`, `outputs/review-node-merge*.log`.

## Remaining Reth fork delta

After removing duplicated upstream tests and the unused persistence-threshold helper, the delta
outside `crates/neox` and `bin/neox-rs` is **20 files, ~423 insertions**. The categories are:

1. **Neo X precompile bridge** — `crates/evm/evm` (`PrecompileSet`), the engine prewarm/validator
   imports, and the RPC config/simulate helpers. Neo X's `NeoXPrecompiles` is a custom
   `PrecompileProvider`; upstream's concrete `PrecompilesMap` bound cannot express it. This is the
   largest generic delta and a candidate for an upstream PR.
2. **Windows/cross-platform** — static-file changeset sidecar offsets, `fs-util` directory fsync,
   CLI segmented-download `FileExt`, mdbx clippy cast, nippy-jar test mapping drop, the Windows
   persistence test split, and the e2e random-byte type annotation.
3. **Recovery/robustness** — F9 `clear_cached_readers` plus its builder hook. The TD checkpoint
   (F6) lives entirely in `crates/neox`.
4. **Build/lint configuration** — Neo X workspace members/dependencies, `gmp` off by default for
   MSVC, and the `missing_const_for_fn` lint allow required by clippy 1.95 on upstream code.

## Remaining

- Amsterdam/BAL and EIP-8282 paths stay dormant until a network schedules `amsterdamTime`; the
  merged code includes upstream's implementations behind those gates.
- The tracing-only `debug_traceBlock*` chain-config override gap and the validator qualification
  gates from the full review are unchanged.
- The Geth oracle checkout's strict-PKCS#7 patch is local, not part of `9dec1dc364`; G9 activation
  remains a governance action.
- The 2.7 binary opens and advances the existing 2.5-era datadir without a migration, but a
  **downgrade** of that datadir to the 2.5 binary was not exercised; take a backup before a
  production upgrade.
- Windows still requires `--ipcdisable`; production full nodes should run on Linux.
