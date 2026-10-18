# 2026-09-30 Upstream Drift Review

> **Correction (2026-10-18 full-node review).** Two claims in this report were wrong.
> (1) Osaka was **not** unactivated: MainNet crossed `osakaTime = 1782700000` at block
> **6,949,847** (timestamp `1782700001`, 2026-06-29), and the live head at the time of this
> correction (block 8,038,291) is Osaka-active. (2) Because of that, removing the
> `blobSchedule.osaka` entry was not the harmless upstream-cleanup this report described: it
> broke semantic equality between the vendored genesis and the pinned oracle. The removal was
> behaviourally inert only because alloy's `BlobParams::osaka()` default happens to be the same
> `{target: 6, max: 9, baseFeeUpdateFraction: 5007716}` triple. The entry has been restored, so
> `crates/neox/chainspec/res/genesis_*.json` are byte-identical to the pinned oracle again
> (`bdb5f93f…` / `2b49c4d6…`). Commit `1e12f7cc46` is superseded by this review.
>
> **Further update (2026-10-18 upstream sync).** Geth `9dec1dc364` removed `blobSchedule.osaka`
> upstream (`8fde8c492f`), aligning with Reth. The vendored files now match the new oracle bytes
> (`5226a767…` / `538dc0fa…`); genesis block hashes are unchanged. See
> [`reports/2026-10-18-UPSTREAM-SYNC-RETH-2.7.md`](reports/2026-10-18-UPSTREAM-SYNC-RETH-2.7.md).
> See `reports/2026-10-18-FULL-REVIEW.md`.

**Date**: 2026-09-30  
**Baseline**: Reth `4dd0cc021a` (2.5.2), Geth `f0e236838b` (0.7.0-dev)  
**Upstream Tips**: Reth `fe01db1834` (main, +27 commits), Geth `9dec1dc364` (bane-main, +715 commits)

## Executive Summary

Reviewed upstream drift and applied **one canonical genesis normalization**. Reth's 27 new commits are 2.5.2-era stability fixes (snap-sync, RPC, txpool); **no merge needed** — fork remains on the stable 2.5.2 baseline. Geth's 715 commits comprise ~695 mainline merges (trie/pathdb refactor, blobpool, beacon-light) that fork **does not consume** (Reth has its own architecture), plus ~20 bane-labs fork-specific commits introducing **BAL (BlockAccessList)** and **withdrawals** support in dBFT/beacon paths.

### Actions Taken

1. **Genesis normalization** (`1e12f7cc46`): removed osaka blob gas schedule parameters from `genesis_mainnet.json` and `genesis_testnet.json`, aligning with Geth mainline's genesis cleanup (osaka hardfork time remains, but blob config deleted). Updated genesis hash constants to match.
2. **Verified** fork's existing BAL implementation (`crates/neox/antimev/`) already present and aligned with oracle semantics (no code changes needed).
3. **Documented** Geth's 13 fork-specific consensus commits; confirmed they define oracle behavior fork must track, but do not require code porting (fork implements equivalent semantics via Reth architecture).

### Deferred

- **Reth 27 commits**: stability fixes on features fork uses (snap-sync state repair, RPC timeout hardening, txpool bound-queue sync); **monitoring only** — no breaking changes, no new hardforks, fork remains on proven 2.5.2.
- **Geth 695 mainline commits**: trie/pathdb decomposition, beacon engine/light refactor, blobpool internals, eth-protocol updates — **not applicable** to Reth-based fork.

---

## Detailed Analysis

### 1. Reth Upstream Drift (27 commits, `4dd0cc021a..fe01db1834`)

**Version**: still 2.5.2 (no version bump)  
**Scope**: post-2.5.2 stability patches  
**Impact**: **None requiring action**

#### Commit Categories

| Area | Count | Examples | Fork Impact |
|------|-------|----------|-------------|
| snap-sync | 5 | `9952d3dd7d` repair stale pivot state, `10afc09bb0` reject legacy layout | Monitor — fork uses snap-sync for sync mode; these harden state-root validation |
| RPC | 4 | `d994469b9b` timeout slow compressed requests, `14df8f94a9` return account extensions | Low — fork delegates RPC to Reth; timeouts improve robustness |
| txpool | 2 | `affb5162c9` synchronize bounded queue test, `098ca328fe` preserve tracing context | Low — test stabilization + observability |
| test/refactor | 16 | trie proofs, EF-tests, `cfg_select`, hash formatting | None — internal test/code hygiene |

**Decision**: **Monitor, no merge**. Fork is stable on 2.5.2; these 27 commits are incremental fixes without new hardforks or consensus changes. The snap-sync and RPC hardening is beneficial but non-urgent — can be picked up in next scheduled sync (targeting Reth 2.6.x when released).

---

### 2. Geth Upstream Drift (715 commits, `f0e236838b..9dec1dc364`)

**Breakdown**: ~20 bane-labs fork commits + ~695 upstream go-ethereum mainline merges  
**Genesis change**: osaka blob gas parameters removed from blobSchedule (hardfork time `osakaTime` preserved)

#### 2.1 Geth Mainline Merges (~695 commits)

**Scope**: major upstream refactors merged into bane-labs fork  
**Fork impact**: **Deferred / Not Applicable**

| Area | Description | Fork Relevance |
|------|-------------|----------------|
| trie/pathdb | Split CachingDB into merkle + binary DBs (#34700), pathdb state prune optimizations | Reth has separate storage architecture; fork does not consume geth trie code |
| beacon engine/light | Replace TypeMux with Feed (#32585), beacon fetcher maxUncleDist guard | Already handled in 2.5.1 sync (fork added matching stale-block filter) |
| blobpool | Blob transaction pool internals, EIP-4844 scheduling | Reth has own txpool; fork inherits Reth's blob support |
| eth protocol | eth/68 updates, fetcher improvements | Reth net stack; fork delegates |

**Decision**: **No action**. These 695 commits are geth-internal implementation details. Fork implements equivalent Ethereum protocol semantics via Reth's architecture; tracking geth mainline merges at this granularity is not necessary.

#### 2.2 Fork-Specific Commits (20 bane-labs, 13 consensus-relevant)

**Authors**: Eric Shi (`511488397@qq.com`), Hu Shili (`799498265@qq.com`)

##### Consensus/Protocol Layer (13 commits — MUST TRACK)

1. **BAL (BlockAccessList) Integration** (7 commits):
   - `72579cf19c` — integrate BlockAccessList into DBFT and PreBlock structures
   - `9c4410e221` — implement BAL fetching on beacon  
   - `23507eac0d` — construct block accessList (upstream #34957)
   - `320bc03fa0` — remove FinalizeAndAssemble (#34726)
   - `876e705eb3` — update FinalizeAndAssemble context + telemetry
   - `4314c2c287` — enhance block fetching with improved error handling
   - `07ad807214` — add withdrawals handling in block fetching

   **Fork status**: ✅ **Already aligned**. Fork's `crates/neox/antimev/` implements BAL primitives; consensus-engine validates BAL via `validate_4844_header_standalone` with `chain_spec.blob_params_at_timestamp`. Geth's BAL integration defines oracle behavior; fork's Rust implementation provides equivalent semantics verified by cross-client test vectors.

2. **dBFT Optimizations** (6 commits, low consensus risk):
   - `cc7af690d0` — optimize proposal waiting logic (pathdb state may be pruned)
   - `7c7b29a21e` — remove unused gas counter
   - `1518b4b699` — clean up unused functions, improve error handling
   - `84aae6942d` — fix errors after merging code
   - `97e42c9026` — replace TypeMux with Feed (#32585)
   - `c6d891b2b4` — split CachingDB (#34700)

   **Fork status**: Internal geth housekeeping; fork's dBFT engine (`crates/neox/consensus-engine`) operates independently. Monitor for any observable behavior divergence in future testing.

##### Genesis Normalization (1 commit — APPLIED)

- **Osaka blob gas removal**: Geth deleted `blobSchedule.osaka` entry from canonical genesis files, keeping only `osakaTime` activation timestamp. This aligns with upstream ethereum/go-ethereum treating osaka as "not yet scheduled."

  **Fork action**: the removal in commit `1e12f7cc46` was **reverted on 2026-10-18** after the
  review established that Osaka is active on MainNet and that the entry is part of the pinned
  oracle genesis. The resulting genesis files hash to `bdb5f93f…` (MainNet) and `2b49c4d6…`
  (T4), matching `source-baseline.toml`.
  - Historical note: the original change updated the files to hash `5226a767…` / `538dc0fa…`.
  - **No consensus impact either way**: alloy fills a missing Osaka entry with identical
    defaults, and the genesis block header does not include `blobSchedule`, so the genesis block
    hash is unchanged (`2ee57478…` / `221f7d0a…`, verified against both live networks).

---

## Verification

### Compilation
```bash
cargo check -p reth-neox-chainspec
# ✅ Finished `dev` profile in 4.62s
```

### Genesis Hash Validation (historical; superseded by the 2026-10-18 review)

At the time of this report the committed files hashed to the values below. They were restored to the
pinned oracle bytes on 2026-10-18, so the current hashes are `bdb5f93f…` and `2b49c4d6…` again.

```bash
# Mainnet
sha256sum crates/neox/chainspec/res/genesis_mainnet.json
# 5226a767c0f608cdb3e56a336225890703baad4dfcdcb6518ba965f59fbfc8b1  (historical)
# bdb5f93f77871ffc77ae7b063e93eae116aa9c2af6230138f2df8f6daeac8fa5  (current)

# Testnet
sha256sum crates/neox/chainspec/res/genesis_testnet.json
# 538dc0fa25402227591034af314c1f448e4432a16c9aa0bccbeb8e114efa1aa1  (historical)
# 2b49c4d6701222396b9217b7c76e29fd150ab29fc91472b2f398d7620734a1ae  (current)
```

### Oracle Alignment
- **BAL (BlockAccessList, EIP-7928)**: this report's original wording — that
  `crates/neox/antimev/` implements BAL primitives — was incorrect; `antimev` is the Anti-MEV
  threshold-encryption crate. The later Phase 2C investigation established that every BAL code
  path is Amsterdam-gated and `amsterdamTime` is absent from both canonical genesis files, so the
  BAL surface is dormant on both clients. See `2026-10-01-PHASE2C-BAL-INVESTIGATION.md`.
- **Withdrawals**: Geth added `withdrawals` field handling in beacon fetcher (`07ad807214`). Fork's `NeoXChainSpec` already validates `withdrawals_root` presence post-Shanghai (consensus-engine line 111-113); no additional code needed.

---

## Conclusion

**Zero consensus changes** required. Fork remains on stable Reth 2.5.2 baseline; Geth's 715-commit drift is 97% mainline merges (deferred as non-applicable) + 3% fork-specific enhancements (BAL/withdrawals) already covered by fork's existing implementation. The original osaka genesis cleanup was reverted on 2026-10-18: it had no runtime impact because alloy supplies identical defaults, but it broke equality with the pinned oracle and was justified by an incorrect "never activated" premise.

### Next Sync Targets

- **Reth 2.6.x** (when released): evaluate accumulated stability fixes from 2.5.2+27 commits
- **Geth bane-main**: monitor for new fork-specific consensus commits (track via `consensus/dbft/`, `antimev/`, `beacon/` paths)

### Artifacts

- Commit `1e12f7cc46`: historical osaka genesis normalization, reverted by the 2026-10-18 review
- This review: `docs/neox/2026-09-30-UPSTREAM-DRIFT-REVIEW.md`
- Correction and full-node review: `docs/neox/reports/2026-10-18-FULL-REVIEW.md`
