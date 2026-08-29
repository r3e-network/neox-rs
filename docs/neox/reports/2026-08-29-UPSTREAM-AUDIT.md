# Upstream audit — Reth and Neo X Geth — 2026-08-29

Scope: a drift audit of both pinned oracles against the baselines recorded in
[`source-baseline.toml`](../source-baseline.toml) after the [2026-08-28 sync](2026-08-28-UPSTREAM-SYNC.md).
Method as before: `paradigmxyz/reth` (`main`) and `bane-labs/go-ethereum` (`bane-main`) were fetched
read-only into throwaway remotes. Nothing was pushed; the remotes were removed afterwards.

## Headline

| | |
|---|---|
| Neo X Geth oracle | **zero drift** — tip is still `f0e236838b`. Genesis blobs re-hashed at the tip: both SHA-256 values match the pin exactly. |
| Reth drift | **10 commits** (`66a08aba22` → `3bc71d43f7`, all landed 2026-08-28 evening UTC). |
| `revm` / alloy | **unchanged** — no dependency bumps in the range; the workspace stays on `revm 42.0.1`. The `crates/neox/evm` revm-internals watch surface is untouched. |
| Merge surface | **zero overlap** with the 7 Neo X-patched upstream files. Only 23 files changed across 9 areas; the root `Cargo.toml` (members and workspace deps) is untouched. |
| Merge rehearsal | `git merge-tree --write-tree neox reth-audit/main` — **clean, exit 0, single tree** `3cb2d57c5b`. |
| One review item | #26861 changes local/private transaction pool admission (details in §2) — flows into `NeoXTransactionValidator` at the next sync and should be a deliberate acceptance, not an accident. |
| Result | Low-risk drift. Sync recommended; the pool-fee item is the only decision to make first. |

## 1. The 10 Reth commits

| commit | subject | relevance to `neox` |
|---|---|---|
| `692fc6999c` | feat(overlay): cache execution overlays in manager (#26834) | Upstream-internal. `crates/neox` references none of the overlay APIs. |
| `7f23df7634` | feat(overlay): build execution overlays (#26838) | Same; the bulk of the new `reth-storage-overlay` code (7 files). |
| `74ce7f1b2b` | fix(txpool): enforce minimum priority fee for local transactions (#26861) | **Behavior change — see §2.** |
| `8215b28f42` | feat(overlay): add overlay state providers (#26862) | Internal; rewires `reth-provider` type aliases (`HistoricalStateRangeProvider`) the fork does not name. |
| `2ac1b59750` | fix(overlay): run computations on dedicated workers (#26871) | Internal. |
| `f55ba955cd` | docs(tasks): document worker access reentrancy (#26873) | Docs only. |
| `fa9635290b` | fix(rpc): track batch entries in a dedicated call counter (#26866) | Metrics bookkeeping in `rpc-builder`; no API change to the custom Neo X methods. |
| `96512668ff` | fix(overlay): preserve storage wipes in execution overlays (#26872) | Internal (state-overlay correctness). |
| `7bd50eaa4d` | feat(downloader): select accounts with storage for snap storage requests (#26852) | SNAP sync efficiency for the full-node path; no overlap with fork code. |
| `3bc71d43f7` | test: post-Cancun selfdestruct e2e suite (#26865) | Tests + `e2e-test-utils` only. |

Changed-file concentration: `crates/storage/storage-overlay` (7), `crates/ethereum/node` (4,
feature wiring), `crates/transaction-pool` (2), `crates/storage/provider` (2), `crates/net/downloaders` (2),
`crates/e2e-test-utils` (2), plus `tasks`, `rpc-builder`, and `Cargo.lock`.

## 2. The one review item: #26861 local minimum priority fee

Upstream tightened the pool's `minimum_priority_fee` check from external-only to **all origins**:

```rust
// before: if !is_local && transaction.is_dynamic_fee() && ...
// after:  if transaction.is_dynamic_fee() && ...
```

with tests now asserting rejection for `External`, `Local`, and `Private` alike.

This matters here because `NeoXTransactionValidator` (`crates/neox/node/src/pool.rs`) delegates
stateless validation to the wrapped `EthTransactionValidator`, so the change flows in unmodified
at the next sync. Consequences to weigh:

- **DKG validator-runtime transactions** are local pool transactions. The runtime already uses
  "protocol-valid fee bumps" (the fork's replacement path tests use ≥20 gwei priority), and the
  fork's `validate_policy` already applies the on-chain `POLICY_MIN_GAS_TIP_CAP_SLOT` floor to
  *every* origin — so under default configuration (pool minimum 1 gwei) nothing practical changes.
  But an operator who raises `--txpool.priority` above the Policy floor would newly block their own
  validator's DKG replacements, where pre-sync the pool let them through.
- **`--txpool.amevcache` secret transactions** are validated with `Private` origin; they now also
  need to clear the configured pool minimum, where before `Private` counted as local and was exempt.

Neither path is consensus-visible. The decision for the sync: accept upstream's stricter behavior
(simpler, stays merge-clean going forward) or preserve the local/private exemption with a
one-line origin check in `NeoXTransactionValidator` plus a regression test. Recommend accepting
upstream and documenting the operator-facing note, consistent with oracle-parity defaults —
Geth's own txpool applies the minimum to local transactions the same way.

## 3. Explicit non-claims

- This audit ran compile-free static analysis plus `merge-tree` only; it does not build or test
  the merged tree. Gate results belong to the sync report that lands it.
- No baseline change: `source-baseline.toml` still pins `66a08aba22` / `f0e236838b`, which remain
  the audited-and-synced state. Advancement happens with the next sync commit.
- Genesis integrity is asserted at the unchanged oracle tip (`f0e236838b`); both hashes match the
  pin (`bdb5f93f…eac8fa5`, `2b49c4d6…734a1ae`).
