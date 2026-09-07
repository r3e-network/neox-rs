# Neo X 全量审计 — 2026-09-07

## Overview

对本轮对 `neox` 分支 HEAD `256998be02`（相对 `origin/neox` ahead 3，含 `neox-v2.5.2`）做增量全量审计：在 2026-09-01 协议审计与 v2.5.2 十一项修复之上，对 dBFT、Anti-MEV/PKCS#7、DKG、网络/同步做缺陷优先复查。

**结论：未发现新的共识分叉级（P0）缺陷。** Canonical MainNet/T4 在默认 genesis 下仍以 legacy PKCS#7 与未打补丁的 Geth oracle 字节兼容。新发现集中在**校验器活性 / sidecar 可用性**（P2），不是区块有效性分叉。活体混合客户端与 DKG epoch 门禁仍开放，不能宣称「100% 协议等价已证明」。

### Baselines

| Component | Pin |
|---|---|
| Reth audited baseline | `3bc71d43f7101f772bbb4f9e15d3cdd58f60e958` |
| Neo X Geth oracle | `f0e236838bb334c7c0d29eeca33533ed0cfda254` (`bane-main`) |
| Neo X layer release | `neox-v2.5.2` |
| Prior full protocol audit | [2026-09-01-FULL-AUDIT.md](2026-09-01-FULL-AUDIT.md) |
| PKCS#7 Geth patch gate | [2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md](2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md) — CLOSED for checkout/apply |

### Scope

- Static defect review: `crates/neox/{antimev,chainspec,consensus,consensus-engine,evm,network,node}`
- Documented deliberate divergences in [docs/neox/README.md](../README.md)
- Post-`2026-09-01` / v2.5.2 remediations (ChangeView tally, duty journal, parent-state pool admission, PKCS#7 hardfork gate, reconstruction retry)
- Out of scope this round: fresh MainNet sync live run, mixed-client DKG epoch, full workspace Reth package suite on Windows MDBX

## API Reference — finding severity

| Severity | Meaning |
|---|---|
| P0 | Release blocker / consensus fork or critical security failure |
| P1 | Urgent defect; fix next |
| P2 | Ordinary defect; fix before validator production claim |
| P3 | Low-impact / API footgun / test gap worth closing |

## Design decisions checked

1. **PKCS#7** — `neoXPkcs7StrictBlock` optional; MainNet/T4 omit it → reconstruction uses `strict: false`, matching unpatched Geth. Strict mode is versioned and must not mix with legacy after activation.
2. **BLS infinity** — deliberate fail-stop stricter than Geth; pinned by tests; not a silent fork under honest validators.
3. **DKG receipt retry / ZK_VERSION** — deliberate fail-closed / retry-more divergences; liveness-only.
4. **Parent-state pool admission** — shared `StaticPoolAdmission` for proposal verify and reconstruction; closes the sequential-funding fork vs Geth staticPool.

## Remediation status (2026-09-07 follow-up)

| Finding | Status |
|---|---|
| P2 Anti-MEV transient retry wakeup | **Fixed** — `maintenance.tick` re-calls `anti_mev.schedule` so backoff deadlines wake without a new dBFT message |
| P2 Missed-notification sidecar archive | **Fixed** — reconcile path calls `sidecars.archive_canonical_range` against the provider tip window |
| P2 DKG `Checking` one-shot receipt | **Fixed** — `actions_with_preparation_limit` re-emits `CheckReceipt` while a task remains in `Checking` |
| P3 items | Two closed 2026-09-07 evening: `decrypt_and_validate` defaults to legacy PKCS#7; legacy padding matrix tests added. Descendant FCU budget remains open (non-blocking). |

## Findings (this round)

### [P2] Transient Anti-MEV reconstruction retries lack a backoff wakeup — FIXED

**Path:** `crates/neox/node/src/sync/anti_mev.rs`, `crates/neox/node/src/sync.rs` (maintenance arm)

After a transient `Provider` failure, `finish()` sets `retryable` and `retry_at`, then `handle_antimev_reconstruction` calls `schedule()` once. `begin()` correctly refuses while `Instant::now() < retry_at`, but previously nothing re-invoked `schedule()` when the deadline elapsed.

**Fix:** The 1s `maintenance.tick()` arm now calls `anti_mev.schedule` for the active round so due transient retries start without waiting for another dBFT event.

### [P2] Missed-notification maintenance skips sidecar archival — FIXED

**Path:** `crates/neox/node/src/sync.rs` (maintenance reconcile), `crates/neox/node/src/sync/sidecar.rs`

When the heartbeat detects a missed canonical notification, it reconciles head and reactivates dBFT. Commit/Reorg paths archive via `archive_chain`; the reconcile path previously did not.

**Fix:** After a successful reconcile, `archive_canonical_range` loads the tip lookback from the provider, archives pool sidecars when present, and peer-requests any missing blob blocks (capped lookback).

### [P2] DKG receipt checks are one-shot while state stays `Checking` — FIXED

**Path:** `crates/neox/node/src/dkg_executor.rs`

At `send_height + 3`, a task moves to `Checking` and emits `CheckReceipt`. While `Checking`, subsequent heartbeats previously emitted nothing, so a lost check left the task inert until phase expiry.

**Fix:** While a task remains in `Checking`, each `actions` poll re-emits `CheckReceipt` for the same transaction hash until `record_receipt` completes or the task expires.

### [P3] `decrypt_and_validate()` hardcodes strict mode — FIXED

**Path:** `crates/neox/node/src/antimev.rs` (public wrapper)

The convenience wrapper previously always passed `strict: true`. Production reconstruction correctly uses `decrypt_and_validate_with_mode` gated by chainspec.

**Fix:** The wrapper now defaults to legacy (`strict: false`) to match MainNet/T4 (no `neoXPkcs7StrictBlock`). Callers with a known height must still use `decrypt_and_validate_with_mode` + the chainspec gate.

### [P3] Legacy PKCS#7 acceptance not fully matrix-tested — FIXED

Strict rejection vectors were covered; legacy `decrypt_message_with_mode(..., false)` acceptance for zero/oversized/inconsistent padding is now asserted in `geth_negative_vectors::legacy_mode_accepts_reference_client_padding_matrix`.

### [P3] Descendant backfill FCU per-anchor budget exhaustion

**Path:** `crates/neox/node/src/sync.rs` (~120 attempts/anchor)

If FCU never validates an announced hash, the node stops requesting that target until the canonical anchor moves. Bounded self-heal; residual catch-up risk under sticky invalid announcements.

## Closed since prior audits (carry-forward)

| Item | Status |
|---|---|
| ChangeView cumulative tally / future-view (nspcc-dbft aligned) | Closed in v2.5.2 |
| Durable signing duty journal | Closed in v2.5.2 |
| Parent-state reconstruction + proposal pool admission | Closed in v2.5.2 |
| PKCS#7 versioned hardfork + Geth patch canonical apply gate | Closed (activation still governance-open) |
| withdrawals_root Shanghai gating, Beacon TTL, RPC Policy sim, FCU timeout, propagated-block backfill | Closed (2026-09-01 era) |
| CipherText.Verify never called in Geth | Documented; liveness stall, not state fork |
| PKCS#7 reachability fork | Mitigated by legacy default + coordinated `Pkcs7Strict` gate |
| P2 Anti-MEV transient retry wakeup | Fixed 2026-09-07 |
| P2 Missed-notification sidecar archive | Fixed 2026-09-07 |
| P2 DKG `Checking` one-shot receipt | Fixed 2026-09-07 |

## Open release gates (unchanged class)

1. Mixed-client successful DKG epoch (seven-message verifier share submission).
2. Fresh-datadir MainNet sync to canonical hash + restart equality.
3. Controlled reorg/crash/unwind across persistence; validator fault injection after NX remediations.
4. BEACON/2 + dBFT/0 mixed-peer live interoperability beyond unit/RLP tests.
5. Coordinated PKCS#7 strict activation with reference-client patch deployment.
6. On-chain KeyManagement PVSS strength vs Rust `verify()` (external contract; not in-repo).
7. Reth tip merge rehearsal: Windows MDBX `os error 1224` on unmodified upstream persistence test — do not bump pinned baseline until gates pass.

## Test coverage (documented expectations)

| Suite / gate | Expected outcome |
|---|---|
| Neo X crates (v2.5.2 release notes) | 418 passed |
| PKCS#7 strict matrix (Rust + Geth patch) | Closed |
| Transient reconstruction backoff wakeup | **Covered** — maintenance `schedule` + unit test for post-deadline `begin` |
| Maintenance reconcile + sidecar archive | **Covered** — `archive_canonical_range` on missed-notification path |
| DKG `Checking` without `record_receipt` | **Covered** — re-emit `CheckReceipt` asserted in executor unit test |
| `cargo deny check advisories` on this host | Tool panic in `krates` (serde-bincode-compat); not treated as advisory evidence |

## Usage examples — audit workflow

```text
# Re-run Neo X authoritative suite (Windows: MSVC wrapper first)
source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh
cargo test -p reth-neox-node -p reth-neox-antimev -p reth-neox-network \
  -p reth-neox-consensus -p reth-neox-consensus-engine -p reth-neox-evm \
  -p reth-neox-chainspec -p neox-rs

# PKCS#7 oracle patch apply (read-only oracle policy)
# See 2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md
```

## Verdict

| Claim | Allowed? |
|---|---|
| Independent non-validator full node / mixed block production operational | Yes (prior evidence) |
| Validator mode production-qualified | **No** — experimental; open DKG/fault/live gates remain |
| 100% Geth protocol equivalence proven | **No** — static/oracle-aligned; live gates incomplete |
| Safe to activate `neoXPkcs7StrictBlock` alone | **No** — requires coordinated Geth strict patch |
| 2026-09-07 P2 liveness trio remediated | **Yes** — wakeup / sidecar archive / DKG Checking re-emit |
