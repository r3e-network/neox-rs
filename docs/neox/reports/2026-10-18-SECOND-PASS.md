# Neo X Rust full node — second review pass (2026-10-18)

Follow-up to [`2026-10-18-FULL-REVIEW.md`](2026-10-18-FULL-REVIEW.md). This pass re-reviewed the
committed fixes, added cross-fork live differential coverage, and looked for defects introduced or
missed by the first pass.

## Verdict

**No new P0/P1 defect.** All eight fixes from the first pass hold, including the Windows
static-file recovery and the total-difficulty checkpoint. One P3 serialization polish was added,
and the remaining open items are validator qualification / governance, not full-node correctness.

Baseline: `neox` HEAD `808574c5df` (`f51b03555a` + serialization polish).

## Changes verified

| Commit | Change |
|---|---|
| `bde595c2e4` | Restore oracle genesis, optional `neoX*Block` fields, pool fee-cap parity, baseline provenance |
| `f51b03555a` | Windows static-file mapping recovery (F9), TD checkpoint (F6), AMEV-gated `eth_envelopeFee` (F7) |
| `808574c5df` | Omitted unscheduled `neoX*Block` fields serialize back as absent (P3 polish) |

## Gates

- **Windows**: 425 Neo X tests passed / 0 failed; `reth-provider` **233/233**; `reth-static-file`
  2/2; nightly rustfmt check clean; strict clippy clean on the changed crates.
- **Linux cross-check** (WSL, `x86_64-unknown-linux-gnu`): `cargo check -p reth-provider` and
  `cargo check -p reth-neox-node -p neox-rs` both pass, covering the `#[cfg(windows)]` no-op path.
- **Live head differential**: 40 checks, 0 mismatches, skew 0 at `0x7aa964` (block 8,038,756),
  re-run after the serialization commit at `0x7aab16` (block 8,039,190) with the same result.

## Cross-fork live differential

The archive datadir was queried at blocks spanning every Neo X/execution fork. All checks passed
with zero mismatches:

| Height | Era | Checks | Txs compared |
|---|---|---|---|
| 2,999,991 | pre-DKG | 71 | 1 |
| 3,650,082 | DKG active, pre-AMEV | 71 | 1 |
| 3,800,003 | post-AMEV / EthSig | 71 | 1 |
| 4,720,750 | pre-Cancun/Prague | 105 | 2 |
| 4,720,848 | post-Cancun/Prague | 71 | 1 |
| 6,949,844 | pre-Osaka | 71 | 1 |
| 6,949,850 | post-Osaka | 71 | 1 |
| 8,000,012 | recent | 71 | 1 |

Checks include block fields, system-contract code, Policy storage, and complete transaction and
receipt payloads where transactions exist. Artifact:
`outputs/review-fork-differential-20261018.json`.

## F6/F9 robustness exercised live

- **Corrupt checkpoint**: overwrote `neox-total-difficulty.json` with invalid JSON, restarted. The
  node ignored it, performed the full 33.8 s scan, rewrote a valid checkpoint, and served RPC. The
  next restart reused the checkpoint and reached P2P in **0.366 s**.
- **Partial state trie**: a hard kill during persistence left an inconsistency at block 8,038,975.
  The fixed binary unwound it, restored RPC, caught up, and followed live dBFT blocks. This
  independently reproduces the F9 fix on the final tree.

## Findings

### P3 — omitted fork fields serialized as a sentinel — **fixed in `808574c5df`**

`NeoXGenesisConfig` correctly deserializes `neoX*Block` omissions to "never active", but
serialization emitted `18446744073709551615`. The fields are now skipped when unscheduled, and a
round-trip test covers both directions.

### P3 — `debug_traceBlock*` chain-config overrides — **open, tracing-only**

Geth's tracing API accepts a `ChainConfig` override (including the Neo X fork fields) for
`debug_traceBlock*`; Reth's `GethDebugTracingOptions` exposes state/block overrides rather than a
chain-config override. This does not affect consensus, block import, or normal RPC; it only means a
tracer cannot force a hypothetical Neo X fork through that Geth-specific parameter. Not fixed in
this pass.

## Remaining risks

Unchanged from the first report: validator-mode qualification (mixed-client DKG on current HEAD,
prover delay, transaction replacement, controlled reorg, fault injection), PKCS#7 strict activation
governance, the deliberate ciphertext-admission liveness divergence, and independent review of the
deployed `KeyManagement` Solidity. Windows still requires `--ipcdisable`; run production full nodes
on Linux.
