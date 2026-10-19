# Neo X Rust full-node review — 2026-10-18

## Verdict

The Neo X-specific implementation in `crates/neox` and `bin/neox-rs` is a faithful,
consensus-safe port of the pinned Neo X Geth oracle (`f0e236838b` at review time, now
`9dec1dc364`, `0.7.0-dev`) for every
execution and dBFT path exercised by MainNet. This review found **no P0 or P1 defect** and no
reachable state divergence. It found and fixed eight defects (four P2, four P3), including the
genesis/baseline drift, two pool/RPC parity gaps, a 34-second restart scan, and the Windows
crash-recovery failure, and documented one Windows startup requirement (F8). A live MainNet
revalidation at this tree caught up 366,744 blocks to the reference head, passed the 40-check head
differential and a 105-check execution differential, and continued following live dBFT blocks after
a restart.

Validator production qualification remains **open** by design: the code is not a stable validator
release, and the DKG/fault-injection gates listed under *Remaining risks* still apply.

> **Second-pass verification** (cross-fork live differential, Linux cross-check, and regression
> re-validation of F6/F9) is recorded in
> [`2026-10-18-SECOND-PASS.md`](2026-10-18-SECOND-PASS.md). The later Reth 2.7.0 / Neo X Geth
> `9dec1dc364` sync is recorded in
> [`2026-10-18-UPSTREAM-SYNC-RETH-2.7.md`](2026-10-18-UPSTREAM-SYNC-RETH-2.7.md).

> **Validator DKG lifecycle (2026-10-19).** The G8 round 1 → 2 transition now passes after
> `daadb7fdeb` and `8c7fc1a85f`: all nine clients report the same non-empty 128-byte aggregate
> commitment and the formal `v2c` gate passes **1,401 blocks** with 0 reorgs and 0 RPC errors.
> Lifecycle fault injection remains before validator release. See
> [`2026-10-19-VALIDATOR-DKG-STALL.md`](2026-10-19-VALIDATOR-DKG-STALL.md).

## Scope and method

Reviewed at `neox` HEAD `3b4e72bc04`:

- `crates/neox/{chainspec,consensus,consensus-engine,evm,network,antimev,node}`
- `bin/neox-rs` CLI, custom RPC, DKG runtime, migration utility
- The Reth fork changes that the Neo X layer depends on (engine tree, RPC gas cap, trie reuse)
- `docs/neox/{README.md,source-baseline.toml,CHANGELOG.md}` and the recent audit reports
- The pinned oracle tree at `D:\Git\neox-geth` (`f0e236838b` during this review; the baseline was
  later synced to `9dec1dc364`, see the upstream-sync report)

Methods:

1. **Line-level semantic comparison** against Geth `consensus/dbft`, `core/state_processor.go`,
   `core/state_transition.go`, `core/vm/evm.go`, `core/systemcontracts`, `antimev/`, `crypto/tpke`,
   `eth/protocols/{beacon,dbft}`, and the gas-price/txpool policy paths.
2. **Offline gates**: build, full Neo X package test suite, nightly rustfmt, targeted unit tests.
3. **Live MainNet validation** on a copy of the existing archive datadir, plus RPC differential
   checks against the public reference endpoint.
4. **Provenance audit** of every commit ID and genesis fingerprint in the compatibility baseline.

## Baseline verification

### Genesis files

The vendored genesis files are synced to the current oracle (`9dec1dc364`):

| File | SHA-256 | Semantics |
|---|---|---|
| `crates/neox/chainspec/res/genesis_mainnet.json` | `5226a767c0f608cdb3e56a336225890703baad4dfcdcb6518ba965f59fbfc8b1` | byte-identical to `9dec1dc364:config/genesis_mainnet.json` |
| `crates/neox/chainspec/res/genesis_testnet.json` | `538dc0fa25402227591034af314c1f448e4432a16c9aa0bccbeb8e114efa1aa1` | byte-identical to `9dec1dc364:config/genesis_testnet.json` |

The genesis **block** hashes in `crates/neox/chainspec/src/lib.rs` were checked against the live
networks, not just the local computation:

- MainNet `eth_getBlockByNumber(0x0)`: `0x2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7`
- T4 `eth_getBlockByNumber(0x0)`: `0x221f7d0a47dd80fe10f476625d62303947c9cd336113e119c64d919f0e9beb71`

### Fork schedule

MainNet and T4 schedule `shanghaiTime = 0`, Cancun/Prague at `1763000000` / `1761600000`, and
Osaka at `1782700000` / `1781500000`. **Osaka is active**, not future: MainNet crossed the Osaka
timestamp at block **6,949,847** (timestamp `1782700001`, 2026-06-29). The current oracle omits an
explicit `blobSchedule.osaka` entry (upstream `8fde8c492f`, aligned with Reth); the node resolves the
same `(target 6, max 9, fraction 5007716)` parameters from Reth/alloy's Osaka defaults, so genesis
block hashes and runtime behavior are unchanged. `amsterdamTime` is absent, so every Amsterdam/BAL
code path is dormant on both clients.

### Commit provenance

The previous baseline contained commit IDs that do not exist. Verified replacements:

| Recorded | Actual | Notes |
|---|---|---|
| Reth tip `8868180a0e7c1b134f0e83af19a77c573a4dcf75` | `8868180a0e72df4c32f514b4d4666203560c2be8` | `github.com/paradigmxyz/reth` |
| Geth tip `9dec1dc3644c91cf8291e30f7f30c1cdd0f10cb7` | `9dec1dc364d3db117bd87eb3613cc4de970912e2` | `github.com/bane-labs/go-ethereum` |
| Phase 2A `a120f00d47982bb58e5f8396d4d8e4eb68ddd4cc` | `a120f00d47e43427816e2fe7e38229fabbb2db87` | local cherry-pick `54959912bc` |
| Phase 2A `444e867155982c6c7d1f4c8a2f1e3b8e4d2f5a6b` | `444e867155c2a7a4c028e479ca7201b0b6871579` | local cherry-pick `785080bf93` |
| Phase 2A `2833f74402847c8f5e6a1d2e3f4b5c6d7e8f9a0b` | `2833f744022fe0eb6e7223ce0dbfe739ff1af6c7` | local cherry-pick `5d3574ed1d` |

Phase 1 hashes (`b68f6fa5…`, `5b686303…`) were already correct. Vector digests in
`source-baseline.toml` were re-hashed and all match.

## Offline verification

Command:

```text
cargo test -p reth-neox-chainspec -p reth-neox-consensus -p reth-neox-consensus-engine \
  -p reth-neox-evm -p reth-neox-antimev -p reth-neox-network -p reth-neox-node -p neox-rs
```

Result: **425 passed, 0 failed** (plus doc-test targets with no tests). `cargo +nightly fmt --all
-- --check` is clean. Strict clippy (`-D warnings`) is clean for `reth-provider`,
`reth-node-builder`, `reth-neox-node`, and `neox-rs`. The full `reth-provider` suite passes
**233/233** on Windows after the static-file mapping fix, and `reth-static-file` passes 2/2. After
the 2.7.0 upstream merge the provider suite is **239/239**; the Neo X suite remains **425**.
Regression tests added by this review:

- `spec::tests::omitted_neox_fork_fields_mean_never_active`
- `config::tests::omitted_forks_deserialize_and_serialize_as_absent`
- `pool::tests::policy_rejects_fee_cap_below_base_fee_even_with_zero_minimum_tip`
- `sync::tests::total_difficulty_checkpoint_roundtrips_and_rejects_corruption`
- `tests::envelope_fee_is_zero_before_amev_activation`
- `providers::static_file::manager::tests::clear_cached_readers_releases_mappings_and_keeps_reads_working`

## Protocol cross-check summary

| Area | Oracle reference | Result |
|---|---|---|
| dBFT extra versions/lengths, hashable prefix, v0/v1/v2 seals | `verifyHeader`, `verifyExtra`, `EncodeSigHeader` | Match |
| Parent next-consensus link (V0 / V1/V2 fallback / threshold) | `verifyExtra` | Match |
| ECDSA quorum, duplicate/unauthorized signer handling | `VerifyMultiBFT` / `VerifyMulti` | Match |
| V1 threshold-signature negation | `PublicKey.Verify(..., isNegatedResult)` | Match |
| In-turn/out-of-turn difficulty | `inturn`, `diffInTurn = 2`, `diffNoTurn = 1` | Match |
| Header structural rules (extra length, ommers, mix digest, withdrawals/beacon/requests roots) | `verifyHeader` | Match |
| Policy base fee, envelope count/gas/fee, blacklist | `state_processor.go`, `state_transition.go` | Match |
| Blacklisted call targets in CALL/CALLCODE/DELEGATECALL/STATICCALL, precompile exemption, EIP-158 zero-value edge case | `core/vm/evm.go` | Match |
| MCOPY and KZG/BLS precompile activation at DKG | `NeoXDKG` instruction set/precompile table | Match |
| onPersist order and selectors (KeyManagement V2 then Governance V2) | `ProcessOnPersist` | Match |
| Envelope recognition, minimum length, encrypted gas/hash offsets | `antimev/envelope.go` | Match |
| Decrypted-transaction validation (type, nonce, tip, sender, hash, gas, allocation) | `validateDecryptedTx` | Match |
| Reconstruction fallback order and per-sender skipping | `processPreBlockCb` | Match |
| dBFT/beacon wire sizes and message IDs | 4 MiB / 10 MiB limits, `dbft/0`, `beacon/1,2` | Match |
| Genesis extra synthesis and explicit threshold sentinel | genesis creation | Match |

## Findings

### P2 — F1: Compatibility baseline contained non-existent commit IDs — **fixed**

`docs/neox/source-baseline.toml` and `2026-10-01-PHASE2A-ENGINE-FIXES-APPLIED.md` recorded full
SHA-1s whose objects do not exist. The 10-character prefixes were real upstream commits, but the
suffixes were fabricated. Both `tip_under_review` values had the same defect. Corrected with the
verified full SHAs above, and the local cherry-pick IDs were recorded separately.

### P2 — F2: Vendored genesis no longer matched the pinned oracle, with a false premise — **fixed**

Commit `1e12f7cc46` removed `blobSchedule.osaka` from both canonical genesis files. The change was
justified by "osaka was never activated … activation times remain far in the future". That is
wrong: MainNet activated Osaka at block 6,949,847 and the live head is Osaka-active. The removal
happened to be behaviourally inert because alloy supplies the identical default
`BlobParams::osaka()`, but it broke semantic and byte equality with the then-pinned `f0e236838b`
oracle and made the README fingerprints wrong. The files were restored to those bytes; the drift
report and Phase 2 evaluation carry correction notes.

The 2026-10-18 upstream sync supersedes the byte-level part: Geth `9dec1dc364` itself removed
`blobSchedule.osaka` (upstream `8fde8c492f`, aligned with Reth). The vendored files now match the
new oracle bytes, the README fingerprints are updated, and the genesis block hashes and Osaka blob
parameters are unchanged.

### P2 — F3: README release-gate status contradicted the G8 PASS evidence — **fixed**

`README.md` still said that live DKG share calls reverted with `CommitmentInvalid()` and that "no
DKG round transition is claimed". `reports/2026-09-10-G8-MIXED-DKG.md` records the repaired
run: round 1 → 2, non-empty aggregate commitment, 1,402 blocks checked, zero reorgs, zero transient
errors. The README now states the PASS and the narrower remaining qualification work.

### P3 — F4: Omitted optional `neoX*Block` fields were rejected — **fixed**

Geth models `neoXDKGBlock`, `neoXAMEVBlock`, and `neoXEthSigBlock` as optional pointers; missing
means the fork never activates. The Rust genesis parser required all three. `NeoXGenesisConfig`
now defaults them to a `NEOX_FORK_NEVER` sentinel, `NeoXChainSpec` omits unscheduled hardforks,
and a test covers a genesis with all three fields absent.

### P3 — F5: Pool admitted a fee cap below the Policy base fee when the minimum tip is zero — **fixed**

Geth computes a signed `gasFeeCap - baseFee`, so a fee cap under the Policy base fee is a negative
effective tip and fails `ErrTxGasPriceTooLow` even when `minGasTipCap == 0`. `pool::validate_policy`
used `effective_tip_per_gas(...).unwrap_or_default()`, turning that case into a zero tip and
admitting the transaction. It now returns `FeeCapBelowPolicyBaseFee`, with a regression test. This
is pool-admission parity only; block execution already rejected such transactions.

### P3 — F6: Startup total-difficulty resolution was O(chain height) — **fixed**

`NeoXNetworkBuilder` starts peers only after `authoritative_canonical_status(..., trusted=false)`.
Because Reth's launch head carries zero total difficulty, the function summed `header.difficulty`
over every header from genesis: **33.8 s** on the 7,671,697-block archive datadir (pool init
`10:23:06.7` → P2P initialized `10:23:40.5`).

The node now maintains `neox-total-difficulty.json` under the data directory. On startup it accepts
the checkpoint only when `provider.block_hash(number)` still equals the stored hash, then adds
difficulty only for blocks after the checkpoint; the sync driver rewrites it every 1,024 blocks and
immediately on a backward reorg. A missing, torn, symlinked, oversized, or stale file falls back to
the full scan. Measured on the same datadir: **33.8 s → 0.374 s** on restart, including a 57-block
catch-up.

### P3 — F7: `eth_envelopeFee` was not AMEV-gated like Geth — **fixed**

Geth returns zero from `EnvelopeFee` before `IsNeoXAMEV(head.Number)`. The Rust RPC returned the raw
`PolicyProxy.envelopeFee` slot for every height. `latest_envelope_fee` now reads the latest header
and returns zero before AMEV, with a unit test covering both a future and an active fork height.
Canonical MainNet/T4 were already past AMEV, so no public-network behavior changed.

### P3 — F8: Windows startup requires `--ipcdisable` — **documented**

The upstream default IPC endpoint `/tmp/reth.ipc` is not a valid Windows named-pipe path, so
`neox-rs node` exits before RPC is served. This is upstream Reth behaviour, not a Neo X defect, but
the review adds the requirement to the README build/run section.

### P2 — F9: Windows hard-kill recovery failed while truncating mapped static files — **fixed**

A hard kill during live persistence can leave a partial state trie. Startup correctly detected it
and scheduled a pipeline unwind, but the unwind failed truncating a static file that a cached
`NippyJar` reader still had mapped:

```text
Executing unwind after consistency check. unwind_target=Unwind(8038457)
inconsistency_source=partial state trie
ERROR failed to run unwind ... err=The requested operation cannot be performed on a file with a
user-mapped section open. (os error 1224)
```

Root cause: opening a static-file writer, the consistency check, and the unwind pipeline all cached
mapped readers in the shared provider, and Windows refuses `SetEndOfFile`/delete while any mapping is
live. The fix adds `StaticFileProviderInner::clear_cached_readers` (a no-op outside Windows) and
calls it after a writer caches its jar but before `NippyJarWriter` heals it, before every
truncate/prune, before deleting a previous file, and between the consistency check and the unwind
pipeline. A regression test asserts the cache drops mappings while reads keep working.

Validated live: the previously unrecoverable datadir (`partial state trie` at block 8,038,457) now
unwinds, reaches the canonical head, and follows live dBFT blocks. The full `reth-provider` suite is
**233/233** on Windows, including the transaction truncation test that previously failed with
`os error 1224`.

## Live MainNet verification

Run performed on a copy of `outputs/verify-datadir` (archive DB at block 7,671,697), current HEAD
binary, ports moved to `30313/18545/18546/18551`, `--nat none --ipcdisable`.

1. **Startup**: resolved the authoritative head, activated the dBFT round from Governance state,
   and connected to both official MainNet bootnodes over `beacon/2` and `dbft/0`.
2. **Historical differential** at the datadir tip (block 7,671,697): 37 checks, **0 mismatches**;
   only the expected height skew against the live reference head was reported.
3. **Catch-up**: headers 7,671,698 → 8,038,336, bodies, and sender recovery completed; the
   Execution stage executed the empty-block range at roughly 9–21 Mgas/s and reached the reference
   head at `09:46:29Z`. Local and reference head were both **8,038,441** at `09:46:34Z`; the node
   then followed new dBFT blocks (`new payload` → canonical commit → FCU → next round) without
   operator action. `eth_syncing` returned `false`.
4. **Head differential** (40 checks, including the three head-only Policy RPC methods):
   **0 mismatches, skew 0, nothing skipped**; re-run at the final head `0x7aa85a` (block
   8,038,490) with the same result.
   ```json
   {"status":"ok","local_head":"0x7aa85a","reference_head":"0x7aa85a",
    "height_skew":0,"checks":40,"skipped":[],"mismatches":[]}
   ```
5. **Execution differential** at block 8,038,414 (two transactions, post-Osaka): **105 checks,
   0 mismatches**, transaction and receipt fields included.
   ```json
   {"status":"ok","height":"0x7aa80e","checks":105,
    "execution_transactions_checked":2,"mismatches":[]}
   ```
6. **Crash recovery (F9)**: a hard kill during live import left a partial state trie at block
   8,038,457. The fixed binary detected it, unwound to 8,038,457, reopened RPC, caught back up to
   the canonical head, and continued importing dBFT blocks. A later restart with the final binary
   reused the TD checkpoint and started P2P in **0.374 s** (F6).
7. **Final head differential with all fixes**: `0x7aa964`, 40 checks, 0 mismatches, skew 0, nothing
   skipped.

Timing: pipeline start at `09:30:41Z`, tip reached at `09:46:29Z` (366,744 blocks, including the
33.8 s first startup TD scan), and the node continued importing live dBFT blocks afterwards. The
reviewed checkpoint reduces subsequent startup TD resolution to under half a second. This run is a
non-validator full node only.

Artifacts: `outputs/review-head-differential-20261018.json`,
`outputs/review-execution-differential-20261018.json`,
`outputs/review-head-differential-final.json`, `outputs/review-node-run1.log`,
`outputs/review-node-run2.log`, `outputs/review-node-run3.log` (the pre-fix failure), and
`outputs/review-node-recovery3.log` / `outputs/review-node-final.log` (successful recovery).

## Remaining risks (not defects found by this review)

1. **Validator qualification** — validator mode is still experimental. The mixed-client DKG gate
   passes on current HEAD; prover-delay and Reth crash/restart fault injection pass on G8, and
   rollback/backfill recovery passes. Transaction replacement, a true controlled reorg, and Anti-MEV
   production decryption remain.
2. **PKCS#7 strict activation (G9)** — the `Pkcs7Strict` gate and the coordinated Geth patch are
   implemented, but activation is a governance/operations action. Do not mix strict and legacy
   validators after activation and do not roll back ad hoc.
3. **Ciphertext admission divergence** — this client rejects a broken TPKE ciphertext at pool
   admission while Geth admits it and later stalls. The divergence is liveness-only by the pairing
   equivalence argument; it remains documented and intentional.
4. **On-chain KeyManagement PVSS/renovate strength** — the contract is outside this repository. The
   Rust-side `DkgPvss::verify`, `verify_aggregated_dkg_share`, and
   `verify_aggregated_dkg_commitment` checks are internally consistent and covered by cross-vectors,
   but they do not replace an independent review of the deployed Solidity.
5. **Other Windows-only upstream tests** — `reth-db` PID-namespace tests fail on this host for
   environmental reasons; they are not Neo X regressions. The `reth-provider` static-file suite now
   passes 233/233.

## Release statement

For a **non-validator full node**, this revision is suitable for MainNet operation: it builds,
passes 425 Neo X tests plus 239 provider and 2 static-file tests, reproduces the pinned genesis and
historical state, catches up to the live head, passes the head and execution differentials, reuses
a validated TD checkpoint, and recovers from a hard kill on Windows. Windows still needs
`--ipcdisable` (F8); Linux remains the recommended production platform. For a **validator**, the
remaining qualification gates above must be closed first. No claim of 100% cross-implementation
equivalence is made for paths that have not been exercised live (controlled reorg injection,
mixed-client DKG on this HEAD, and strict PKCS#7 activation).
