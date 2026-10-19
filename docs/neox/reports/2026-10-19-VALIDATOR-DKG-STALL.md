# Validator DKG epoch stall on the G8 harness — resolved 2026-10-19

## Result

**Resolved on the core G8 criteria after two fixes.** The validator kept the chain live and agreed
with all eight Geth nodes; after fixing the preparation-retry and submit-retry lifecycle, the
on-chain DKG round advanced from **1 to 2**, all nine clients exposed the same non-empty 128-byte
aggregate commitment, and a 24-block post-transition agreement check passed with zero reorgs and
zero RPC errors.

The initial failure was **not specific to the Reth 2.7 merge**: a pre-merge 2.5.2 control
reproduced the same preparation stall. The root cause was in the shared DKG lifecycle:

- a canonical-head advance during a heartbeat invalidated the attempt and retried at the stale
  height, aborting every in-flight prover job (135 attempts, 0 preparations);
- after that was fixed, a `Ready` task moved to `Submitting` was stranded there when the
  canonical-head fence rejected the submit, so the prepared Share was never sent.

Fixes: `daadb7fdeb` (preserve preparations across head advances) and `a5a70ad34e` (restore a
`Ready` task when the submit fence fails). The formal long-running `v2c` gate then **passed**:
**1,401 blocks** checked from height **2,402 to 3,802**, initial round **1 → final round 2**,
aggregate commitment SHA-256
`7790337238407f24bef096bb45ef53880420c55dcaf43f1abe6dffb20eed69c3`, **0 reorgs**, **0 transient RPC
errors**, and all nine clients on the same head. See `outputs/g8-20261019-formal.json`.

**Release note:** the gate predates the later signer-installation digest optimization
`09ec63cdbf`. That change only reduces redundant installations (verified at 185 blocks with one
install) and has unit coverage, but a release candidate must rerun the full gate on the exact
release commit.

Historical failure detail:

- Gate entry: height **2400** at `23:46:49Z`; all nine clients had the same head `2400`.
- At `00:12Z` height **3686**: on-chain `currentRound` still **1** (round 2 was expected at 3600).
- Reth runtime metrics: `reth_neox_dkg_prover_attempts_total=135`,
  `reth_neox_dkg_task_preparations_total=0`, `task_preparation_failures_total=0`,
  `submissions_total=0`, `queued_tasks=0`, `current_round=2`.
- Reth logged `Discarded unfinished Neo X DKG round outside its canonical window` once at the epoch
  boundary.
- From `23:52Z` onward, `Failed to sign Neo X Anti-MEV final block commit` repeated with
  `managed Neo X DKG share does not match canonical epoch: installed round 1 at …, expected round 1
  at …`; the installed and expected canonical heads differ and the expected value changes per block.

The chain itself was healthy: all clients followed dBFT blocks, and the earlier short
`--no-round-advance` smoke passed **34 common blocks with 0 mismatches / 0 reorgs / 0 RPC errors**
(`outputs/g8-mixed-smoke-20261019.json`).

Additional timing observations from the preserved log:

- Reth was still **syncing** when the first round-2 tasks were queued at height **1800**
  (`Received forkchoice updated message when syncing`; it activated its local validator signer at
  height 1807). This is earlier than the gate's assumed share window: the on-chain
  `DkgSchedule::new(0, 3600, 900)` gives share start **1800**, recovery start **2700**, target
  **3600**, so the gate's `[2400, 3300)` wait is conservatively inside the share phase, not at its
  start.
- Task queueing stopped at height **2698** (the last `Queued ... inserted=2` log), i.e. at the
  recovery boundary. There were **no** `Prepared Neo X DKG calldata` or
  `Neo X DKG preparation failed` messages at any point, and no prover child process was visible.
- The aggregate commitment for round 1 was non-empty (the gate accepted its initial snapshot), so
  round 1 itself was settled; only the round-2 task preparation is stuck.

## Pre-merge control run

To isolate the merge, the pre-merge tree `a94406bb8a` was built as `2.5.2` and run against the same
G8 harness and genesis:

- At height **2351** the pre-merge binary had `prover_attempts=74`, `queued_tasks=2`,
  `task_preparations=0`, `task_preparation_failures=0`, `submissions=0`.
- It also queued tasks repeatedly from height 1800 and produced no `Prepared` or `preparation failed`
  message; no prover child process was visible.
- At height 1800 the pre-merge binary briefly re-entered dBFT recovery (`Published local Neo X
  RecoveryRequest`), then caught up to height 2351; the preparation stall remained.

**Conclusion: the stall is not caused by the Reth 2.7 merge.** The same preparation behavior appears
on the pre-merge binary. The root cause is therefore in the shared G8 harness/prover environment or
in pre-existing DKG runtime behavior; the prior 2026-09-11 pass used the same code family and needs
its prover/keystore/environment diffed against this run.

Control evidence: `outputs/g8-control-20261019/reth-val1.log`,
`outputs/g8-control-20261019/launch-premerge.log`.

## Fix applied and post-fix run

Commit `daadb7fdeb` stops invalidating the DKG attempt when the canonical head advances during a
heartbeat. It breaks the retry loop instead of retrying at the stale notification height and
aborting every in-flight prover job. On a fresh G8 run with that binary:

- The prover child spawned, completed, and was recorded: `task_preparations=2`,
  `preparation_failures=0`, `submissions=3`.
- `Prepared Neo X DKG calldata` and `Submitted Neo X DKG transaction` appeared for the round-2
  Reshare and Share tasks instead of 135 attempts with zero completions.
- The Reshare transaction was mined (Reth validator nonce advanced to 1).

The gate still fails at height 3600, but for a **different** reason:

- The Share task was prepared at height **1980** but never logged `Submitted`; it expired at
  height **2710**.
- At 3600 all six Geth validators logged `DKG reached targetHeight round=2
  aggregatedCommitment=` (empty), and the on-chain round stayed **1**.
- Reth's Share contribution is therefore missing from the aggregate even though the six Geth
  validators submitted their share/reshare receipts.

This is a **task-lifecycle/submission bug** (a prepared Share task is dropped or reset before it is
submitted), not the original preparation churn. Evidence:
`outputs/g8-20261019-fixed/reth-val1.log`, `outputs/g8-20261019-fixed/geth-node*.log`.

## Final passing run (`a5a70ad34e`)

After the Submit-retry fix:

- Both round-2 tasks prepared and submitted:
  - Reshare `0xa9b92f…` at block 1,936, receipt status `0x1`;
  - Share `0x386317…` at block 2,034, receipt status `0x1`.
- At height 3600 all nine clients reported on-chain **round 2**.
- Every client returned the same **128-byte aggregate commitment**,
  SHA-256 `7790337238407f24bef096bb45ef53880420c55dcaf43f1abe6dffb20eed69c3`.
- A post-transition agreement check covered 24 common blocks with **0 reorgs, 0 transient RPC
  errors, 0 mismatches**.
- The formal `v2c` gate then passed **1,401 blocks** from height **2,402 to 3,802**, round **1 → 2**,
  the same commitment SHA-256, **0 reorgs**, **0 transient RPC errors**, and all nine clients on
  the same head.
- Evidence: `outputs/g8-20261019-pass.json`, `outputs/g8-20261019-pass/`,
  `outputs/g8-20261019-formal.json`, `outputs/g8-20261019-formal/`.

Lifecycle fault injection remains below; the full `v2c` block/DKG gate itself has passed.
Post-fix validation: **426 Neo X tests** across the eight Neo X crates pass, and clippy is clean
with `-D warnings`.

## Reproduction

- One Reth binary: `target-linux/debug/neox-rs`, final commit `a5a70ad34e` (`2.7.0-dev`), copied to
  `/home/dministrator/g8-run/neox-rs`.
- Eight Geth nodes: `/home/dministrator/g8-run/geth-linux` (the existing G8 Linux build).
- Genesis: `genesis_short_epoch_v2.json`, SHA-256
  `ac9381428879a1e5b8e6c51e202c21625fb91cda46fb6e730331405ffd70970d`.
- Launcher: `/home/dministrator/g8-run/launch-wsl-v2.sh`; gate:
  `/home/dministrator/g8-run/v2c-run-gate.sh` with `--minimum-blocks 1400` and
  `--max-height-skew 64`.
- All nine clients were at height 2400 when the gate armed; P2P was fully connected
  (`reth peers=0x8`).

Preserved evidence:

- `outputs/g8-20261019/reth-val1.log` (18.8 MB historical failure)
- `outputs/g8-20261019/launch-g8-full.log`
- `outputs/g8-20261019/gate-v2c.out`
- `outputs/g8-20261019-fixed/` (post-preparation-fix failure)
- `outputs/g8-20261019-pass/` and `outputs/g8-20261019-pass.json` (final passing run)
- `outputs/g8-20261019-formal/` and `outputs/g8-20261019-formal.json` (formal `v2c` PASS)

## Assessment

This was **not** a block-sync or dBFT-consensus divergence: Reth followed the Geth chain and
produced/validated dBFT traffic throughout. The pre-merge control ruled out the Reth 2.7 merge as
the cause of the original preparation churn.

Two lifecycle defects caused the failure, both now fixed:

1. a canonical-head advance during a heartbeat aborted every in-flight prover task and retried at
   the stale notification height (`daadb7fdeb`);
2. a `Ready` task moved to `Submitting` was stranded when the canonical-head fence rejected the
   submit, so the prepared Share was never sent (`a5a70ad34e`).

After both fixes the epoch transition, commitment equality, and block agreement all pass. The
separate `managed Neo X DKG share does not match canonical epoch` warning is an Anti-MEV final
commit signature issue observed on both pre-merge and current binaries; it did not prevent the DKG
epoch transition but remains a validator-lifecycle qualification item.

## Next steps

1. Prover-delay and Reth crash/restart scenarios pass; see
   [2026-10-19-FAULT-INJECTION.md](2026-10-19-FAULT-INJECTION.md).
2. Qualify the Anti-MEV final-commit share epoch issue and production decryption. Prover delay,
   crash/restart, rollback/backfill, and transaction replacement pass; conflicting-branch reorg
   beyond finality is rejected by dBFT.

**The full G8 block/DKG gate and the exercised fault-injection scenarios pass.**
