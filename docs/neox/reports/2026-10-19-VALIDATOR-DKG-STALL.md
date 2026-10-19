# Validator DKG epoch stall on the G8 harness (2.5.2 and 2.7) — 2026-10-19

## Result

**Full G8 mixed-client DKG gate FAILED, and the failure is not specific to the Reth 2.7 merge.**
The validator kept the chain live and agreed with all eight Geth nodes, but the on-chain DKG round
never advanced from **1 to 2**. A pre-merge control run on the same harness reproduced the same
preparation stall. This is a validator-release blocker; the non-validator full node is unaffected.

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

## Reproduction

- One Reth binary: `target-linux/debug/neox-rs`, commit `fcbc603724` (`2.7.0-dev`), copied to
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

- `outputs/g8-20261019/reth-val1.log` (18.8 MB)
- `outputs/g8-20261019/launch-g8-full.log`
- `outputs/g8-20261019/gate-v2c.out`

## Assessment

This is **not** a block-sync or dBFT-consensus divergence: Reth followed the Geth chain and
produced/validated dBFT traffic throughout. The failure is in the validator DKG preparation path,
and the pre-merge control rules out the Reth 2.7 merge as its cause.

The most likely remaining explanations are:

- the external `neox-dkg-prover-linux` process is never successfully spawned in this harness (no
  child appears, yet attempts increment);
- the preparation future is replaced/cancelled before it can be polled, so attempts accumulate
  without a `Prepared` or `preparation failed` outcome;
- the G8 harness has drifted from the 2026-09-11 pass (prover binary, manifest, keystore template,
  or WSL execution environment).

The separate `managed Neo X DKG share does not match canonical epoch` warning is an Anti-MEV final
commit signature issue; it also appears on the pre-merge binary and is not the immediate cause of
the round-2 task stall.

## Next steps

1. Instrument `start_preparation`/`poll_preparations` and the prover spawn at
   `neox_rs::dkg=debug`: log task ID, preparation-map length, spawn result, child PID, and every
   outcome. This will distinguish “never spawned” from “spawned but not polled”.
2. Diff the 2026-09-11 G8 harness against the current one: prover binary hash, manifest, keystore
   template, WSL kernel/seccomp environment, and Geth binary.
3. Fix the preparation lifecycle (or harness) and add a focused regression test for the
   preparation→record path.
4. Rerun the full G8 round-1 → 2 gate on both the pre-merge and current binaries.

**Validator readiness remains blocked until the full gate passes.**
