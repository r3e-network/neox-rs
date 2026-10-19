# Validator DKG epoch stall after the Reth 2.7 merge — 2026-10-19

## Result

**Full G8 mixed-client DKG gate FAILED.** The new Reth 2.7 validator kept the chain live and agreed
with all eight Geth nodes, but the on-chain DKG round never advanced from **1 to 2**. This is a
validator-release blocker; the non-validator full node is unaffected.

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
produced/validated dBFT traffic throughout. The failure is in the validator DKG runtime.

The most likely trigger is the Reth 2.7 engine/canonical-notification change: preparations are
started (`prover_attempts=135`) but never recorded as prepared or failed, which points at the
preparation future being replaced/cancelled before completion or at the canonical share metadata
changing under every notification. The share-mismatch warning (`installed_head != expected_head`)
is consistent with a canonical-head/state ordering race introduced by the base upgrade.

This must be isolated against a pre-merge binary before blaming the merge conclusively. The prior
full G8 pass on 2026-09-11 used the pre-merge tree and the same harness/template.

## Next steps

1. Rebuild the pre-merge commit (`a94406bb8a`, Reth 2.5.2) and run the same G8 gate; if it passes,
   the regression is merge-induced.
2. Instrument `start_preparation`/`poll_preparations` at `neox_rs::dkg=debug` and log the task ID,
   prepared handle count, spawn result, and child PID; check whether the prover future is replaced
   or cancelled on each canonical notification.
3. Audit Reth 2.7 canonical-notification ordering against `DkgRuntime`'s `canonical_head` /
   `state_by_block_hash` fence; install shares only for a stable canonical state.
4. Fix, add regression coverage, and rerun the full G8 round-1 → 2 gate.

**Validator readiness remains blocked until the full gate passes.**
