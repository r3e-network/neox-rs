# Neo X ZK-v1 short-epoch DKG regression — 2026-07-20

This is a synthetic private-network regression run. It is intentionally separate from the
official `privnet/zk` release evidence: Governance timing was shortened only to reach the DKG
share window during a bounded local run.

## Test fixture

- Eight Geth nodes (six validators and two observers) plus one `neox-rs` validator.
- Chain ID `2312251829`; seven pending validator entries were populated in Governance slot 24.
- Synthetic genesis SHA-256:
  `162d893315204b788d2f68a6f97f3f1f9381f00e09b738233236ff18426d2d78`.
- `dbftPeriod = 1`, `epochDuration = 240`, `sharePeriodDuration = 60`, and
  `currentEpochStartHeight = 0`.
- Derived checkpoints: `share_start = 120`, `recover_start = 180`, `target = 240`.
- Reth used the pinned official ZK-v1 ceremony artifacts, migrated validator-1 DKG keystore, and
  the Rust/Go `neox-dkg-prover` boundary.

## Observed DKG boundary

At canonical height 120, Reth logged:

```text
Queued Neo X DKG validator tasks height=120 inserted=2 round=2
```

The metrics at shutdown were:

| metric | result |
|---|---:|
| `reth_neox_dkg_tasks_queued_total` | 2 |
| `reth_neox_dkg_prover_attempts_total` | 1 |
| `reth_neox_dkg_task_preparations_total` | 0 |
| `reth_neox_dkg_task_preparation_failures_total` | 0 |
| `reth_neox_dkg_submissions_total` | 0 |
| `reth_neox_dkg_confirmed_total` | 0 |
| `reth_neox_dkg_expired_total` | 0 |

The first task entered the seven-message Groth16 prover. The helper was still running after at
least 4m58s and used approximately 4.2 GB resident memory; the run was stopped before a proof
response or timeout was returned. Consequently this fixture does **not** prove on-chain DKG
submission, receipt confirmation, or Anti-MEV envelope decryption.

## MDBX lifetime finding and fix

While the long proof was running, MDBX reported a 300-second long-lived read transaction. The
stack pointed to `prepare_task`: the state provider used to read recipient keys remained in scope
while the external prover was awaited. The runtime now scopes that provider to the key-read block,
so the read transaction is released before proof generation.

The finding is independent of whether the seven-message proof eventually succeeds. A production
gate still needs a measured seven-message proving duration, bounded memory profile, and an
asynchronous scheduling test showing that canonical processing and DKG retries do not stall while
the prover is working.

## Status

This regression closes the task-planning and prover-launch boundary only. The official network
smoke remains the separate evidence in [`zk-network-2026-07-20.md`](zk-network-2026-07-20.md), and
the complete official DKG window at heights 360–720 remains open.
