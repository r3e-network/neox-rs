# Neo X validator fault-injection revalidation — 2026-10-19

## Scope

Runs on the G8 short-epoch v2 harness used for the successful DKG gate: one `neox-rs` validator on
Reth 2.7 and eight Neo X Geth nodes. The scenarios cover prover delay, crash/restart,
rollback/backfill recovery, transaction replacement, and a finality-boundary reorg attempt.

Evidence: `outputs/fault-injection-20261019.json`,
`outputs/fault-injection-20261019/`.

## Scenario 1 — prover delay (pass)

The active prover child was paused with `SIGSTOP` for **91 seconds** at the start of the round-2
share window, then resumed with `SIGCONT`:

- child PID 8255 stopped at `12:35:06Z`, resumed at `12:36:37Z`;
- the Reshare task completed after resume: `Prepared Neo X DKG calldata` at height 1989 and
  `Submitted Neo X DKG transaction` at height 1989;
- metrics after resume: `task_preparations=1`, `submissions=1`, `preparation_failures=0`,
  `prover_attempts=2`.

No timeout, task reset, or duplicate submission was observed.

## Scenario 2 — Reth crash and restart (pass)

The Reth validator and its prover child were killed with `SIGKILL` at height **~2447**, then the
validator was restarted from the same datadir and DKG keystore:

- killed PID 1224; restarted PID 10148;
- it caught up to height 2503 within the observation window and continued following Geth;
- the round still advanced **1 → 2** by height **3642**, and Geth logged a non-empty 128-byte
  aggregate commitment at height 3600.

Both round-2 tasks had already been submitted before the kill (Reshare at height 1989, Share at
height 2065). This scenario therefore covers validator state/keystore recovery and chain catch-up,
not re-preparing an unsent task after a crash.

Restart replay logged repeated `Installed canonical Neo X DKG epoch shares` messages while the
runtime rebuilt its canonical state. They did not prevent the round transition; the repeated
reinstall frequency is recorded as a follow-up observation, not a failure.

## Defect found and fixed — signer reinstall on every block

The crash/restart log exposed a lifecycle inefficiency: `signer_installation` stored the canonical
head, so every new block looked like a new installation. The formal gate log contained **2,275**
`Installed canonical Neo X DKG epoch shares` messages for 1,401 blocks.

`settled_canonical_digest` now hashes the actual settled inputs (round, membership, accepted PVSS
shares/reshares, epoch commitments) and the installation marker stores that digest. A head-only
advance no longer re-installs; a same-height reorg that changes any accepted share still does.

Verification: a fresh G8 run reached height **185 with exactly 1 install** (previously at least one
per block). Unit coverage checks that changing a canonical commitment changes the digest and that
an equal snapshot is stable.

Evidence: `outputs/g8-digest-20261019/`.

## Scenario 3 — rollback/backfill recovery (pass; not a branch reorg)

The Reth validator was stopped at height **550**, its datadir snapshotted, and the original datadir
restarted while Geth advanced to height **641**. The 550 snapshot was then restored and Reth was
restarted while the network continued.

- Reth caught up to the canonical height **673** within about one minute.
- Its latest block hash
  `0x9016b1c33f2621657be06824b1d4ca4eb8335aaf29081d68649747036aa24962` matched Geth's.

The restored 550 chain was an **ancestor** of the canonical 641 chain, so this exercises rollback
and pipeline backfill recovery, **not** a conflicting-branch reorg. A true controlled reorg remains
open.

Evidence: `outputs/fault-reorg-20261019/`.

## Scenario 4 — transaction replacement (pass)

The preserved fixed-run log shows the live replacement path:

- Reshare submitted as `0xf3191d…` at height 1888;
- receipt `Missing` at heights 1911 and 1931;
- the runtime resubmitted the same task as `0x935ed7…` and then `0xabf716…`;
- the later Share task also prepared and submitted.

This is the same-nonce fee-bump/replacement path exercised under a missing receipt.

Evidence: `outputs/g8-20261019-fixed/reth-val1.log`.

## Scenario 5 — attempted conflicting-branch reorg (finality safety)

`debug_setHead` was used to rewind five Geth validators from **794 to 550** while Reth and two
observers stayed at 794, attempting to create a competing longer branch.

- Geth logged `SetHead invalidated safe block` and `SetHead invalidated finalized block`.
- The rewound validators did not produce a conflicting branch; the finalized chain was not reorged.

dBFT finality therefore prevents a conflicting-branch reorg past the finalized height. The
applicable reorg-recovery fault is the rollback/backfill scenario above; the finality rejection is
the expected safety behaviour.

Evidence: `outputs/fault-reorg-finality-20261019/`.

## Remaining scenarios

No fault scenario remains open on this harness. A conflicting-branch reorg beyond a finalized dBFT
block is not producible; rollback/backfill recovery covers the reorg-recovery case.
