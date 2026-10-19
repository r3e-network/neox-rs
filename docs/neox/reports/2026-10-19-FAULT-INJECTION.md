# Neo X validator fault-injection revalidation — 2026-10-19

## Scope

Runs on the G8 short-epoch v2 harness used for the successful DKG gate: one `neox-rs` validator on
Reth 2.7 and eight Neo X Geth nodes. Two lifecycle faults are exercised here. Transaction
replacement and controlled-reorg scenarios remain open.

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

## Remaining scenarios

- transaction replacement during production;
- controlled reorg across the DKG share boundary;
- full lifecycle fault-injection qualification.

**These two scenarios pass; validator qualification is not complete until the remaining scenarios
also pass.**
