# Neo X release checklist — 2026-10-20

## Decision summary

| Track | Decision | Scope |
|---|---|---|
| Non-validator full node | **GO with conditions** | MainNet/TestNet full node, RPC, archive sync |
| Validator | **NO-GO for stable; RC only after the gates below** | dBFT validator, DKG, Anti-MEV |

The non-validator path is the same merged Reth 2.7 / Neo X Geth 9dec codebase without validator
duties. The validator path has additional production-lifecycle and security gates that are not yet
closed.

## Evidence already available

- Reth 2.7 / Geth `9dec1dc364` merge verification:
  [`2026-10-18-UPSTREAM-SYNC-RETH-2.7.md`](2026-10-18-UPSTREAM-SYNC-RETH-2.7.md)
- Full G8 DKG gate, **1,401 blocks**, round 1 → 2, identical 128-byte commitment:
  [`2026-10-19-VALIDATOR-DKG-STALL.md`](2026-10-19-VALIDATOR-DKG-STALL.md),
  `outputs/g8-20261019-formal.json`
- Fault injection (prover delay, crash/restart, rollback/backfill, transaction replacement,
  finality-boundary reorg attempt):
  [`2026-10-19-FAULT-INJECTION.md`](2026-10-19-FAULT-INJECTION.md),
  `outputs/fault-injection-20261019.json`
- Neo X tests: **426 passed** across the eight Neo X crates; clippy `-D warnings`; nightly fmt.

## A. Non-validator full-node release

Required before tagging:

- [ ] Freeze the release commit and create a signed tag from that exact commit.
- [ ] Build release artifacts from the frozen commit (Linux x86_64/aarch64; Windows if shipped).
- [ ] Run `cargo test` for all Neo X crates and clippy/format checks on the frozen commit.
- [ ] Verify MainNet genesis hash `2ee57478…` and TestNet `221f7d0a…`; verify the Geth 9dec
      genesis bytes.
- [ ] Run a clean-datadir MainNet sync plus an existing archive-datadir upgrade on the release
      binary.
- [ ] Record the datadir backup and downgrade policy: Reth 2.7 can open a 2.5 datadir; a downgrade
      is untested and requires a backup.
- [ ] Publish checksums and the container image digest.
- [ ] Confirm validator flags are absent from the default full-node runtime.
- [ ] Decide and record the residual risk of shipping before the independent security review is
      complete (the review is still an open gate in the README).

## B. Validator release / RC

Required in addition to A:

- [ ] Freeze the exact release commit. The current code head includes `09ec63cdbf`
      (signer-installation digest); the formal G8 gate predates that change.
- [ ] **Rerun the full 1,401-block G8 DKG gate on the exact release commit** and archive the JSON.
- [ ] Re-run the G8 fault scenarios on that commit: prover delay, crash before and after DKG task
      submission, transaction replacement, rollback/backfill.
- [ ] Qualify Anti-MEV production envelope decryption end to end.
- [ ] Close the `managed Neo X DKG share does not match canonical epoch` / final-commit share epoch
      investigation; the final gate did not reproduce it, but the root cause is not closed.
- [ ] Exercise validator datadir + DKG keystore upgrade and rollback with a backup.
- [ ] Verify monitoring/alerts for DKG preparations, submissions, replacements, confirmed tasks,
      current round, and prover failures.
- [ ] Complete the independent protocol/security review required by the README.
- [ ] Publish as `-rc`, not a stable validator release.

## Go/no-go record

Fill at release time:

```
release commit:
artifact digest:
full-node:   GO / NO-GO  (reviewer, date)
validator:   GO / NO-GO  (reviewer, date)
open exceptions:
security review status:
```
