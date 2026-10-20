# Neo X release checklist — 2026-10-20

## Current status

- Candidate code: `f361db8c7f` (dependency security fixes on top of `ff78e47cc1`); docs head:
  `61d61e38c2`.
- Exact-commit G8 gate, current-epoch Envelope decryption, exact-commit fault rerun, datadir/
  keystore downgrade, and x86_64 release builds are verified.
- Stable release is **NO-GO** while full MainNet sync, cross-epoch production decryption, and the
  independent security review remain open.

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
- Final-candidate G8 gate, **1,401 blocks**, round 1 → 2, identical 128-byte commitment, zero
  canonical-epoch mismatches: `outputs/g8-20261019-final-gate.json`.
- Fault injection (prover delay, crash/restart, rollback/backfill, transaction replacement,
  finality-boundary reorg attempt):
  [`2026-10-19-FAULT-INJECTION.md`](2026-10-19-FAULT-INJECTION.md),
  `outputs/fault-injection-20261019.json`
- Neo X tests: **427 passed** across the eight Neo X crates; clippy `-D warnings`; nightly fmt.

## A. Non-validator full-node release

Required before tagging:

- [ ] Freeze the release commit and create a signed tag from that exact commit. Candidate code:
      `f361db8c7f` (deps security update on top of validator candidate `ff78e47cc1`); docs head
      `372b161b1f`.
- [x] Build release artifacts from the frozen commit: Linux x86_64
      `20a15c17…` and Windows x86_64 `7fe4d014…`, 2.7.0-dev, commit `f361db8c7f`
      (`outputs/release-20261020/manifest.json`). aarch64 was not built in this session.
- [x] Run `cargo test` for all Neo X crates (**427 passed**) and clippy/format checks on the
      frozen commit.
- [x] `cargo audit`: **0 vulnerabilities** after quinn-proto 0.11.18 / rustls 0.23.46 updates
      (`outputs/cargo-audit-after-20261020.json`).
- [x] Verify MainNet genesis hash `2ee57478…` and TestNet `221f7d0a…`; verify the Geth 9dec
      genesis bytes.
- [ ] Run a clean-datadir MainNet sync plus an existing archive-datadir upgrade on the release
      binary. The release binary initialized a clean MainNet datadir, connected to 2 peers, entered
      the Headers stage, and downloaded 10,000-header batches from ~7.68M in a 5-minute smoke
      (`outputs/clean-sync-20261020.json`). The release binary also opened the existing archive
      datadir. Full clean sync is not completed and remains outstanding.
- [x] Record the datadir backup and downgrade policy: Reth 2.7 can open a 2.5 datadir; a downgrade
      is untested and requires a backup.
- [ ] Publish checksums and the container image digest. Local artifact manifest exists; registry
      publication is a release-maintainer action.
- [x] Confirm validator flags are absent from the default full-node runtime.
- [ ] Decide and record the residual risk of shipping before the independent security review is
      complete (the review is still an open gate in the README).

## B. Validator release / RC

Required in addition to A:

- [x] Freeze the exact validator candidate code commit: `ff78e47cc1` (includes
      `09ec63cdbf` signer-installation digest and the Anti-MEV epoch match).
- [x] **Rerun the full 1,401-block G8 DKG gate on the exact release commit**: passed from height
      2,394 to 3,794, round 1 → 2, identical commitment, 0 reorgs, 0 RPC errors. JSON:
      `outputs/g8-20261019-final-gate.json`.
- [x] Re-run the G8 fault scenarios on that exact commit: prover delay (60 s `SIGSTOP` at height
      1,782), Reth crash/restart at height 2,319, and a live missing-receipt replacement at height
      2,374; the chain reached height 3,670 at round 2
      (`outputs/fault-final2-20261020.json`). Rollback/backfill evidence remains from the earlier
      commit.
- [x] Qualify Anti-MEV production envelope decryption end to end for the current DKG epoch: a live
      Envelope sent through Reth was decrypted by Geth and its inner transaction mined at block 525
      with status 1 (`outputs/g8-envelope-20261019.json`). Two Envelope decryptions also occurred
      during the final gate. Cross-epoch/reshare vectors remain in the integration-test suite.
- [x] Close the `managed Neo X DKG share does not match canonical epoch` root cause: the signer now
      matches round + aggregate global key, not the exact canonical head (`ff78e47cc1`); the final
      gate logged zero mismatches.
- [x] Exercise validator datadir + DKG keystore upgrade and rollback with a backup. A 2.7 G8
      datadir (height 1,073) opened under 2.5.2 with its DKG keystore loaded and the validator
      signer activated (`outputs/downgrade-20261020.json`). This verifies datadir schema and
      keystore open, not live downgraded consensus; a 2.5 archive datadir also opened under 2.7.
- [x] Verify monitoring/alerts for DKG preparations, submissions, replacements, confirmed tasks,
      current round, and prover failures. The `neox.dkg` metric scope exposes
      `reth_neox_dkg_task_preparations_total`, `prover_attempts_total`,
      `task_preparation_failures_total`, `submissions_total`, `submission_failures_total`,
      `replacements_total`, `confirmed_total`, `expired_total`, `current_round`, and
      `queued_tasks`; the G8 runs exercised the endpoint.
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
