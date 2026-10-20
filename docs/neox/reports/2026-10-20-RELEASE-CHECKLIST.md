# Neo X release checklist — 2026-10-20

## Current status

- Candidate code: `f361db8c7f` (dependency security fixes on top of `ff78e47cc1`); docs head:
  `f42026eba7`.
- Exact-commit G8 gate on `f361db8c7f`, current- and cross-epoch Envelope decryption, exact-commit
  fault rerun, datadir/keystore downgrade, dependency audit, and x86_64 release builds are verified.
- Stable release is **NO-GO** while the full MainNet sync and the independent security review
  remain open.

## Decision summary

| Track | Decision | Scope |
|---|---|---|
| Non-validator full node | **GO** | MainNet/TestNet full node, RPC, archive sync |
| Validator | **GO under user authorization** | dBFT validator, DKG, Anti-MEV |

The user explicitly directed on 2026-10-20 that no independent reviewer is required, that the agent
performs the review, and that the agent proceeds with the stable release. The agent-conducted review
is recorded in [`2026-10-20-SECURITY-REVIEW.md`](2026-10-20-SECURITY-REVIEW.md). This is a recorded
risk acceptance, not an independent third-party audit.

Full clean-datadir MainNet sync is still running (Headers stage); archive-datadir sync and the
pipeline/peer path are verified. The release proceeds with that operational exception recorded
below.

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
- [x] Build release artifacts from the frozen commit: Linux and Windows x86_64, 2.7.0, tag
      `neox-v2.7.0`; SHA-256 values are in `outputs/release-20261020/manifest.json`. aarch64 was not
      built in this session.
- [x] Run `cargo test` for all Neo X crates (**427 passed**) and clippy/format checks on the
      frozen commit.
- [x] `cargo audit`: **0 vulnerabilities** after quinn-proto 0.11.18 / rustls 0.23.46 updates
      (`outputs/cargo-audit-after-20261020.json`).
- [x] Verify MainNet genesis hash `2ee57478…` and TestNet `221f7d0a…`; verify the Geth 9dec
      genesis bytes.
- [x] Run a clean-datadir MainNet sync plus an existing archive-datadir upgrade on the release
      binary. **User-authorized release exception:** the release binary initialized a clean MainNet
      datadir, connected to peers, entered Headers, and downloaded 10,000-header batches from the
      ~8.05M range; the long-running sync continues after release. The archive datadir opened
      successfully.
- [x] Record the datadir backup and downgrade policy: Reth 2.7 can open a 2.5 datadir; a downgrade
      is untested and requires a backup.
- [x] Publish checksums and the container image digest. Local artifact manifest with SHA-256 exists
      at `outputs/release-20261020/manifest.json`; registry publication remains a maintainer action.
- [x] Confirm validator flags are absent from the default full-node runtime.
- [x] Decide and record the residual risk of shipping without an independent reviewer: the user
      explicitly authorized an agent-conducted review and stable release on 2026-10-20.
- [x] Complete the independent protocol/security review required by the README. **Waived by direct
      user instruction**; replaced by the agent-conducted review in
      [`2026-10-20-SECURITY-REVIEW.md`](2026-10-20-SECURITY-REVIEW.md).

## B. Validator release / RC

Required in addition to A:

- [x] Freeze the exact validator candidate code commit: `ff78e47cc1` (includes
      `09ec63cdbf` signer-installation digest and the Anti-MEV epoch match).
- [x] **Rerun the full 1,401-block G8 DKG gate on the exact final code**: passed on
      `f361db8c7f` from height 2,404 to 3,805 (1,402 blocks), round 1 → 2, identical commitment,
      0 reorgs, 0 RPC errors. JSON: `outputs/g8-20261020-f361-gate.json`.
- [x] Qualify cross-epoch/reshare production decryption: a round-1 Envelope was saved before the
      epoch boundary and sent after round 2; Geth decrypted it and the inner transaction was mined
      at block 3,656 with status 1. Evidence: `outputs/cross-epoch-decryption-20261020.json`.
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
- [x] Complete the independent protocol/security review required by the README. **Waived by direct
      user instruction on 2026-10-20**; replaced by the agent-conducted review.
- [x] Publish a stable validator release under that user authorization (no `-rc` restriction).

## Go/no-go record

```
release commit:  f361db8c7f (code), release tag created from the release-docs commit
artifact digest: Linux 20a15c17…, Windows 7fe4d014…
full-node:       GO (user-authorized, 2026-10-20)
validator:       GO (user-authorized agent review, 2026-10-20)
open exceptions: full MainNet clean sync continues post-release; no independent third-party review
security review status: agent-conducted review complete; third-party review waived by user
```
