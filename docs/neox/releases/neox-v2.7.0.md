# Neo X v2.7.0 release notes — 2026-10-20

## Release

- Tag: `neox-v2.7.0`
- Candidate code: `f361db8c7f`
- Reth base: `2.7.0` (`8868180a0e72df4c32f514b4d4666203560c2be8`)
- Neo X Geth oracle: `9dec1dc364d3db117bd87eb3613cc4de970912e2`
- MainNet chain ID: `47763`
- TestNet T4 chain ID: `12227332`

## Highlights

- Merged Reth upstream `2.7.0` (185 commits after `4dd0cc021a`) while preserving the Neo X
  engine, RPC, dBFT, DKG, and Anti-MEV layers.
- Synced the Neo X Geth oracle to `9dec1dc364`; MainNet/TestNet genesis files now match its bytes
  and keep the same genesis block hashes.
- Fixed the validator DKG lifecycle: preparations survive canonical head advances, and a rejected
  Submit restores `Ready` instead of stranding a prepared task.
- Fixed managed DKG share matching to use round + aggregate global key, removing the
  `managed Neo X DKG share does not match canonical epoch` failure on normal block advances.
- Avoided re-installing the DKG signer shares on every block by hashing the settled canonical
  inputs instead of the canonical head.
- Fixed nine `cargo audit` vulnerabilities by updating `quinn-proto` to 0.11.18 and `rustls` to
  0.23.46. `cargo audit` now reports zero vulnerabilities.

## Validation

- Exact-candidate G8 gate on `f361db8c7f`: **1,402 blocks**, height 2,404 → 3,805, DKG round
  1 → 2, identical 128-byte aggregate commitment, 0 reorgs, 0 transient RPC errors.
- Current-epoch Envelope decryption: inner transaction mined at block 525, status 1.
- Cross-epoch Envelope decryption: a saved round-1 Envelope sent after round 2 was decrypted and
  mined at block 3,656, status 1.
- Exact-candidate faults: 60-second prover delay, Reth SIGKILL/restart, missing-receipt Share
  replacement; chain reached round 2.
- 427 Neo X tests pass; clippy `-D warnings`; nightly fmt clean.
- Datadir compatibility: a 2.7 G8 datadir and its DKG keystore opened under 2.5.2 and activated
  the validator signer; the release binary opened the existing MainNet archive datadir.

## Artifacts

Linux and Windows x86_64 release binaries are published with `manifest.json`; the manifest carries
the exact size and SHA-256 for each artifact.

## Known exceptions

- The user authorized an agent-conducted security review in place of an independent third-party
  review on 2026-10-20. This is a recorded risk acceptance; it is not a third-party audit.
- A full clean-datadir MainNet sync from genesis continues after release. Peer connection and the
  Headers pipeline are verified; archive-datadir sync is verified.
- aarch64 artifacts were not built in this release session.
- Registry/container publication remains a maintainer action.

## Upgrade notes

- Back up the datadir before upgrading.
- Reth 2.7 can open an existing 2.5 datadir. A downgrade from 2.7 to 2.5 opened the datadir and
  loaded the validator/DKG keystore in testing, but live downgraded consensus was not run; restore
  from backup if a downgrade is required.
- Do not run mixed `Pkcs7Strict` activation states until the governance activation procedure is
  applied coherently across validators.
