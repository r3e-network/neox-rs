# Neo X v2.8.0 release notes — 2026-11-16

## Release

- Tag: `neox-v2.8.0`
- Candidate code: `3c4d335cee`
- Reth base: `2.8.1` (`0e9de4b95dc010d9d54c1ea17884102a9d717669`, last commit before the
  evm2 switch)
- Neo X Geth oracle: `f5d768e8a9` (`bane-main`, `0.7.0-dev`)
- MainNet chain ID: `47763`
- TestNet T4 chain ID: `12227332`

## Highlights

- Merged Reth upstream through `0e9de4b95d` (2.8.1) while preserving the Neo X engine, RPC,
  dBFT, DKG, and Anti-MEV layers. The evm2 switch (`9d1638f328`) and its 243 follow-up commits
  remain deliberately unmerged until the Neo X EVM is ported to evm2; four post-switch
  correctness fixes were backported instead (engine recreated-account cache, safe-no-sync
  rollback bound, trie proof target grouping, static-file unwind error context).
- Synced the Neo X Geth oracle to `f5d768e8a9` (255-commit delta). MainNet/T4 genesis,
  `antimev/`, and `crypto/tpke/` are byte-unchanged, so prior cross-implementation vectors stay
  valid.
- **Consensus fix (live rule)**: from Prague, calls to an EIP-7702 delegation designator whose
  target is blacklisted now revert before the delegated code runs (Geth `a3a768dff4`, #678).
  Prague is active on MainNet and T4.
- **P2P fix**: `dbft/0` messages up to 10 MiB are accepted (Geth `242f59a021`, #655); the old
  4 MiB cap would have disconnected honest peers on large Recovery messages.
- Pre-Amsterdam alignment: the dBFT seal hash commits `blockAccessListHash`/`slotNumber` when
  present (Geth `0b58eff7bc`, #679), the parent beacon root is pinned by fork, and a non-zero
  post-Amsterdam slot number is rejected (Geth `b6c5233579`). No behavior change on current
  public networks.
- Local dBFT participation pauses while an announced peer is more than one block ahead
  (Geth `cc7af690d0`); `dbft/0` relay stays up. `--txpool.amevcache` semantics documented:
  RPC submissions only, remote gossip keeps relaying.

## Validation

- **Full MainNet replay** with the candidate build: genesis → 8,321,108 in ~1h53m, zero errors.
  32,570/32,570 checkpoint block hashes match the oracle-verified references (22 fork-boundary
  checkpoints + the complete 8,063,175–8,096,057 range from the v2.7.0 clean sync); all
  fork-boundary state roots match (DKG 3,623,040, EthSig/AMEV 3,749,760, Prague/Cancun
  4,720,788, 8,000,000, 8,039,772). The node then followed live dBFT consensus. See
  [`reports/2026-11-16-MAINNET-REPLAY.md`](../reports/2026-11-16-MAINNET-REPLAY.md).
- All Neo X crate test suites pass (441 tests, 0 failures); clippy clean; nightly rustfmt clean.
- Delta audit reports: [`reports/2026-11-16-GETH-DELTA.md`](../reports/2026-11-16-GETH-DELTA.md),
  [`reports/2026-10-29-GETH-DELTA.md`](../reports/2026-10-29-GETH-DELTA.md).

## Artifacts

CI builds `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin`
bundles with SHA-256 checksums when the tag is pushed, and attaches them to the GitHub release.

## Known exceptions

- The extended PrepareRequest format and BEACON3 remain unported: the
  `neoXPrepareRequestExtensionBlock` fork is privnet-only (block 5) and not scheduled on public
  Neo X networks. Peers negotiate `beacon/2`, so interop is unaffected.
- The 243-commit post-evm2 Reth backlog is intentionally held; only reviewed backports are
  taken. See [`reports/2026-10-28-UPSTREAM-SYNC-RETH-2.8.md`](../reports/2026-10-28-UPSTREAM-SYNC-RETH-2.8.md).
- Windows artifacts are not built by CI; build from source on Windows using the documented MSVC
  environment.
- Registry/container publication remains a maintainer action.

## Upgrade notes

- Back up the datadir before upgrading.
- This release replays MainNet identically to 2.7.0; no state migration is required. Downgrade
  compatibility was not re-verified for 2.8.0 — restore from backup if a downgrade is required.
- The EIP-7702 delegated blacklist rule is consensus-critical: all nodes should upgrade before
  submitting or validating Prague-era transactions that touch delegated blacklisted targets.
