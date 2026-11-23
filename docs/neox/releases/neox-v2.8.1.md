# Neo X v2.8.1 release notes — 2026-11-23

## Release

- Tag: `neox-v2.8.1`
- Candidate code: `f3c50fe5a4`
- Reth base: `2.8.1` (`0e9de4b95dc010d9d54c1ea17884102a9d717669`, unchanged from v2.8.0)
- Neo X Geth oracle: `da96fc385d` (`bane-main`, `0.7.0-dev`)
- MainNet chain ID: `47763`
- TestNet T4 chain ID: `12227332`

## Highlights

- **Consensus fix (live rule)**: Geth `8410f2bfba` (#683) removed the Prague enforcement that a
  header's `requestsHash` equal `EmptyRequestsHash`. The geth block builder now seals real
  `CalcRequestsHash` values whenever requests are non-nil, so this client now checks presence only.
  Without this fix, a quorum-sealed header carrying a real requests hash would fail-stop this node.
- Reth upstream backlog re-audited through `95b1b67496` (43 new commits since v2.8.0, all
  post-evm2): no Neo X protocol-critical fix; classification in
  [`reports/2026-11-23-GETH-DELTA.md`](../reports/2026-11-23-GETH-DELTA.md). Optional RPC DoS
  bounds (`eth_getLogs` range cap, batch size cap, `simulateV1` parsing, builder validation cached
  reads) remain recommended hardening for public RPC endpoints.
- `antimev/`, `crypto/tpke/`, and both genesis files are byte-identical between oracle tips
  `f5d768e8a9` and `da96fc385d`, so all cross-implementation vectors remain valid.

## Validation

- All Neo X crate test suites pass (442 tests, 0 failures), including the new
  `prague_accepts_any_non_nil_requests_hash` oracle pin; clippy clean; nightly rustfmt clean.
- The replay node relaunched with the candidate build and immediately followed live dBFT consensus
  (head ~8.38M, 21 proposals verified against execution post-state commitments in the first
  minutes, zero errors). The full MainNet replay evidence from v2.8.0 (genesis → 8,321,108, zero
  divergence, 32,570/32,570 checkpoints) remains the base correctness record; the requestsHash
  rule change is a strict relaxation, so the replayed prefix is unaffected.
- Delta audit report: [`reports/2026-11-23-GETH-DELTA.md`](../reports/2026-11-23-GETH-DELTA.md).
- Protocol completeness re-verification:
  [`reports/2026-11-17-PROTOCOL-COMPLETENESS.md`](../reports/2026-11-17-PROTOCOL-COMPLETENESS.md)
  (2026-11-23 update section).

## Artifacts

CI builds `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and `aarch64-apple-darwin`
bundles with SHA-256 checksums when the tag is pushed, and attaches them to the GitHub release.

## Known exceptions

- The extended PrepareRequest format and BEACON3 remain unported: the
  `neoXPrepareRequestExtensionBlock` fork is privnet-only (block 5) and not scheduled on public
  Neo X networks. Peers negotiate `beacon/2`, so interop is unaffected.
- The post-evm2 Reth backlog is intentionally held; only reviewed backports are taken.
- Windows artifacts are not built by CI; build from source on Windows using the documented MSVC
  environment.
- Registry/container publication remains a maintainer action.

## Upgrade notes

- Back up the datadir before upgrading.
- The consensus change is a relaxation (accepting more headers), so a v2.8.1 node that is fed a
  header with a real requests hash will no longer stall; v2.8.0 nodes will reject such headers.
  Upgrade promptly once validators begin sealing non-empty request hashes.
- No state migration is required; the chain data is unchanged from v2.8.0.
