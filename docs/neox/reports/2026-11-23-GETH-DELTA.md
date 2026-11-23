# Upstream delta audit — 2026-11-23

Scope: re-synchronize against both upstreams since the v2.8.0 audit (2026-11-16) and confirm the
Rust client still matches the Neo X protocol.

- Oracle: `bane-labs/go-ethereum@bane-main` `f5d768e8a9` → `da96fc385d` (**3 commits**)
- Reth: `c09a02d4e0` → `95b1b67496` (**43 commits**, all post-evm2-freeze backlog)

## Geth bane-main delta (3 commits)

### `8410f2bfba` / `da96fc385d` — consensus/dbft: remove the empty request hash enforcement (#683)

**Live consensus change.** `DBFT.verifyHeader` no longer rejects a Prague header whose
`requestsHash` differs from `types.EmptyRequestsHash`; only presence is checked (nil before
Prague, non-nil from Prague on). The block builder now seals
`CalcRequestsHash(requests)` whenever requests are non-nil, so headers carrying a real requests
hash are expected to appear.

**Action (applied):** removed the value check in
`crates/neox/consensus-engine/src/lib.rs::validate_neox_header_fields` and the now-dead
`NeoXConsensusError::InvalidRequestsHash` variant. Presence checks on the proposal path
(`validate_ethereum_proposal_header`) and the sealed-header path (reth's fork validation) are
unchanged and still match geth. Pinned by the new `prague_accepts_any_non_nil_requests_hash` test:
a Prague-active header with a non-empty `requestsHash` validates.

Without this change a quorum-sealed header with a real `CalcRequestsHash` value would have
fail-stopped this client; this is exactly the divergence class the previous audit flagged.

### `7843c3dbbf` — beacon/eth: revert #670

Reverts engine-API/catalyst plumbing that passed raw `requests [][]byte` into
`ExecutableDataToBlock`; the functions take a precomputed `requestsHash *common.Hash` again.
Confined to `beacon/`, `eth/catalyst/`, and the beacon miner worker — **no `core/` or
`consensus/dbft` changes** (verified: `git diff` between the tips shows only the 3-line dbft.go
removal under those trees). Neo X runs dBFT consensus and never uses the beacon engine path.

**Action:** none required.

### Verification of the unchanged surface

- `antimev/` and `crypto/tpke/` are byte-identical between the two tips, so all vendored
  cross-implementation vectors remain valid.
- MainNet/T4 genesis untouched.

## Reth delta (43 commits, `c09a02d4e0`..`95b1b67496`)

All 43 sit on the post-evm2 line that the fork deliberately does not merge. Classification:

- **No Neo X protocol impact**: none touches consensus rules, the revm call path, or fork gating in
  a way the frozen base lacks. The two `deps: update evm2` bumps do not apply to the revm freeze.
- **Dev-tooling fixes, not backported**: `38aef3469c` (db get MDBX subkey reads), `6ca2c082ab`
  (era-download prune checkpoints), `efae8fb8bc` (manual `stage unwind` limits).
- **Refactor-heavy with no observed misbehavior on Neo X paths, not backported**:
  `8fa8b31ea2` (changeset range bounds; large provider refactor), `fba8e16e3f`/`0e57f25915`/
  `d7ac51bb89` (in-memory state consolidation), `4b1238164c`/`7ad95de2c1` (TreeState).
- **RPC DoS bounds — recommended candidates, still open**: `85c7066331` (bound `eth_getLogs`
  ranges by response size), `fad9eb6091` (cap unlimited batches by request size), `725f1b7773`
  (bound `simulateV1` request parsing), `53b5db1c3b` (bound builder validation cached reads by
  gas). These extend the previously recommended RPC resource-exhaustion bounds; backporting them
  to the frozen RPC tree is a hardening decision, not protocol alignment, and stays a
  deliberate operator choice (public RPC endpoints should consider it).
- **Perf/features/deps/CI**: no action.

The full MainNet replay (2026-11-16, zero divergence) remains the operative correctness evidence
for the frozen base; none of these 43 commits fixes a defect that replay or live-follow exposed.

## Result

- Oracle parity restored after the #683 consensus change; everything else already aligned.
- Both baselines in `docs/neox/source-baseline.toml` updated
  (geth `da96fc385d`/258, reth observed tip `95b1b67496`/287).
- Verification: full Neo X test suite re-run green; nightly rustfmt clean.
