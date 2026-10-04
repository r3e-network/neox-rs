# Phase 2C: Geth BAL Integration Investigation - 2026-10-01

**Date**: 2026-10-01
**Scope**: Determine whether Geth's BlockAccessList (BAL) integration into dBFT/beacon
requires Rust-side changes before the Geth oracle baseline can advance.

---

## Verdict

**No immediate action required. The two clients are already aligned.**

BAL is the Amsterdam-fork (EIP-7928) consensus feature, and on both sides every BAL
code path is gated on `IsAmsterdam`. Neo X genesis pins `amsterdamTime: null`, so the
entire BAL surface is currently dormant on both clients. The Rust-side validation logic
already exists, inherited from the Reth 2.5.2 sync.

The Geth baseline can advance to `9dec1dc364` without any Rust consensus change. The
baseline update itself remains deferred to the next scheduled oracle sync.

---

## Evidence

### 1. BAL is Amsterdam-gated on the Geth side

`72579cf19c` (BAL into DBFT/PreBlock) attaches the access list only when Amsterdam is
active:

```go
// consensus/dbft/dbft.go
if dbftBlock.accessList != nil && block.AccessList() == nil &&
    c.chain.Config().IsAmsterdam(block.Number(), block.Time()) {
    block = block.WithAccessList(dbftBlock.accessList)
}
```

`9c4410e221` (beacon BAL fetching) mirrors the same gate in header validation:

```go
// beacon/impl/fetcher/block_fetcher.go
amsterdam := chain.Config().IsAmsterdam(header.Number, header.Time)
if amsterdam {
    if header.BlockAccessListHash == nil { ... reject ... }
```

### 2. BAL is Amsterdam-gated on the Rust side (already inherited)

`crates/neox/consensus-engine/src/lib.rs:138-150` (from the Reth 2.5.2 sync, commit
`e5b80c423f`) validates the same header field with the same semantics:

```rust
if self.chain_spec.is_amsterdam_active_at_timestamp(header.timestamp) {
    if header.block_access_list_hash.is_none() {
        return Err(ConsensusError::BlockAccessListHashMissing)
    }
    ...
} else {
    if header.block_access_list_hash.is_some() {
        return Err(ConsensusError::BlockAccessListHashUnexpected)
    }
```

### 3. Amsterdam is not activated on Neo X

```json
// crates/neox/chainspec/res/genesis_mainnet.json
"shanghaiTime": 0, "cancunTime": 1763000000,
"pragueTime": 1763000000, "osakaTime": 1782700000,
"amsterdamTime": null
```

With `amsterdamTime: null`, `is_amsterdam_active_at_timestamp` is always false today:
both clients reject any block carrying a BAL hash and accept any block without one.

### 4. The remaining Geth BAL commits are non-consensus

| Commit | Subject | Classification |
|---|---|---|
| `23507eac0d`, `b020bc1659`, `1e584ef1d8`, `9f2af3fa2a` | EIP-7928 mainline construction/validation | Upstream, arrives via Reth, not via Geth porting |
| `9c4410e221` | beacon BAL fetching | Network optimization, Amsterdam-gated, dormant |
| `72579cf19c` | BAL into DBFT/PreBlock | Plumbing, Amsterdam-gated, dormant |
| `07ad807214` | beacon withdrawals hash check | Shanghai semantics; Rust side already validates `withdrawals_root` (consensus-engine lib.rs:111-113) |

---

## What Would Change If Amsterdam Is Activated Later

When Neo X governance sets an `amsterdamTime`:

1. **Header validation** activates on both sides automatically (code already in place
   on both clients) — no porting needed.
2. **Payload building**: the Reth payload builder (2.5.2) already constructs BALs
   (EIP-7928 support landed upstream in the 2.5.2 range); Neo X uses the standard
   builder, so proposals will carry BAL hashes automatically.
3. **Sync layer**: a syncing Neo X node may want the Geth-style beacon BAL fetching
   (`FetchBALs`) so full bodies can be validated before BAL availability; this is an
   optimization, not a correctness requirement, because Engine-API import validates
   the BAL hash against execution locally.
4. **Action item at activation time**: re-run the cross-client differential gate
   (`scripts/neox-rpc-differential.py`) plus a mixed-client dBFT epoch gate with both
   clients on Amsterdam.

None of this blocks the oracle baseline advance.

---

## Oracle Baseline Recommendation

- Advance the Geth oracle baseline to `9dec1dc364` (715 commits) at the next scheduled
  sync — **no code change required**.
- The dBFT-adjacent Geth commits in the range are: gas-counter removal (`7c7b29a21e`),
  proposal-waiting optimization under pathdb pruning (`cc7af690d0`), FinalizeAndAssemble
  context plumbing (`876e705eb3`), and error-handling cleanup (`84aae6942d`,
  `1518b4b699`). All are Geth-internal; the Rust dBFT engine is an independent
  implementation and tracks the wire/consensus semantics, which are unchanged.

---

## Status

- [x] BAL consensus impact determined (Amsterdam-gated, dormant)
- [x] Rust-side validation verified in place
- [x] Geth-side gating verified identical
- [x] Beacon fetching classified as optimization
- [x] Oracle advance unblocked (deferred to scheduled sync)
- [ ] Amsterdam activation checklist (future, when governance schedules the fork)
