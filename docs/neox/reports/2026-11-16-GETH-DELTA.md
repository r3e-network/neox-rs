# Neo X delta audit — Reth `c09a02d4e0`, Neo X Geth `f5d768e8a9` (2026-11-16)

Continuation of [2026-10-29-GETH-DELTA.md](2026-10-29-GETH-DELTA.md) and
[2026-10-28-UPSTREAM-SYNC-RETH-2.8.md](2026-10-28-UPSTREAM-SYNC-RETH-2.8.md).

## New tips

| Remote | Previous | New | Delta |
|---|---|---|---|
| `paradigmxyz/reth` main | `f1cc50e4fc` | `c09a02d4e0` | 241 new commits, all post-evm2 |
| `bane-labs/go-ethereum` bane-main | `b51d712adf` | `f5d768e8a9` | 255 commits (bane PRs #655/#667/#673/#675/#678/#679 + upstream v1.17.7 merge) |

The Reth backlog past the evm2 switch is now 243 commits (244 from the merged `0e9de4b95d` base);
upstream released 2.9.0, 2.10.x, and 2.11.0 in the range. The evm2 freeze decision is unchanged
(see the blocker table in the 2026-10-28 report).

## Neo X Geth `b51d712adf..f5d768e8a9`

`antimev/`, `crypto/tpke/`, `config/genesis_mainnet.json`, and `config/genesis_testnet.json` are
byte-unchanged in the range, so every recorded cross-implementation divergence
(`docs/neox/source-baseline.toml`) remains valid and no re-export is needed. The only scheduled
fork change is `neoXPrepareRequestExtensionBlock: 5` in the four `privnet/*/genesis_privnet.json`
files, which are not vendored.

### Commit disposition (bane-specific, upstream v1.17.7 noise omitted)

| Commit | What Geth changed | Rust |
|---|---|---|
| `242f59a021` (#655) | Extended `PrepareRequest` carrying the full transaction list instead of hashes, gated by the new optional `neoXPrepareRequestExtensionBlock` fork; `dbft/0` message cap raised 4→10 MiB; BEACON1 removed, BEACON3 added (blob request/response messages); recovery message carries the extension flag. | Fork is privnet-only (block 5); MainNet/T4 do not schedule it, so the V0 hash-list format stays authoritative and no port is needed yet. The 10 MiB cap raise applies to every peer regardless of the fork, so [`DBFT_MAX_MESSAGE_SIZE`](../../crates/neox/network/src/dbft.rs) was raised to match. BEACON3 support is pending work for whenever the extension is scheduled. |
| `0b58eff7bc` (#679) | `encodeUnchangeableHeader`/`EncodeSigHeader` append `BlockAccessListHash` and `SlotNumber` to the seal encoding when the header carries them. | **Divergence fixed.** [`unsigned_header`](../../crates/neox/consensus/src/validation.rs) cleared the fields; it now keeps them, which is byte-identical on current networks (fields are always `None`) and matches the oracle once Amsterdam sets them. Test `seal_commits_to_amsterdam_fields` pins the new behaviour. |
| `b6c5233579` | Header validation pins `parentBeaconRoot` by fork: zero hash from Amsterdam, empty root before; post-Amsterdam `slotNumber` must be zero. | **Divergence fixed** (dormant): consensus-engine validation now selects the expected root by fork and rejects non-zero post-Amsterdam slot numbers (`NeoXConsensusError::InvalidSlotNumber`). Cancun-only behaviour is unchanged. |
| `6687f1c635`, `20b0ec7890` | Upstream interpreter dispatch rewrites (PGO switch, folded DUP/SWAP). | Perf only; no semantic change. |
| `b668cd90cd` | Test generator confirms MCOPY is gated on `IsNeoXDKG`, not Cancun. | Already matched: `crates/neox/evm` activates MCOPY (and the Cancun precompiles) at the DKG fork. |
| `49654299a0` | Miner sends `TargetGasLimit: 60M` (miner default) instead of 0 in forkchoice payload attributes. | Geth-internal payload-attribute plumbing; block gas limits are governed by header rules that this client already validates. No action. |
| `3c48807e63`, `8b719ce148`, `5337d5817d` (#675) | Blob fetch: search EL first, pending-blob map cache, engine-API switch formatting. | Geth-internal downloader/miner plumbing; this client's blob store is searched before any network request by construction. No action. |
| `652aa73f0b` (#673) | Shutdown order fix; force stop on keystore round mismatch. | Geth process-level liveness. The Rust node's dBFT loop already exits on keystore round regression. No action. |
| `d33029220c` | Empty system-contract check condition in Amsterdam fork. | Amsterdam-gated, dormant. |
| `88e7fc01fc`, `5787932415`, `b3cca6de0f` | `beacon` protocol versions now `[BEACON2, BEACON3]` (lengths 10/12); NewBlockPacket renamed NewBlockPacket3. | Rust advertises `beacon/1`+`beacon/2`; peers negotiate `beacon/2`, so interop is unaffected today. BEACON3 (two new blob messages) is pending work tied to the PrepareRequest extension. |
| `1161cb3eb3` (#667) | Upstream geth v1.17.7 merge (Amsterdam/BAL machinery, parallel execution, PGO interpreter). | Amsterdam paths remain dormant (no public network schedules Amsterdam); everything else is upstream-internal. |
| `a3a768dff4` (#678) | From Prague, all four call kinds revert when the target's code is an EIP-7702 designator whose delegated address is blacklisted (`isBlacklistedDelegation`). | **Divergence fixed.** Prague is active on MainNet and T4, so this is a live rule: the Rust call-frame blacklist only checked the target itself. [`NeoXPrecompiles::run`](../../crates/neox/evm/src/factory.rs) now resolves the delegation target (journal code first, then the DB) and reverts when it is blacklisted; test `blacklisted_delegation_reverts_calls_from_prague` pins both directions. |

### Applied in this audit

1. `DBFT_MAX_MESSAGE_SIZE` 4→10 MiB (`crates/neox/network/src/dbft.rs`): the oracle now treats
   up to 10 MiB as compliant, and a Recovery message or extended proposal can legitimately exceed
   4 MiB; the old cap would disconnect an honest geth peer as a protocol violation.
2. Seal hash commits to the Amsterdam fields (`crates/neox/consensus/src/validation.rs`): no-op on
   current networks, mandatory before Amsterdam.
3. Fork-pinned `parentBeaconRoot` and zero post-Amsterdam `slotNumber`
   (`crates/neox/consensus-engine/src/lib.rs`): no-op on current networks, aligns header
   validation with `verifyHeader`.
4. EIP-7702 delegated blacklist (`crates/neox/evm/src/factory.rs`): Prague is live, so a call to
   an address delegating to a blacklisted target now reverts instead of executing the delegated
   code. The blacklist lookup was refactored into `policy_blacklisted`, shared by the direct and
   delegated checks.

`reth-neox-consensus`, `reth-neox-consensus-engine`, `reth-neox-network`, and `reth-neox-evm` test
suites pass (19/14/47/34 tests).

## Reth `f1cc50e4fc..c09a02d4e0`

Nothing was merged. Per the documented freeze, the fork stays on the revm base until the Neo X EVM
ports to evm2; the backlog grew to 243 post-switch commits. Tree-wide refactors in the range
(#28506 `chain-state` in_memory split, #28507 `engine` tree-handler split, #28553 soketto→
tokio-tungstenite) make naive cherry-picks increasingly conflict-prone, so the recommended posture
is: keep the freeze, and backport only fixes that are both security-relevant and mechanically
portable. Candidates observed in the range, by area:

- **RPC resource-exhaustion bounds** (highest value): #27716 getProof/getMultiProof key caps,
  #28314 callMany/trace_callMany bounds, #28315 default eth_call gas cap, #28253/#28386
  callBundle/simBundle bounds, #28438 pending-nonce fast path.
- **P2P/DoS hardening**: #28414 capability overflow rejection, #28280 disconnect payload bounds,
  #28364 pending pool import byte bound, #28180/#28232 extra-field tolerance, #28360/#28361/#28362
  peer-session and re-announcement fixes.
- **Storage correctness**: #28549 history reads floored at lowest changeset, #28376 interrupted
  genesis init resume, #28405 interrupted jar init resume, #28370 reorg static-file truncation.
- **Local security**: #28326 IPC socket permissions, #28247 datadir path-escape rejection.

The delta above the 2026-10-28 baseline adds no urgency to the evm2 port decision itself; none of
the Neo X consensus surfaces (dBFT, antimev, TPKE) are touched by the range.

## Baseline update

`docs/neox/source-baseline.toml` now pins the new observed tips and records this audit.
