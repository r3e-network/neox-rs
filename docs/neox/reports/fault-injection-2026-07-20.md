# Neo X validator fault-injection gates — 2026-07-20

Exercises the `neox-rs` validator runtime under injected faults on a live seven-validator private
network (private `chainId`, pure-ECDSA regime, the seven deterministic test validators in both
`config.dbft.standbyValidators` and the Governance `currentConsensus` storage). Each node is a
separate process with its own datadir, validator key, fixed devp2p key, and a full trusted-peer mesh.
This is the harness the earlier audit flagged as the prerequisite for the liveness/robustness findings
(NX-2…NX-8); the two fork-id defects below were found and fixed with it.

## Gate A — primary crash and view change

Killing a validator (`SIGKILL`) mid-round leaves the remaining six (≥ the 5-of-7 quorum) producing.
The round whose primary died times out and advances to view 1: survivor logs show
`ChangeView` for the stalled height and then `reached preparation quorum … view: 1` /
`reached commit quorum … view: 1`, and the chain continues with all survivors in hash agreement
(e.g. blocks 23 and 30 identical across nodes after the kill). Production slows to the view-change
cadence while a validator is absent, then returns to the block period once it rejoins.

## Gate B — transaction inclusion via a single node

A signed value transfer submitted to exactly one node's RPC (not the primary) is gossiped, included,
and executed: it lands in a block (observed block 394), every node reports the identical block hash,
and the recipient balance updates network-wide. Transactions below the Neo X policy tip minimum are
rejected at submission with the policy error, confirming the Policy-aware pool is enforced on the
validator path.

## Gate C — crash recovery and pipeline backfill (two fork-id defects fixed)

Restarting a validator that has fallen behind (here 249 blocks: head 5194 while the network was at
5443) surfaced two defects that together stranded the node permanently at its stale head, proposing
blocks nobody wanted:

1. **Beacon-protocol fork-id rejection.** The beacon handshake advertised `ChainSpec::fork_id` but
   validated with `fork_filter(head)`. On a spec without a Paris fork these diverge once a time fork
   activates, so every peer closed the restarted node's beacon streams with `ForkIdRejected`. Fixed by
   advertising `fork_filter(head).current()` and accepting any hash in the spec's reachable fork-id
   family (chain identity is still enforced by the genesis-hash and network-id checks). Commit
   `c931360c30`.

2. **Eth-protocol fork-id mismatch → no pipeline backfill.** reth's core eth-protocol `Status`
   advertises the unfolded `ChainSpec::fork_id` while validating with the folded
   `fork_filter(head).current()`, so on the same non-Paris spec every eth session was rejected and the
   node had **zero eth peers** — reth's staged-sync pipeline had nobody to download the missing blocks
   from. Steady-state production hid this (blocks arrive as head+1 over the beacon protocol), but a
   node needing backfill was stuck. Fixed at the Neo X network-builder layer by advertising the folded
   fork id on the eth `Status` as well; on the built-in MainNet spec (which has Paris) the two values
   are already identical, so live behavior and Neo X Geth eth-protocol interop are unchanged.

After both fixes, a validator restarted 249 blocks behind runs the full reth pipeline
(`stage=Headers … Received headers total=247 from_block=5441`, then Bodies/SenderRecovery/Execution/
MerkleExecute), reaches the network head within ~20 s, and rejoins consensus (`peers=6`, adding
canonical blocks). Its backfilled state is byte-identical to the network (block 5300 hash matches
across nodes). The beacon-session churn is gone (0 disconnects after the fix vs. 74 before).

## Gate D — whole-cluster restart

Restarting all seven validators at once from their persisted datadirs (heads split by a few blocks
plus one far-behind node) reconverges to a single canonical head and resumes lockstep production once
every node runs the fork-id fixes, exercising cross-node reconciliation of differing restart heads.

## Scope and remaining work

These gates run in the pre-anti-MEV (ECDSA) regime. Not yet covered: prover-delay behavior on the
live ZK path, transaction-replacement/Anti-MEV decryption during production, and reorg beyond a single
validator drop. The two fork-id defects were latent for any non-Paris custom chain; MainNet and
TestNet (both with a Paris fork and monotone fork schedules) are unaffected, but the fixes make
crash-recovery correct for private networks and any future custom Neo X deployment. Validator mode
remains pre-release pending the remaining gates and an independent security review.
