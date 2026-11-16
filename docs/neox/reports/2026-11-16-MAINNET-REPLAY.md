# Mainnet Full Replay Verification — 2026-11-16

## Objective

Replay the entire Neo X mainnet from genesis with the current build (all four
2026-11-16 delta-audit fixes applied) and verify full state consistency against
independent, oracle-verified checkpoints.

## Build

- Binary: `target\release\neox-rs.exe`, commit `e61ba40e93` + working tree
  (dbft/0 10 MiB cap, Amsterdam seal-hash fields, fork-pinned parentBeaconRoot /
  slotNumber rules, EIP-7702 delegated blacklist revert from Prague)
- Node flags identical to the prior v2.7.0 full-sync run: fresh datadir
  `outputs\replay-20261116\datadir`, `--chain neox-mainnet --http.port 18546
  --authrpc.port 18556 --port 30316 --nat none --ipcdisable`

## Replay Timeline (UTC)

| Time | Event |
|---|---|
| 09:50 | Node started at genesis, peers connected, live head 8,321,108 |
| 11:23 | Headers stage complete (8,321,108 headers, ~1,100 headers/s) |
| 11:36 | Bodies + SenderRecovery complete |
| 11:43 | Execution complete (all 8.32M blocks re-executed), all 13 stages finished |
| 11:43+ | Live dBFT follow mode, verifying each new proposal against post-state commitments |

Total replay time: ~1h53m. **Zero ERROR lines in the entire log.**

## Verification Results

### 1. Block hash differential — 32,570 / 32,570 matched, 0 mismatches

Checkpoint sources (both previously verified against the neox-geth oracle):
- `checkpoints-static.txt`: 22 heights from `outputs\review-datadir`
  (oracle-verified 2026-10-28), bracketing every fork boundary:
  genesis, DKG 3,623,040, EthSig/AMEV 3,749,760, Prague/Cancun 4,720,788
  (ts 1,763,000,000), up to 8,039,772.
- `checkpoints-live.txt`: all 32,548 canonical block hashes from the v2.7.0
  clean full-sync log, heights 8,063,175–8,096,057.

Comparison method: `verify-checkpoints.ps1` queries the replay node's
`eth_getBlockByNumber` for every checkpoint height and compares the canonical
hash. Dense run (`-LiveStride 1`): `checked=32570 matched=32570 mismatched=0
not_synced=0`.

### 2. State root differential — all fork boundaries match

Header state roots at heights 3,623,040 / 3,749,760 / 4,720,788 / 8,000,000 /
8,039,772 compared between the oracle-verified review-datadir and the replay
node: **all MATCH**.

The Execution and MerkleExecute stages completed for the full chain without any
state-root mismatch, proving the recomputed state root equals the header state
root for every replayed block — including all Prague-era blocks exercising the
new EIP-7702 delegated blacklist rule.

### 3. Live consensus agreement

After replay, the node follows the live chain via dBFT: 226 proposals verified
("Verified Neo X proposal execution and post-state commitments") and finalized,
tracking the live head (8,322,109 and counting) with validator set = 7.

## Conclusion

neox-rs with the current audit fixes replays the entire Neo X mainnet
(genesis → 8,321,108) with block hashes, state roots, and live consensus fully
consistent with the neox-geth oracle and the network. Protocol conformance
confirmed end-to-end.

## Artifacts

- `replay.log` — full node log
- `checkpoints-static.txt`, `checkpoints-live.txt` — checkpoint sets
- `verify-checkpoints.ps1`, `verify-results.txt` — differential harness + dense results
- `monitor.log` — periodic progress/verification snapshots
- `datadir\` — fully replayed mainnet state (kept for further audits)
