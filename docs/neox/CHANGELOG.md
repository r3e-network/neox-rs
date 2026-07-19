# neox-rs changelog

Neo X release history for `neox-rs`, the Neo X execution and full-node client built on Reth. Reth's
own version history is upstream; this file tracks the Neo X layer.

## neox-v2.4.1 — 2026-07-19

First tagged Neo X release, built on Reth `2.4.1`
(`9ebad6c4b77e053cd15de448e8a402d40905e58e`); behavior oracle is Neo X Geth
`a0c80295ab2c7a6d0bc218e4bc85270f5610948c`.

### Status

- **Non-validator full node: operational and verified.** A full MainNet sync (~7.15M blocks) executes
  with zero state-root mismatch, and block hashes and state roots match the public reference at
  checkpoints spanning the pre-DKG, DKG (3,623,040), and Anti-MEV (3,749,760) eras. dBFT ECDSA quorum
  and BLS12-381 threshold verification are confirmed on live MainNet blocks.
- **Validator mode: pre-release.** The live private-network fault gates (view-change, prover delay,
  transaction replacement, Anti-MEV decryption, reorg) and an independent protocol/security review are
  not complete. An all-Reth validator network converges and finalizes dBFT blocks at a 5-of-7 quorum,
  but sustained production still hits a dBFT recovery-state merge conflict; see the reports in
  [`reports/`](reports/). Do not run this release as a validator or claim MainNet validator
  compatibility.

### Implemented

- Canonical MainNet and T4 TestNet chain specs, genesis, fork schedule, and bootnodes.
- V0/V1/V2 dBFT header codecs; ECDSA quorum and BLS12-381 threshold finality.
- Neo X system-contract execution, Policy-aware transaction pool, and Governance/Policy/KeyManagement
  storage models verified against live testnet storage.
- BEACON/2 and dBFT wire protocols; missing-transaction recovery; timeout view changes; recovery
  messages; automatic primary proposals; final block import.
- Anti-MEV Envelope parsing, TPKE share verification/aggregation, and reconstruction with fallback;
  5-of-7 DKG (PVSS/ECIES/share/reshare/recover) with a crash-safe, validator-bound encrypted keystore
  and a one-shot Geth-keystore migration utility.
- `neox-rs` full-node binary; custom RPC (`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`,
  `eth_getCachedTransaction`); Prometheus metrics; container packaging; snapshot backup/restore.

### Changes in this release

- Rename the node binary and package from `neox-reth` to `neox-rs`.
- fix(dBFT): the primary now attaches the parent reseal witness for ECDSA parents, and propagated-block
  import respects dBFT instant finality (import only head-extending blocks) — an all-Reth validator
  network now converges instead of stalling at block 1.
- fix(rpc-differential): compare head-only Policy RPC methods only when both nodes share the checked
  height.
- Verification: live-MainNet BLS threshold consensus test, codec fuzz sweeps, full-sync state-consistency
  and live-node run reports, an internal audit (findings NX-1…NX-8), and an all-Reth private-network
  report.

### Known issues

- Sustained all-Reth validator block production stalls on a dBFT recovery-state merge conflict
  (validator mode is pre-release).
- Mixed-client (Neo X Geth) and live ZK-v1 Anti-MEV gates require the Neo X Geth fork and
  network-approved ZK ceremony artifacts, which are external inputs.
