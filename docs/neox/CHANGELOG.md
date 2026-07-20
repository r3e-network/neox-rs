# neox-rs changelog

Neo X release history for `neox-rs`, the Neo X execution and full-node client built on Reth. Reth's
own version history is upstream; this file tracks the Neo X layer.

## neox-v2.4.1-rc.4 — 2026-07-20

This pre-release follows `rc.3` and carries the DKG runtime liveness fixes from the `neox` integration
branch. It is still a validator pre-release; it is not a MainNet validator release.

### Changes in this release

- fix(dkg): release the MDBX read provider before invoking the external prover, so a long proof does
  not hold a canonical read transaction open.
- fix(dkg): move external proving to an abortable asynchronous worker and poll readiness from the
  canonical heartbeat, with at most one new preparation in flight.
- fix(dkg): retry failed signer installation and reset the worker on runtime teardown or round reset.
- Verification: the official nine-client `privnet/zk` Anti-MEV consensus smoke and the synthetic
  short-epoch async-worker smoke both passed their stated boundaries; see
  [`reports/zk-network-2026-07-20.md`](reports/zk-network-2026-07-20.md) and
  [`reports/zk-short-epoch-dkg-2026-07-20.md`](reports/zk-short-epoch-dkg-2026-07-20.md).

### Release boundary

- Non-validator full-node behavior remains operational and verified against the Neo X Geth oracle.
- The async worker prevents canonical processing from waiting on the external prover, but this run
  does not prove successful seven-message proving, on-chain DKG submission, receipt confirmation, or
  Anti-MEV decryption. The official DKG window at heights 360–720 and the remaining validator fault
  gates remain open.

## neox-v2.4.1 — 2026-07-20

First tagged Neo X release, built on Reth `2.4.1`
(`9ebad6c4b77e053cd15de448e8a402d40905e58e`); behavior oracle is Neo X Geth
`a0c80295ab2c7a6d0bc218e4bc85270f5610948c`.

### Status

- **Non-validator full node: operational and verified.** A full MainNet sync (~7.15M blocks) executes
  with zero state-root mismatch, and block hashes and state roots match the public reference at
  checkpoints spanning the pre-DKG, DKG (3,623,040), and Anti-MEV (3,749,760) eras. dBFT ECDSA quorum
  and BLS12-381 threshold verification are confirmed on live MainNet blocks.
- **Validator mode: pre-release.** Both an all-Reth seven-validator network and a **mixed
  Neo X Geth + neox-rs** network now sustain dBFT block production and finalize in lockstep at a
  5-of-7 quorum, including cross-client block proposals (Geth accepts neox-rs primary proposals and
  vice versa); see [`reports/mixed-network-2026-07-20.md`](reports/mixed-network-2026-07-20.md). The
  remaining live private-network fault gates (view-change under crash, prover delay, transaction
  replacement, Anti-MEV/ZK decryption, reorg) and an independent protocol/security review are not
  complete. Do not run this release as a validator or claim MainNet validator compatibility.

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
- One-line curl installer (`scripts/install.sh`): platform detection, checksum-verified release
  bundle download, `~/.neox-rs/bin` install with shell `PATH` setup, covered by hermetic tests.
- Operational exception notification: a health watcher (`scripts/neox-health-notify.py`) that polls
  RPC/metrics, evaluates the documented health criteria, and reports to a Better Stack heartbeat
  (with `/fail` escalation), the Better Stack incidents API, or a generic webhook; Prometheus alert
  rules (`etc/neox/prometheus-alerts.yml`); and hardened systemd units (`pkg/neox/`). Covered by
  hermetic tests and shipped in the release bundle's `ops/` directory.

### Changes in this release

- Rename the node binary and package from `neox-reth` to `neox-rs`.
- fix(dBFT): the primary now attaches the parent reseal witness for ECDSA parents, and propagated-block
  import respects dBFT instant finality (import only head-extending blocks) — an all-Reth validator
  network now converges instead of stalling at block 1.
- fix(dBFT): recovery-message construction (`DbftRecoveryMessage::add_message`) no longer rejects a
  PrepareRequest/PrepareResponse whose hash differs from the accumulated preparation hash. Neo X Geth
  tolerates this (the compact form keeps one shared preparation hash); the strict check aborted
  recovery and stalled sustained block production. Now mirrors Geth's `recoveryMessage.AddPayload`.
- Verification: a live mixed-client network (Neo X Geth + neox-rs on one genesis) finalizes dBFT
  blocks in lockstep with bidirectional cross-client proposals, and an all-Reth network runs past the
  former block-15 recovery stall — see [`reports/mixed-network-2026-07-20.md`](reports/mixed-network-2026-07-20.md).
- fix(dBFT/net): a restarted validator is no longer permanently rejected by its peers. The beacon
  handshake advertises and accepts the chain spec's reachable fork-id family, and the core eth-protocol
  `Status` advertises the folded fork id so reth's pipeline backfill has eth peers to sync from. Without
  this, a validator that fell behind sat at its stale head with zero eth peers. No-op on MainNet/TestNet
  (both have a Paris fork); fixes crash recovery on private/custom chains. See
  [`reports/fault-injection-2026-07-20.md`](reports/fault-injection-2026-07-20.md).
- fix(dkg-prover): route gnark's solver/prover logging to stderr so the ZK-v1 stdout response stays
  a single parseable JSON object; verified by generating a committed Groth16 proof against the
  production ceremony artifacts.
- fix(dBFT/security): decode a `RecoveryMessage` payload only after the sender is authorized against
  the validator set, so an unauthenticated `dbft/0` peer can no longer force ~10^5 BLS12-381 subgroup
  checks per frame (pre-authorization CPU DoS). fix(security): zeroize the raw 32-byte private-key read
  buffer. Both from an internal adversarial review — see
  [`reports/security-review-2026-07-20.md`](reports/security-review-2026-07-20.md).
- perf(neox): result-identical hot-path cleanups — TPKE batch decrypt decodes the DKG global key and
  each G2 signature share once instead of per combination; the Anti-MEV block bloom is OR-ed from the
  receipt blooms; a propagated block is encoded once and fanned out as a raw frame; and the sidecar
  store's existence check stats instead of decoding. See
  [`reports/optimizations-2026-07-20.md`](reports/optimizations-2026-07-20.md).
- refactor(neox): behavior-preserving consolidation of duplication and type/style alignment across the
  Neo X crates (verified by an adversarial audit; no functional change).
- fix(rpc-differential): compare head-only Policy RPC methods only when both nodes share the checked
  height.
- Verification: live-MainNet BLS threshold consensus test, codec fuzz sweeps, full-sync state-consistency
  and live-node run reports, an internal audit (findings NX-1…NX-8), and an all-Reth private-network
  report.

### Known issues

- Validator mode is pre-release. The live fault-injection gates for crash + view change, single-node
  transaction inclusion, crash recovery / pipeline backfill, and whole-cluster restart now pass on a
  seven-validator private network (see [`reports/fault-injection-2026-07-20.md`](reports/fault-injection-2026-07-20.md)),
  but prover-delay behavior, transaction-replacement / Anti-MEV decryption during production, and reorg
  beyond a single validator drop are still not exercised, and an independent security review is
  outstanding.
- The live ZK-v1 Anti-MEV block-production path (TPKE decryption while building blocks) is not yet
  exercised end-to-end on a network, though the DKG proving boundary is: the `neox-dkg-prover` produces
  a committed Groth16 proof from the production ceremony artifacts. A full network run needs the `zk`
  privnet layout with DKG/Anti-MEV forks active. The mixed-client run covers the pre-anti-MEV (ECDSA)
  regime.
