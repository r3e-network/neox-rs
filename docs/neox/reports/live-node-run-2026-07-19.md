# Neo X live-node validation run — 2026-07-19

A `neox-reth` full node was built and run against **live Neo X MainNet** (chain 47763) to validate
network participation, sync, RPC correctness, robustness, stability, and shutdown behavior. This is
a non-validator full-node run; validator duty remains pre-release (see
[`audit-2026-07-19.md`](audit-2026-07-19.md) and [`../README.md`](../README.md)).

Command (debug build):

```sh
target/debug/neox-reth node --chain neox-mainnet --datadir <tmp> \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3,txpool,admin \
  --metrics 127.0.0.1:9101 --port 30399 --discovery.port 30399
```

## Results

### Startup and identity
- Started cleanly as Reth 2.4.1 (`1e34017`); log/data namespace `47763`.
- `Neo X P2P networking initialized with beacon/1,2 and dbft/0`; resolved external IP and published
  an enode.
- `Activated Neo X dBFT round from Governance state … validators=7`.
- HTTP RPC and Prometheus metrics endpoints came up.

### RPC correctness
- `eth_chainId` = `0xba93` (47763); `net_version` = `47763`.
- Genesis (`eth_getBlockByNumber 0x0`) hash = `0x2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7`
  (the canonical `NEOX_MAINNET_GENESIS_HASH`); state root = `0x92a17dd5…ccd9c`.
- Custom methods respond: `eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`,
  `eth_getCachedTransaction`.

### Live network participation
- Connected to live MainNet peers on **both** `beacon/2` and `dbft/0`; peer count grew to 4 on each
  (`reth_neox_sync_beacon_peers` / `reth_neox_sync_dbft_peers` = 4).
- Learned the real network head (~block 7,145,844) and backfilled real historical headers via staged
  sync (7,145,844 → ~6,655,845, ~500k headers).
- Received **live tip blocks in real time** as the dBFT validators produced them:
  `Received new payload from consensus engine number=7145893 … 7145896`.

### Differential vs live reference (`mainnet-1.rpc.banelabs.org`)
- `scripts/neox-rpc-differential.py --height 0`: **status `ok`, 0 mismatches, 37 height-addressed
  checks pass** — the genesis header, state root, Policy storage (slots 2/3/5/6/7), and every
  system-contract bytecode are byte-identical to the live network.
- The three head-only Policy RPC methods (`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`)
  take no block parameter and always read each node's head, so they are only comparable when the
  checked height is both nodes' head. The gate now records them under `skipped` when heights differ
  instead of reporting a false mismatch (they previously showed as 2 "mismatches" purely because
  this node was at genesis while the reference was at the 7.1M-block tip). Node-side self-consistency
  was confirmed directly: at genesis `eth_maxEnvelopeGas` and `eth_envelopeFee` equal Policy slots 7
  and 5, and `eth_gasPrice` (21 Gwei) equals the genesis header base fee (1 Gwei) plus `minGasTipCap`
  (20 Gwei), matching the `policy_gas_price` contract.
- A full execution differential requires a synced node and was out of scope for this debug-build run.

### Robustness (fuzz)
- Added deterministic, bounded fuzz-robustness sweeps (50,000 adversarial inputs each) over the two
  security-critical wire decoders reachable from untrusted peers:
  `extra::tests::extra_decoders_never_panic_on_adversarial_bytes` and
  `precommit::tests::decryption_share_decoder_never_panics_on_adversarial_bytes`. Random and
  mutated-valid inputs confirmed no panic and exact re-encode on every successful decode.

### Stability and shutdown
- **0 ERROR / 0 WARN / 0 panic** across the full ~9-minute run.
- `SIGTERM` produced a graceful shutdown: `Received SIGTERM` → `Wrote network peers to file` → exit
  code 0.

## Test suite
- `cargo +stable test` across all neox crates + `neox-reth`: pass (205 tests, including the 2 new
  fuzz sweeps); `clippy --all-targets` clean; nightly `fmt --check` clean; `scripts/tests/`: 13 pass.

## Core-logic verification matrix

Each core subsystem is exercised for correctness (against Geth-derived and live vectors), robustness
(negative/adversarial inputs), and completeness (all branches reached). All tests pass on `+stable`.

| Subsystem | Correctness | Robustness |
|---|---|---|
| dBFT header validation | `validates_live_mainnet_block_one` (ECDSA quorum, real block 1), `validates_live_testnet_v1/v2_threshold_block` | `rejects_a_child_validator_set_not_committed_by_its_parent`, `rejects_invalid_recovery_id_before_recovery` |
| **BLS12-381 threshold** | `validates_live_mainnet_v2_threshold_block` — real `validate_header` verifies a **current live MainNet** V2 seal (G2-over-G1, subgroup checks, DST, V1 negation path) | `rejects_a_tampered_live_mainnet_v2_threshold_signature` (1-bit tamper → `InvalidThresholdSignature`) |
| extraData codec | `genesis_v0_matches_mainnet_layout`, `threshold_roundtrip`, exact-length decode | `extra_decoders_never_panic_on_adversarial_bytes` (50k random + mutated inputs) |
| Anti-MEV / TPKE | envelope parse + epoch classification; share verify/aggregate; reconstruction + fallback; Geth 5-of-7 vectors | 55 error-path assertions in `tpke.rs`; `rejects_mismatched_ciphertext_commitment_and_share_indexes`; pairing-identity checks |
| DKG (PVSS/ECIES/share/reshare/recover) | Geth PVSS SHA-256 vector; epoch rotation; crash-safe keystore | `rejects_inconsistent_pvss_randomizers_and_public_shares`, `rejects_invalid_sources_indices_and_scalars`, `rejects_conflicting_replay_and_invalid_recovery_sets`, `rejects_wrong_password_before_creating_destination` |
| PreCommit share codec | `precommit_share_encoding_matches_geth_layout` | `decryption_share_decoder_never_panics_on_adversarial_bytes` (50k), `precommit_share_decoder_enforces_length_and_ceiling` |
| EVM / system contracts | storage-layout keys verified against live testnet storage; Policy validation; `onPersist`/`onPersistV2` selectors | envelope gas/count enforcement; blacklist; tip floor |
| RPC (custom Neo X) | live self-consistency: `eth_maxEnvelopeGas`/`eth_envelopeFee` = Policy slots 7/5; `eth_gasPrice` = header base fee + `minGasTipCap` | — |

The dBFT validation path is wired into `HeaderValidator::validate_header_against_parent`, so every
imported block runs the full ECDSA/BLS seal check — exercised in practice by the live header backfill
in this run.

## Not covered here (needs a synced node or private network)
- Full historical execution and a synced-height execution differential (infeasible for 7.1M blocks
  on a debug build in one session).
- Validator-duty fault gates (view-change, prover delay, transaction replacement, Anti-MEV
  decryption, reorg) — require the 1-Reth/6-Geth private network; see the open findings in
  `audit-2026-07-19.md`.
