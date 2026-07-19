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
- `scripts/neox-rpc-differential.py --height 0`: **38 of 40 checks matched**, including the genesis
  header, state root, Policy storage, and system-contract bytecode — i.e. byte-level genesis
  compatibility with the live network.
- The 2 differences (`eth_gasPrice`, `eth_maxEnvelopeGas`) are **head-dependent** live Policy reads
  (no block parameter); they differ only because this node sat at genesis while the reference is at
  the tip (7.1M-block skew), not because of a node defect. A full execution differential requires a
  synced node and was out of scope for this debug-build run.

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

## Not covered here (needs a synced node or private network)
- Full historical execution and a synced-height execution differential (infeasible for 7.1M blocks
  on a debug build in one session).
- Validator-duty fault gates (view-change, prover delay, transaction replacement, Anti-MEV
  decryption, reorg) — require the 1-Reth/6-Geth private network; see the open findings in
  `audit-2026-07-19.md`.
