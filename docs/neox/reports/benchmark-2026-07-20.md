# NeoX Geth vs neox-rs benchmark — 2026-07-20

This report is the first reproducible performance comparison between the Neo X Geth
behavior oracle and the Reth-based `neox-rs` node. The raw result is checked in as
[`benchmark-2026-07-20.json`](benchmark-2026-07-20.json).

## Scope and fairness

- **Clients:** `neox-rs` `reth/v2.4.1-baa2be9/aarch64-unknown-linux-gnu` and Neo X Geth
  `Geth/v0.6.1-stable-7b59ded3/linux-arm64/go1.24.13`.
- **Version note:** the measured Geth is the published `v0.6.1` ARM64 release. The repository's
  compatibility-oracle pin remains `a0c80295...`; this report is therefore a current release
  snapshot, not an exact commit-for-commit oracle comparison.
- **Host:** one Apple Silicon ARM64 host; both nodes ran in Ubuntu 24.04 containers with
  `--cpus=4 --memory=4g --network host`.
- **Chain state:** the same canonical `crates/neox/chainspec/res/genesis_mainnet.json`, chain ID
  `47763`, and block height `0` at the start and end of the run.
- **Corpus:** 22 deterministic JSON-RPC cases covering chain metadata, block headers/full blocks,
  balances, system-contract bytecode, Policy storage slots, and a successful system-contract EVM
  call.
- **Method:** 100 warmup requests, 500 timed requests, 3 paired rounds, and concurrency 1/4/16.
  The endpoint order is randomized independently for every paired round. Before timing, every case
  is sent once to both clients; a semantic mismatch aborts the comparison. Empty Geth revert data
  is normalized because Reth omits that optional field.
- **Statistics:** each row reports the median of the three round medians. `throughput` is completed
  requests per second; latency is wall-clock client-observed latency.

This is a **genesis-state RPC/read benchmark**. It does not measure full-chain synchronization,
block import, transaction execution under load, dBFT finality, disk growth, or validator memory
pressure. Those are separate gates and are intentionally not inferred from this run.

## Results

The semantic probe passed for **22/22 cases**, with zero timed RPC errors. The median Reth/Geth
throughput ratio across all cases was:

| Concurrency | Reth/Geth throughput | Reth wins | Median p50 latency ratio |
|---:|---:|---:|---:|
| 1 | 1.002x | 11/22 | 0.994x |
| 4 | **1.052x** | 15/22 | **0.951x** |
| 16 | **1.041x** | 19/22 | **0.959x** |

The category medians show where the advantage is most repeatable:

| Category | c=1 | c=4 | c=16 |
|---|---:|---:|---:|
| Chain/RPC metadata | 1.151x | **1.165x** | 1.036x |
| Block header/full | 1.070x | **1.174x** | 1.059x |
| Balance reads | 0.949x | 0.987x | 1.012x |
| Contract code reads | 0.996x | 1.042x | **1.080x** |
| Policy storage reads | 0.995x | 1.054x | 1.039x |
| EVM call | 0.915x | 1.044x | 1.056x |

Representative c=4 results (median throughput) were:

| Case | neox-rs | Neo X Geth | Ratio |
|---|---:|---:|---:|
| `eth_getBlockByNumber` header | 5,236 req/s | 4,567 req/s | **1.147x** |
| `eth_getBlockByNumber` full | 5,249 req/s | 4,369 req/s | **1.202x** |
| `eth_getCode` (implementation) | 4,526 req/s | 3,465 req/s | **1.306x** |
| `eth_call` (system implementation) | 4,813 req/s | 4,610 req/s | 1.044x |

The result supports a narrow, evidence-based claim: on this host and this genesis-state read
corpus, `neox-rs` has lower median latency and higher throughput under moderate/high concurrency,
with the clearest gains in block and code reads. It is not evidence that Reth is already faster for
full synchronization or transaction execution.

## Reproduce

Start both clients on the same genesis and resource limits, then run:

```sh
python3 scripts/neox-benchmark.py \
  --reth http://127.0.0.1:18546 \
  --geth http://127.0.0.1:18545 \
  --genesis crates/neox/chainspec/res/genesis_mainnet.json \
  --requests 500 --warmup 100 --rounds 3 --concurrency 1,4,16 \
  --output docs/neox/reports/benchmark-YYYY-MM-DD.json
```

The harness has no third-party Python dependencies. Unit tests are run with:

```sh
python3 -m unittest scripts.tests.test_neox_benchmark -v
```

## Next benchmark phases

To turn this into a full-node performance claim, the following measurements are required:

1. **Sync/import:** the first fresh-datadir phase is recorded in
   [`sync-benchmark-2026-07-20.md`](sync-benchmark-2026-07-20.md): the median was 5.98x Reth/Geth
   on a 400-block empty private-chain range, with matching final roots. The first live MainNet
   sample is recorded in [`mainnet-sync-benchmark-2026-07-20.md`](mainnet-sync-benchmark-2026-07-20.md),
   but its performance comparison was invalidated because the Geth timer included an asymmetric
   270.8-second pre-trigger wait. Only the matching final hashes/roots remain valid. A replacement
   requires a shared trigger barrier, event timestamps, complete raw workload metadata, and at least
   three fresh-datadir runs before publishing a median and range.
2. **Execution/commit:** use an identical deterministic signed-transaction corpus on a seven-node
   private dBFT network and report sustained tx/s, block execution time, finality latency, and RPC
   p50/p95/p99 under load.
3. **Soak and variance:** repeat each phase for at least 30 minutes, pin CPU/memory/disk settings,
   publish raw samples, and include regressions in scheduled CI following Reth's baseline/feature
   benchmark model.
