# NeoX block-sync/import benchmark — 2026-07-20

This is the second benchmark phase. It measures fresh-datadir import of the same NeoX private
chain range into `neox-rs` and Neo X Geth. The raw suite summary is checked in as
[`sync-benchmark-2026-07-20.json`](sync-benchmark-2026-07-20.json), and the runner is
[`neox-sync-benchmark.py`](../../../scripts/neox-sync-benchmark.py).

## Fairness and correctness gates

- Both observers started from height **0** with new datadirs and the same genesis.
- The source was a seven-validator dBFT private chain at height **400**. The source was held at
  that height so every run used the same canonical range.
- Genesis SHA-256: `198b87d341df6a0f89b2a9962c0b51f7551a6ba8b23b029e62681a0af2f3e0db`.
- Chain ID: `2312251829`; dBFT period: `1`; NeoX DKG/AMeV/ECDSA forks: `1,000,000` (pure
  ECDSA test regime).
- Both clients ran in Ubuntu 24.04 containers on the same Apple Silicon ARM64 host with
  `--cpus=2 --memory=2g --network host` and the same source peers.
- The runner rejected any node whose first observed head exceeded the start height. It then
  compared block number, hash, parent hash, state root, transactions root, and receipts root.
- All three recorded runs passed the final-block equality gate. Height-400 hash:
  `0xf4e324affb6b5771b2ca3ac368c52ea3a78387d98820f8dddc59ca1fd69bbed5`.

## Results

| Run | neox-rs blocks/s | Neo X Geth blocks/s | Reth/Geth |
|---:|---:|---:|---:|
| 1 | 6,122.172 | 1,452.728 | 4.214x |
| 2 | 6,241.970 | 882.122 | 7.076x |
| 3 | 13,461.083 | 1,044.161 | 12.892x |
| **Median** | **6,241.970** | **1,044.161** | **5.978x** |

The median result is approximately **+497.8%** for `neox-rs` (about **6×** the Geth import
rate). The three ratios range from 4.21× to 12.89× because the measured 400-block range is very
short and contains empty blocks; cold-start and RPC polling overhead are therefore a large part of
the elapsed time.

## What this proves—and what it does not

This run exercises the Reth-style staged pipeline: headers, bodies, sender recovery, execution,
Merkle/index stages, and database commit. It is a valid sync/import advantage signal, and the final
state and transaction/receipt roots match.

The blocks contain no transactions, so this is **not** a transaction-throughput or NeoX system-call
benchmark. It does not yet measure sustained EVM execution, Policy validation, dBFT finality, disk
write amplification, memory pressure, or long-range sync. Those require a transaction-bearing
corpus and a longer replay window.

## Reproduce

Start a fresh observer pair against a held source chain, then run:

```sh
python3 scripts/neox-sync-benchmark.py \
  --reth http://127.0.0.1:18619 \
  --geth http://127.0.0.1:18618 \
  --start-height 0 --target-height 400 \
  --poll-interval 0.05 --deadline 120 \
  --output docs/neox/reports/sync-benchmark-YYYY-MM-DD.json
```

The harness has no third-party Python dependencies. Unit tests:

```sh
python3 -m unittest scripts.tests.test_neox_sync_benchmark -v
```
