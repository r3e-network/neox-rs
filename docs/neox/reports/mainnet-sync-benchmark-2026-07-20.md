# Neo X MainNet sync sample — 2026-07-20 (performance invalidated)

> **Status: invalid for performance comparison.** The Geth timer started about
> 270.8 seconds before `debug_sync` was triggered. The reported elapsed-time
> difference was 273.67 seconds, so the former `4.214x` / `+321.4%` conclusion
> was dominated by an asymmetric idle wait and must not be cited.

This is a reproducible cold-start sync sample using the live Neo X MainNet
chain, not the synthetic private-chain sample in
[`sync-benchmark-2026-07-20.md`](sync-benchmark-2026-07-20.md).

## Validation boundary

- Source RPC: `https://mainnet-1.rpc.banelabs.org`
- Chain ID: `47763`
- Genesis hash: `0x2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7`
- Fresh datadirs: both clients started from height `0` with the repository's
  `genesis_mainnet.json`.
- Target: block `20,000`
- Target hash: `0xc043a64254d2dd159f422d538b7d71da660984e67dc3f72feb3f4ee0b62dc1e9`
- Target state root: `0x24b8cefa283972829daa72770c58ac7fd4d453f67deb0980c498747c0cbbfd6b`
- Target transactions root and receipts root:
  `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`

The final block number, hash, parent hash, state root, transactions root, and
receipts root matched between Reth and Geth and the live MainNet RPC. This
correctness result remains valid.

## Invalid timing record

| Client | Version | Imported blocks | Elapsed | Blocks/s |
| --- | --- | ---: | ---: | ---: |
| `neox-rs` | `reth/v2.4.1-baa2be9/aarch64-unknown-linux-gnu` | 20,000 | 85.147911 s | **234.885** |
| Neo X Geth | `Geth/v0.6.1-stable-7b59ded3/linux-arm64/go1.24.13` | 20,000 | 358.819724 s | **55.738** |

These values are retained only to make the audit reproducible. They are not a
valid throughput comparison. After subtracting the asymmetric idle wait, the
Geth time is at most approximately 88.02 seconds, close to the 85.15-second
Reth observation; a fair ratio cannot be calculated from this run.

The complete machine-readable result is
[`mainnet-sync-benchmark-2026-07-20.json`](mainnet-sync-benchmark-2026-07-20.json).

## Method and caveats

The runner is [`scripts/neox-sync-benchmark.py`](../../../scripts/neox-sync-benchmark.py).
Neo X Geth's published `--synctarget` startup flag exits when the target header
is not available before peer handshake. This run started Geth without that
flag and later invoked `debug_sync(hash)`. The runner incorrectly began Geth's
timer when its RPC first reported height zero, while delaying `debug_sync`
until the Reth RPC was also ready. That sequencing created the invalid idle
interval.

A replacement benchmark must use one explicit trigger barrier for both
clients, record process start / RPC ready / trigger / completion events, place
the transaction count and complete commands in raw JSON, run at least three
fresh-datadir samples, publish the median and range, and reject all performance
statistics unless every final hash/root field matches.
