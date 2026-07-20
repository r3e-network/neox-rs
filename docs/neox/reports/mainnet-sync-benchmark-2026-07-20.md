# Neo X MainNet sync benchmark — 2026-07-20

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
receipts root matched between Reth and Geth and the live MainNet RPC. The
range contains 205 transactions across 20,000 imported blocks; block 20,000
itself has zero transactions.

## Result

| Client | Version | Imported blocks | Elapsed | Blocks/s |
| --- | --- | ---: | ---: | ---: |
| `neox-rs` | `reth/v2.4.1-baa2be9/aarch64-unknown-linux-gnu` | 20,000 | 85.147911 s | **234.885** |
| Neo X Geth | `Geth/v0.6.1-stable-7b59ded3/linux-arm64/go1.24.13` | 20,000 | 358.819724 s | **55.738** |

`neox-rs` is **4.214×** faster on this sample, or **+321.4%** throughput
relative to Neo X Geth. Equivalently, it completed the range about 273.7 s
earlier.

The complete machine-readable result is
[`mainnet-sync-benchmark-2026-07-20.json`](mainnet-sync-benchmark-2026-07-20.json).

## Method and caveats

The runner is [`scripts/neox-sync-benchmark.py`](../../../scripts/neox-sync-benchmark.py).
Neo X Geth's published `--synctarget` startup flag exits when the target header
is not available before peer handshake. For a fresh node the benchmark therefore
starts Geth without that flag, waits for the endpoint to come up, and invokes
the published `debug_sync(hash)` API; the runner exposes this as
`--geth-sync-target`. This is still Geth's own full-sync path, but the elapsed
time includes the target-peer acquisition and transport behavior required by
that path.

This is a 20,000-block MainNet history sample, not a claim about syncing the
entire current tip. A release-level claim should repeat the same procedure at
larger fixed heights, record variance across cold starts, and retain the
hash/state-root equality gate.
