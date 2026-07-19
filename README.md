# neox-rs

**An independent Rust implementation of the Neo X execution and full-node protocol, built on [Reth](https://github.com/paradigmxyz/reth).**

`neox-rs` reuses Reth's storage, networking, RPC, EVM, and staged-sync infrastructure and adds the
Neo X protocol on top: dBFT consensus, the BEACON and dBFT wire protocols, Neo X system contracts and
Policy-aware fees, and the Anti-MEV / DKG stack. The integration and default branch is `neox`.

> Built on Reth by [Paradigm](https://paradigm.xyz/). This repository tracks a pinned upstream Reth
> revision and layers the Neo X protocol on it; see [Relationship to Reth](#relationship-to-reth).

## What is Neo X?

Neo X is an EVM-compatible chain that finalizes blocks with dBFT and extends Ethereum with an
Anti-MEV transaction pipeline. `neox-rs` implements that protocol as a Reth node preset (`neox-rs`)
so an operator can run an independent Neo X full node that syncs from the public network and
reproduces canonical block hashes and execution roots.

## Compatibility baseline

The pinned Neo X Geth source and canonical genesis files are the behavior oracle until an independent
protocol specification covers every Neo X extension. Update
[`docs/neox/source-baseline.toml`](docs/neox/source-baseline.toml) deliberately when that oracle
changes.

| Component | Baseline |
|---|---|
| Reth | `9ebad6c4b77e053cd15de448e8a402d40905e58e` (`2.4.1`) |
| Neo X Geth | `a0c80295ab2c7a6d0bc218e4bc85270f5610948c` |
| MainNet chain ID | `47763` |
| T4 TestNet chain ID | `12227332` |

## Implemented

- Canonical MainNet and T4 TestNet chain specs, genesis state, fork schedule, and bootnodes.
- V0/V1/V2 dBFT header codecs, proposer/difficulty checks, and ECDSA + BLS12-381 threshold finality.
- Neo X system-contract execution hooks and Policy-aware transaction-pool validation.
- BEACON/2 and dBFT wire protocols with authenticated messages, missing-transaction recovery, timeout
  view changes, recovery messages, automatic primary proposals, and final block import.
- Anti-MEV Envelope parsing, current/previous DKG epoch classification, TPKE share verification and
  aggregation, reconstruction with fallback, and blob-sidecar preservation.
- A managed validator DKG runtime (5-of-7 PVSS, ECIES, share/reshare/recover, epoch rotation) with a
  crash-safe, validator-bound encrypted keystore.
- The `neox-rs` full-node executable, with MainNet synchronization proven against live Neo X block
  hashes and execution roots.
- Neo X RPC behavior for `eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`, and
  `eth_getCachedTransaction`, plus Prometheus metrics for the sync and consensus drivers.

## Status

An independently syncing non-validator full node is operational: it peers over `beacon/2` and
`dbft/0`, backfills real headers, receives live tip blocks, and reproduces the canonical genesis
state. dBFT consensus and BLS12-381 threshold verification are exercised against live MainNet blocks.

**Validator mode is pre-release.** The remaining private-network fault gates (explicit view-change,
prover delay, transaction replacement, Anti-MEV decryption, reorg) and an independent
protocol/security review must complete before any validator or MainNet release claim. See the
[remaining release gates](docs/neox/README.md#remaining-release-gates) and the audit record in
[`docs/neox/reports/`](docs/neox/reports/).

## Build and run

The workspace builds on the stable Rust toolchain (MSRV 1.95); the formatting configuration uses
nightly rustfmt.

```sh
cargo +stable build -p neox-rs
target/debug/neox-rs node --chain neox-mainnet --http
```

Run a non-validator MainNet full node with persistent data and published RPC, WebSocket, metrics, and
P2P ports:

```sh
target/debug/neox-rs node \
  --chain neox-mainnet --datadir /data \
  --http --http.addr 0.0.0.0 \
  --ws --ws.addr 0.0.0.0 \
  --metrics 0.0.0.0:9001
```

See [`docs/neox/README.md`](docs/neox/README.md) for validator operation, the DKG keystore and
migration flow, the live JSON-RPC differential gate, the mixed-validator DKG gate, and the full
metrics reference. See [`docs/neox/OPERATIONS.md`](docs/neox/OPERATIONS.md) for snapshot round-trip,
upgrade/rollback, and validator fencing procedures.

## Testing

Use the stable toolchain (the default nightly on some hosts is below the 1.95 MSRV):

```sh
cargo +stable test -p reth-neox-chainspec -p reth-neox-consensus -p reth-neox-consensus-engine \
  -p reth-neox-antimev -p reth-neox-evm -p reth-neox-network -p reth-neox-node -p neox-rs
cargo +stable clippy --workspace --all-features
cargo +nightly fmt --all --check
python3 -m unittest discover -s scripts/tests -p "test_*.py"
```

The Neo X crates carry unit and integration tests against Geth-derived and live-network vectors,
codec fuzz sweeps, and negative/robustness tests for the consensus and cryptographic paths.

## Relationship to Reth

`neox-rs` is a fork of Reth. The upstream Reth crates are kept close to their pinned revision and the
Neo X protocol lives in dedicated crates so the two can evolve independently:

- `crates/neox/chainspec` — Neo X chain specs, genesis, forks, bootnodes
- `crates/neox/consensus`, `crates/neox/consensus-engine` — dBFT header validation and Reth consensus
  integration
- `crates/neox/evm` — Neo X block execution, system contracts, Policy
- `crates/neox/network` — BEACON and dBFT wire protocols
- `crates/neox/antimev` — TPKE, DKG, keystore, decryption-share codec
- `crates/neox/node` — node-component wiring, sync driver, validator runtime
- `bin/neox-rs` — the Neo X full-node executable

Everything under `crates/` outside `crates/neox/` is upstream Reth. The general Reth development guide
lives in [`AGENTS.md`](AGENTS.md).

## Security

See [`SECURITY.md`](SECURITY.md). `neox-rs` has not completed an independent Neo X protocol/security
review; do not run it as a validator or make a MainNet compatibility claim until that review and the
release gates above are complete.

## License

Licensed under the Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)) or the MIT license
([`LICENSE-MIT`](LICENSE-MIT)), at your option.

## Acknowledgements

- [Reth](https://github.com/paradigmxyz/reth) by [Paradigm](https://paradigm.xyz/) — the Ethereum
  execution client this project is built on. Reth completed an audit with
  [Sigma Prime](https://sigmaprime.io/) ([report](audit/sigma_prime_audit_v2.pdf)).
- [Neo X Geth](https://github.com/bane-labs/go-ethereum) — the Neo X protocol behavior oracle.
- [go-ethereum](https://github.com/ethereum/go-ethereum), [Erigon](https://github.com/ledgerwatch/erigon),
  and the wider Rust Ethereum ecosystem ([Alloy](https://github.com/alloy-rs/alloy),
  [revm](https://github.com/bluealloy/revm)).

## Warning

The `NippyJar` and `Compact` encoding formats inherited from Reth are for internal storage and are not
hardened to safely read potentially malicious data.
