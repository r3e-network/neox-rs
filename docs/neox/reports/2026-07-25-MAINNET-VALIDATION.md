# Neo X `neox-v2.4.2` MainNet validation — 2026-07-25

This report records the full-chain MainNet re-validation of `neox-v2.4.2`, which the release notes
originally published as outstanding. It supersedes that statement.

Binary under test: `neox-rs` built at `e1c8e031bec34e446b0233b7b4b3d386082a121e`, release profile.
Reference: the public Neo X MainNet RPC `https://mainnet-1.rpc.banelabs.org`, chain ID `47763`.

## Full-history re-execution

Every canonical block was re-executed with the `neox-v2.4.2` binary against the archive datadir
carried forward from the `neox-v2.4.1` validation, using the built-in `re-execute` command. This
re-runs execution and compares the result to the stored state, so it exercises the release's
execution and reconstruction changes across all history rather than only at the tip.

```sh
neox-rs re-execute --chain neox-mainnet \
  --datadir /home/neo/.cache/neox-rs-validation/mainnet-20260722 \
  --from 1 --to 7212903
```

| Measure | Result |
|---|---:|
| Range | `1` – `7,212,903` |
| Blocks re-executed | `7,212,902` |
| Throughput | `1.18 Ggas/s` |
| State-root mismatches | `0` |
| Bad blocks | `0` |
| Errors, panics, required unwinds | `0` |

## Restart and live tip following

The same datadir was then restarted on the `neox-v2.4.2` binary with no debug tip, so the release
had to catch the live backlog accumulated while re-execution ran and then follow dBFT production.

| Measure | Result |
|---|---:|
| Height at shutdown of the `2.4.1` node | `7,212,903` |
| Height after `2.4.2` caught the backlog | `7,212,989` |
| Final observed local head | `7,213,178` |
| Reference head at that moment | `7,213,178` (delta `0`) |
| Head hash | `0x859eacdf5a864653fdd9de841ca79ad424192a0b731fa790a73e891bb90def13` |
| Head state root | `0xe1102a123e5c1c2b01c4549a30dd70521ccaf53c13602c3c7f3ebdff48b0d7b7` |
| Bad blocks, root mismatches, unwinds | `0` |

Both the hash and the state root at `7,213,176` matched the reference. The only warning emitted was
a peer returning an empty response to a dBFT missing-transaction request, which is a peer-side
condition and not a validation failure.

## Differential comparison

A block, transaction, and receipt differential was run against the reference over a recent range.
The full 491-block range initially attempted did not complete: the public reference endpoint
rate-limits sustained receipt queries. The completed range is reported rather than the attempted one.

| Measure | Result |
|---|---:|
| Range | `7,212,953` – `7,213,132` |
| Blocks compared | `180` |
| Transactions compared | `44` |
| Receipts compared | `44` |
| Total field comparisons | `3,808` |
| Mismatches | `0` |

Compared per block: `number`, `hash`, `parentHash`, `stateRoot`, `transactionsRoot`, `receiptsRoot`,
`gasUsed`, `gasLimit`, `timestamp`, `miner`, `extraData`, `mixHash`, `baseFeePerGas`, `logsBloom`,
`difficulty`, `nonce`, `sha3Uncles`. Per transaction: `hash`, `from`, `to`, `value`, `input`,
`nonce`, `gas`, `type`, `transactionIndex`. Per receipt: `status`, `cumulativeGasUsed`, `gasUsed`,
`logs`, `logsBloom`, `contractAddress`, `transactionIndex`, `blockHash`.

## What this run does and does not demonstrate

The DKG is live on MainNet: `KeyManagement.roundNumber` reads `17` and `ZK_VERSION()` reads `1`, so
a threshold key exists and Anti-MEV Envelope decryption is reachable in principle.

In practice it is not reached by any historical block. Scanning `eth_getLogs` for the Envelope
target `0x1212000000000000000000000000000000000003` across all `7,213,174` blocks returns a single
log, in block `3,491,620`, and that block's only transaction targets
`0x1212000000000000000000000000000000000000` rather than the Envelope address. No MainNet block
carries a direct Envelope transaction.

The consequence for this release is specific and worth stating plainly:

- The **zero-mismatch re-execution across all 7.21M blocks** establishes that `neox-v2.4.2`
  reproduces every canonical MainNet state root, so none of the six fixes regressed the historical
  execution path. That is the claim the release notes previously left unverified, and it now holds.
- It does **not** exercise the Anti-MEV reconstruction cursor fix or the static-pool gate, because
  MainNet history contains no Envelope-bearing block to reconstruct. Those two fixes remain covered
  by their unit tests and by the TestNet and private-network runs behind earlier releases, not by
  MainNet history.
- Validator-side behavior (proposal signing, primary selection, the dBFT timer reset, future-message
  caching) is not exercised by a following node. Validator mode remains experimental.

## Reproduction

```sh
cargo build --release -p neox-rs --bin neox-rs
neox-rs re-execute --chain neox-mainnet --datadir <archive-datadir> --from 1 --to <head>
neox-rs node --chain neox-mainnet --datadir <archive-datadir> \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3 \
  --port 30313 --discovery.port 30313
```

Set `NO_PROXY='*'` for local Python RPC calls; this host routes `127.0.0.1` through a proxy
otherwise.
