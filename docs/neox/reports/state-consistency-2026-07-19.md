# Neo X MainNet full-sync state-consistency verification — 2026-07-19

Verifies that `neox-reth` executes Neo X MainNet (chain 47763) and reproduces the network's canonical
world state, using an optimized (release) build.

## Method

A node's block hash is a commitment to its header, and the header's `stateRoot` is a Merkle-Patricia
commitment to the **entire** world state (every account and storage slot) at that block. If our node
independently downloads and executes blocks `0..N` and its computed `stateRoot` at `N` equals the
network's canonical `stateRoot` at `N`, the full state at `N` is byte-identical to the network.

Reth's staged pipeline enforces this per block: the `Execution` stage runs the EVM and the
`MerkleExecute` stage recomputes the state root and validates it against each block's header. A single
mismatch fails the stage with `StateRootMismatch` and unwinds. A clean run to `N` therefore means
**every** block's state root in `0..N` matched.

## Bounded full sync to block 200,000 — verified

A bounded sync (`--debug.tip <hash@200000> --debug.max-block 200000`) ran the complete 13-stage
pipeline to block 200,000 and exited cleanly:

```
Headers → Bodies → SenderRecovery → Execution → MerkleUnwind → AccountHashing →
StorageHashing → MerkleExecute → TransactionLookup → IndexStorageHistory →
IndexAccountHistory → Prune → Finish     (all: checkpoint 200000, 100%)
```

No `error`, `panic`, `StateRootMismatch`, `Invalid`, or unwind occurred. Wall-clock: ~63 s on the
release build (blocks 0..200,000 are pre-DKG/pre-AntiMev — the AntiMev fork activates at 3,749,760).

Explicit comparison of the synced node against the public reference
(`mainnet-1.rpc.banelabs.org`) at three checkpoints:

| Block | Block hash | State root |
|---|---|---|
| 50,000 | match | match |
| 100,000 | match | match |
| 200,000 | match | match |

The live JSON-RPC differential gate at height 200,000 reported `status: ok`, **0 mismatches, 37
height-addressed checks** (block fields, Policy storage slots 2/3/5/6/7, and every system-contract
bytecode). Because the state root at 200,000 matched, the full state of every block in `0..200,000`
is byte-identical to the live network.

## Full sync to the live tip — in progress

An unbounded sync resumes from block 200,000 and downloads/executes toward the live tip (~7.15M
blocks), verifying every block's state root through the same `MerkleExecute` gate. This is a
multi-hour run that continues beyond the recorded session; it crosses the DKG (3,623,040) and AntiMev
(3,749,760) forks, exercising threshold-sealed and Anti-MEV blocks under execution. Progress is
observable via `reth_neox_sync_canonical_height` and the pipeline stage logs; any state-root
divergence would halt the pipeline with `StateRootMismatch`.

## Reproduce

```sh
cargo +stable build --release -p neox-reth
# Bounded, verifiable sync to a checkpoint N (fetch N's hash from a reference first):
target/release/neox-reth node --chain neox-mainnet --datadir <dir> \
  --debug.tip 0x<hash@N> --debug.max-block <N> --http
# Then compare block hash and stateRoot at N against the reference, or run:
scripts/neox-rpc-differential.py --local http://127.0.0.1:8545 \
  --reference https://mainnet-1.rpc.banelabs.org --height <N> --max-height-skew 99999999
```
