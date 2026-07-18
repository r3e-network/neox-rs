# Neo X client development

`neox-rs` is an independent Rust implementation of the Neo X execution and full-node protocol
built on Reth. The `neox` branch is the integration and default branch.

## Compatibility baseline

| Component | Baseline |
|---|---|
| Reth | `9ebad6c4b77e053cd15de448e8a402d40905e58e` (`2.4.1`) |
| Neo X Geth | `a0c80295ab2c7a6d0bc218e4bc85270f5610948c` |
| MainNet genesis SHA-256 | `bdb5f93f77871ffc77ae7b063e93eae116aa9c2af6230138f2df8f6daeac8fa5` |
| T4 TestNet genesis SHA-256 | `2b49c4d6701222396b9217b7c76e29fd150ab29fc91472b2f398d7620734a1ae` |

The pinned Neo X Geth source and canonical genesis files remain the behavior oracle until an
independent protocol specification covers every Neo X extension. Update
`docs/neox/source-baseline.toml` deliberately when that oracle changes.

## Implemented

- Canonical MainNet and T4 TestNet chain specs, genesis state, fork schedule, and bootnodes.
- V0/V1/V2 dBFT header codecs, proposer/difficulty checks, ECDSA and BLS threshold finality.
- Neo X system-contract execution hooks and Policy-aware transaction-pool validation.
- BEACON/2 and dBFT wire protocols, authenticated messages, missing-transaction recovery, timeout
  view changes, recovery messages, automatic primary proposals, and final block import.
- Anti-MEV Envelope parsing, current/previous DKG epoch classification, TPKE share verification and
  aggregation, reconstruction retry, fallback execution, and blob-sidecar preservation.
- `neox-reth` full-node executable with MainNet synchronization proven against live Neo X Geth
  block hashes and execution roots.
- Neo X RPC behavior for `eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`, and
  `eth_getCachedTransaction`.
- Optional Geth-compatible secret-transaction caching with `--txpool.amevcache`. Cached secret
  transactions are validated but are not inserted into or propagated by the public pool.
- Mode-0600 validator identity/share loading and canonical-round DKG share rotation from a key
  directory shared by all signer clones.
- A repeatable live JSON-RPC differential gate covering canonical block fields, Policy state and
  Neo X system-contract code.

## Remaining release gates

- Port the validator-side ZK-DKG task engine used by Neo X Geth: share, reshare, recover,
  reshare-recover, proof generation, KeyManagement transaction submission, confirmation/retry,
  and crash-safe local keystore persistence. The current key-directory rotation consumes shares;
  it does not generate or publish them.
- Run a seven-validator mixed Geth/Reth testnet through proposal, view-change, validator-set change,
  DKG epoch transition, Anti-MEV decryption, restart, and reorg scenarios.
- Qualify archive, tracing, snapshot, pruning, backup/restore, metrics, packaging, and upgrade paths
  under sustained MainNet load.
- Complete independent protocol/security review before a validator or MainNet release claim.

An independently syncing non-validator full node is operational. Validator mode remains
pre-release until the ZK-DKG and mixed-client gates above are complete.

## Build and run

The workspace currently requires the stable Rust toolchain for compilation. The repository's
formatting configuration still uses nightly rustfmt.

```sh
cargo +stable build -p neox-reth
target/debug/neox-reth node --chain neox-mainnet --http
```

Enable the private Anti-MEV construction cache only on an endpoint intended to receive secret
transactions:

```sh
target/debug/neox-reth node --chain neox-mainnet --http --txpool.amevcache
```

Validator key files must be readable only by their owner. Static share files remain supported, but
round-key directories are safer for epoch transitions:

```text
/secure/neox-dkg/
  87.key
  88.key
```

```sh
target/debug/neox-reth node \
  --chain neox-mainnet \
  --validator.ecdsa-key /secure/validator.key \
  --validator.dkg-key-dir /secure/neox-dkg
```

When `KeyManagement.roundNumber` changes, the node atomically installs `<round>.key` as current and
`<round-1>.key` as previous. Missing, malformed, or overly permissive files are rejected and retried
on the next canonical update.

## Live differential gate

Run a local node near the reference head, then compare one shared canonical height:

```sh
scripts/neox-rpc-differential.py \
  --local http://127.0.0.1:8545 \
  --reference https://mainnet-1.rpc.banelabs.org
```

The command exits non-zero for excessive height skew, canonical header/root divergence, Policy RPC
or storage divergence, missing custom methods, and system-contract bytecode differences. Use
`--height` to pin a reproducible historical block.

## Release rule

No release may claim validator compatibility until it independently obtains blocks through P2P,
reproduces canonical execution roots, completes mixed-client consensus and DKG epoch transitions,
and passes the operational and security gates above.
