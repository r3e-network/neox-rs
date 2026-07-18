# Neo X client development

`neox-rs` is a clean Rust implementation of the Neo X full-node protocol built with the Reth
SDK. The target is an independently syncing and validating client, followed by dBFT validator and
Anti-MEV support. It is not considered compatible merely because it can execute ordinary EVM
transactions.

## Compatibility baseline

| Component | Baseline |
|---|---|
| Reth | `9ebad6c4b77e053cd15de448e8a402d40905e58e` (`2.4.1`) |
| Neo X Geth | `a0c80295ab2c7a6d0bc218e4bc85270f5610948c` |
| MainNet genesis SHA-256 | `bdb5f93f77871ffc77ae7b063e93eae116aa9c2af6230138f2df8f6daeac8fa5` |
| T4 TestNet genesis SHA-256 | `2b49c4d6701222396b9217b7c76e29fd150ab29fc91472b2f398d7620734a1ae` |

The Neo X Geth repository and its canonical genesis files are the current behavior oracle. This is
a temporary engineering baseline, not a substitute for an independent protocol specification.

## Implementation order

1. ChainSpec, genesis, hardforks, and header primitives.
2. Differential block execution and state-root parity.
3. Reth storage pipeline and crash-safe unwind.
4. Neo X P2P, BEACON/2, and independent synchronization.
5. JSON-RPC, tracing, archive, and operator packaging.
6. State-aware dBFT validation and finality.
7. Validator state machine and mixed-client testnet.
8. Envelope transactions, TPKE, DKG, and Anti-MEV block production.
9. Independent audits and staged MainNet rollout.

Every stage is gated by differential tests against Neo X Geth. A later stage must not compensate
for unresolved state-root or consensus divergence in an earlier stage.

## Current status

- [x] Fork Reth and establish upstream remote.
- [x] Add a dedicated Neo X ChainSpec crate.
- [x] Model Neo X DKG, Anti-MEV, and signature hardforks.
- [x] Parse and validate the dBFT genesis extension.
- [x] Vendor canonical genesis files with provenance verification.
- [x] Match canonical MainNet and TestNet genesis hashes.
- [x] Implement V0/V1/V2 dBFT header extra-data primitives.
- [x] Verify live V0 ECDSA and V1/V2 TPKE threshold-signed headers.
- [x] Validate parent next-consensus commitments and in-turn difficulty.
- [ ] Integrate dBFT validation into the Reth consensus pipeline.
- [ ] Add single-block Geth/Reth differential execution harness.
- [ ] Assemble the `neox-reth` node binary.

## Safety rule

No release may claim full-node compatibility until it independently obtains blocks through P2P,
validates dBFT finality, and reproduces all canonical state and receipt roots. Validator builds have
additional mixed-client and Anti-MEV gates.
