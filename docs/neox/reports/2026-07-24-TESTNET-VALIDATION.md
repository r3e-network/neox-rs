# Neo X `neox-v2.4.1-rc.7` TestNet validation — 2026-07-24

This report records the release-candidate validation run after synchronizing the Reth layer to
`32de8f9c78ff03edb74f846a356df81d6935a494`. The behavior oracle is Neo X Geth
`a0c80295ab2c7a6d0bc218e4bc85270f5610948c` with the official `privnet/zk` genesis.

## Nine-client canonical differential

The topology was one `neox-rs` validator, six Neo X Geth validators, and two Geth observers:

| Role | RPC |
|---|---:|
| `neox-rs` validator | `8661` |
| Geth observer | `8660`, `8668` |
| Geth validators | `8662`–`8667` |

The reproducible gate is `scripts/neox-full-differential.py`. With `NO_PROXY=127.0.0.1,localhost`
set for local Python RPC calls, it compared every canonical block from genesis through the common
head, every transaction object, and every receipt against all eight reference endpoints.

Result:

| Measure | Result |
|---|---:|
| Chain ID | `0x89d229b5` (`2312251829`) |
| Common head | `830` |
| Blocks checked | `831` (`0`–`830`) |
| Transactions checked | `9` |
| External receipt comparisons | `72` |
| Receipt statuses | `9 × 0x0` (reverted DKG calls) |
| Block/transaction/receipt mismatches | `0` |

The same gate over the validator-only set also reached height `641` with zero mismatches. This is
an exact Rust↔Go canonical-data result, including the reverted transaction status and gas usage;
it does not turn a reverted application call into a successful protocol transition.

## Mixed-client consensus smoke

`scripts/neox-mixed-dkg-e2e.py` was run against one Reth and six Geth validators for 11 common
blocks (heights `429`–`439`):

- zero reorgs and zero transient RPC errors;
- one observed dBFT view change;
- zero DKG replacements;
- three Reth prover attempts;
- all seven clients remained on the same chain and DKG round (`1`).

## DKG execution boundary

Nine DKG transactions were included during the share window. Each had receipt status `0x0`. A
historical `eth_call` and `debug_traceTransaction` for the first two calls return
`CommitmentInvalid()` (`0xa3a93fee`) from the `SevenMessageVerifier` commitment pairing path.
Geth validators also logged rejected `share`/`reshare` submissions, and no client reached a new
on-chain aggregate commitment or DKG round.

This is not a Rust↔Go block, transaction, or receipt divergence: all clients agree on the canonical
reverted calls. It is an unresolved deployed-verifier/ceremony compatibility boundary and must be
fixed and requalified before claiming a successful mixed-client DKG epoch.

## Release boundary

Validator mode remains experimental. Mixed-client DKG and validator fault scenarios are not claimed
as production-qualified, and this release candidate must not be used for a MainNet validator or
stable-validator compatibility claim.
