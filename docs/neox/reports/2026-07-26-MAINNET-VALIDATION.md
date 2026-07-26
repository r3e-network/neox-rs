# Neo X `neox-v2.4.3` MainNet validation — 2026-07-26

This report records the full-chain MainNet validation of `neox-v2.4.3`.

Binary under test: `neox-rs` built at `d34e96ad028668a11ada7d3eb6906a08df90dfa7`, release profile.
Reference: the public Neo X MainNet RPC `https://mainnet-1.rpc.banelabs.org`, chain ID `47763`.

## What this run can and cannot establish

Neither fix in `neox-v2.4.3` is reachable from block execution. The blob-sidecar TTL bound lives in
the `beacon` sub-protocol's request-serving path, and the keystore password fix is in an offline
migration utility. Full-history re-execution therefore cannot exercise either one; it establishes
that neither regressed historical execution. The fixes themselves are covered by unit tests: the TTL
range and the forwarding-decrement invariant in `crates/neox/node/src/sync/sidecar.rs`, and the
NFKD/control-character rules in `crates/neox/antimev/src/geth_keystore.rs`, whose fixture writer now
normalises the way the reference client's encryptor does.

The live-tip half of the run is the part that carries weight for the sidecar change, since the node
served and forwarded beacon traffic against real peers under the new bound for the duration.

## Full-history re-execution

Every canonical block was re-executed with the `neox-v2.4.3` binary against the archive datadir
carried forward from the `neox-v2.4.2` validation, using the built-in `re-execute` command.

```sh
neox-rs re-execute --chain neox-mainnet \
  --datadir /home/neo/.cache/neox-rs-validation/mainnet-20260722 \
  --from 1 --to 7214807
```

| Measure | Result |
|---|---:|
| Range | `1` – `7,214,807` |
| Blocks re-executed | `7,214,806` |
| Throughput | `1.55 Ggas/s` |
| State-root mismatches | `0` |
| Bad blocks | `0` |
| Errors, panics, required unwinds | `0` |

## Restart and live tip following

The `neox-v2.4.2` node was stopped with `SIGTERM` at height `7,214,807` and exited cleanly, with no
error or panic anywhere in its 4h12m log. The same datadir was then restarted on the `neox-v2.4.3`
binary with no debug tip, so the release had to catch the backlog accumulated during re-execution and
then follow dBFT production.

| Measure | Result |
|---|---:|
| Height at shutdown of the `2.4.2` node | `7,214,807` |
| First head published by `2.4.3` | `7,214,828` |
| Height after catching the backlog | `7,214,842` (reference `7,214,842`, delta `0`) |
| Final observed local head | `7,214,861` (reference `7,214,862`, delta `1`) |
| Bad blocks, root mismatches, unwinds | `0` |
| Errors, panics | `0` |

Block `7,214,853` was compared field-for-field against the reference:

| | Value |
|---|---|
| Head hash | `0xe6f4b29e70a7b85be3809aa9b3a38318a161e0b848698689379f7b23155ef4ca` |
| State root | `0x6843a4fc64f66f7ffe8933a3b37996a07e297d0964b6fb28853da74c352de42d` |

Both matched exactly. The closing delta of `1` is the reference having produced one further block
between the two RPC reads, not a lag: the node had already matched the reference exactly at
`7,214,842` and continued importing and finalizing dBFT blocks after.

## Warnings observed

Three warning kinds appeared across 781 log lines, none a validation failure:

- Two `Rejected beacon transaction response for Neo X proposal` — a peer returned a response that did
  not match the proposal's missing-transaction request. Peer-side condition.
- Two `Blocked waiting for execution cache mutex` (66 ms, 110 ms) — cache contention during backlog
  catch-up.

No `ERROR`-level line, panic, bad block, state-root mismatch, or unwind occurred in either half of
the run.
