# Reth and Neo X Geth upstream sync — 2026-07-21

## Decision

The `neox` branch now incorporates Reth through
`e3823342ab0f07a909d886b8b4a9b65a1a3a8be3`. The Neo X Geth behavior oracle remains pinned to
`a0c80295ab2c7a6d0bc218e4bc85270f5610948c` because that commit is still the head of its
`bane-main` branch.

This update changes the Reth implementation baseline, not the Neo X protocol oracle or canonical
genesis inputs.

## Imported Reth range

The range from the previous baseline
`9ebad6c4b77e053cd15de448e8a402d40905e58e` through the new baseline contains 14 commits:

- `362979d5e8` feat(builder): pause jit while building payloads (#26429)
- `1a2054a195` fix(discv4): use provided rng in test utils instead of thread_rng (#26437)
- `e6d13ab741` chore: re-enable nightly Docker cron (#26440)
- `e61333f0fe` fix(rpc): align BAL lookup errors with spec (#26441)
- `6d0284257a` fix(rpc): add BAL debug method (#26438)
- `9d56213acc` test(net): add first snap e2e tests (#26368)
- `92cf59e2be` feat(trie): expose payload state root receiver (#26431)
- `9d2213bf9c` chore(deps): bump the ci-weekly group with 3 updates (#26443)
- `d036a1181d` feat(stages): add partial persistence finish checkpoint (#26447)
- `f969bd4de3` fix(discv5): advertise fork ENR entry on custom chain ids (#26449)
- `01d3400ffa` feat(engine): configure dev finality depth (#26451)
- `a04b780d6f` perf(trie): remove sparse trie memory accounting (#26458)
- `9b0c17c855` feat(metrics): engine thread resource usage (#26459)
- `e3823342ab` feat(trie): rebase partial proof roots (#26421)

The Neo X-sensitive changes are:

- custom Ethereum chain IDs now advertise an `eth` fork entry in discv5 ENRs without overwriting an
  explicitly configured network-stack key;
- SNAP storage-range requests accept Geth's empty-byte-string encoding for unbounded origin and
  limit fields;
- partial proof roots are rebased against the correct parent path, including compressed branch and
  singleton subtrie cases;
- sparse-trie retained-memory accounting is removed from the hot path, while engine-thread resource
  metrics add page-fault and context-switch observability.

## Verification

The merge completed without a source conflict; only `Cargo.lock` required automatic reconciliation.
The following local gates passed with stable Rust 1.97 (the workspace MSRV is 1.95):

- `cargo +nightly fmt --all -- --check`
- custom-chain discv5 fork-ID regression: 1 passed
- Geth empty-origin/limit SNAP regression: 1 passed
- `reth-trie`, `reth-trie-parallel`, and `reth-trie-sparse`: 289 tests and 1 doctest passed
- Neo X Rust package set: 224 tests passed
- strict Neo X Clippy with `--locked --all-targets -- -D warnings`
- `cargo +stable build --locked -p neox-rs --bins`
- Neo X DKG prover: Go test and trimmed build passed
- Python compatibility tools: 60 tests passed

The first targeted test invocation used the host's default Rust 1.91 nightly and stopped before
compilation because the workspace requires Rust 1.95. It was rerun with the CI-aligned stable
toolchain; this was an environment selection issue, not a code or test failure.

## Remaining external gates

These local gates establish compile-time, unit, codec, trie, and tooling compatibility. They do not
replace the live external gates required before a release:

- a fresh-datadir Neo X MainNet sync with final block hash, parent hash, state root, transactions
  root, and receipts root equal to the Neo X Geth/reference RPC;
- restart with the sync donor offline and the same root/hash equality after reopening the database;
- mixed-client SNAP/ETH synchronization and sustained dBFT production;
- crash, unwind, and controlled-reorg validation across a partially persisted trie boundary;
- at least three fresh-datadir runs per sync source before publishing performance comparisons.

Do not treat this baseline update alone as proof that an unreleased Reth partial-persistence change
or an open Neo X Geth protocol PR is safe to adopt.
