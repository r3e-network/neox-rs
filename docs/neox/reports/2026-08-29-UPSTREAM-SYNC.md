# Upstream sync — Reth — 2026-08-29

Scope: landing the drift identified by the [2026-08-29 audit](2026-08-29-UPSTREAM-AUDIT.md):
10 Reth commits `66a08aba22` → `3bc71d43f7`, merged onto the `neox` branch. The Neo X Geth oracle
did not move; no chain spec, genesis, or fork-schedule change.

## Headline

| | |
|---|---|
| Merge | `f6f0c5c077`, zero conflicts, 23 files +3201/−373 |
| Fork patches | all 7 Neo X-patched upstream files re-verified by tip-delta; every edit intact |
| One carry-patch | `crates/ethereum/node/tests/e2e/utils.rs` — see §2 |
| Decision | upstream #26861 accepted (pool minimum priority fee applies to local/private origins); operator note added to [`docs/neox/README.md`](../README.md) |
| Baseline | `source-baseline.toml`, root `README.md`, and `docs/neox/README.md` advanced to `3bc71d43f7` (`2.5.1`) |

## 1. Gates

Run on this host (Windows, stable 1.95 MSVC, `CARGO_INCREMENTAL=0`, nightly rustfmt
`1.10.0-nightly e457a7b0d`), per the environment recipe in the
[2026-08-29 validation report](2026-08-29-FULL-VALIDATION.md) §1a.

| gate | result |
|---|---|
| Nightly rustfmt `--check` | pass |
| Strict clippy, Neo X set, `--all-targets -D warnings` | pass |
| Neo X package tests (9 packages) | **all 18 suites ok, 0 failed** (362-test suite shape) |
| `neox-rs` binary | builds; `--version` reports `f6f0c5c077`. One transient compile failure immediately after the test step did not reproduce on rerun. |
| `reth-storage-overlay` (new crate) | 68 passed, 0 failed |
| `reth-transaction-pool` | 296 passed, 0 failed — includes the #26861 change and its new origin tests |
| `reth-tasks` / `reth-rpc-builder` / `reth-downloaders` / `reth-node-ethereum` (lib) | all pass (31 / 50+ / 70 / 36) |
| `reth-provider` at `--test-threads=4` | 224/233 — the same 9 static-file truncate/prune failures classified in the validation report §3 (Windows `ERROR_USER_MAPPED_FILE`); unchanged from the pre-merge classification |
| `zepter` / `dprint` (`lint-toml`) | **skipped** — neither tool is installed on this host (matches the 2026-08-28 practice); the only TOML deltas are upstream's own committed files plus the three-line baseline edit |

Not runnable on this host, therefore not gate-relevant: `reth-e2e-test-utils` (lib/e2e/rocksdb
targets) and `reth-node-ethereum` (e2e/it targets) spawn real nodes and require a Linux loopback
interface (`Failed to read network interface IP if_name="lo": interface not found: lo`). These are
ubuntu-runner suites upstream and were not part of the host's gate set on 2026-08-28 either.

## 2. The carry-patch

Upstream's new `crates/ethereum/node/tests/e2e/utils.rs` (#26865) calls
`rng.random().collect::<Vec<u8>>()`. In this workspace's dependency resolution,
`encode_unicode`'s blanket `FromIterator` impls join the graph and rustc can no longer infer the
element type (E0283); upstream's lockfile does not contain that crate, which is why their CI
passes. The fork patch annotates `rng.random::<u8>()` — behavior-identical, trivially
upstreamable, and tracked as fork divergence on that file until it lands upstream.

## 3. Explicit non-claims

- A green compile and unit suite is not consensus parity. The live gates are unchanged and still
  required before any release note: fresh-datadir MainNet sync with restart equality,
  mixed-client SNAP/ETH + dBFT production, crash/unwind/reorg across the persistence boundary,
  the DKG epoch gate, and the RPC differential gate.
- The `reth-provider` Windows failures are the documented upstream-prune/mmap platform artifacts,
  not regressions from this merge; the failing set and root causes are identical to the
  pre-merge run recorded earlier today.
