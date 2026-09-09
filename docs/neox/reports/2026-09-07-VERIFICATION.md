继续

# 继续



## Overview

Continue closing the gap to a “100% protocol equivalence” claim after the  
[2026-09-07 full audit](2026-09-07-FULL-AUDIT.md) and the three P2 liveness fixes.  
This document is the plan and running log for verification that can execute on the  
Windows host; live mixed-client / DKG epoch gates that need Geth + ceremony artifacts  
are recorded as blocked with exact preconditions.

## API Reference — gate matrix


| Gate ID | Gate                           | Pass criterion                                           | Host runnable?                     |
| ------- | ------------------------------ | -------------------------------------------------------- | ---------------------------------- |
| G1      | Neo X Rust crate suite         | All `reth-neox-*` + `neox-rs` tests green                | Yes                                |
| G2      | Strict clippy Neo X crates     | `-D warnings` clean                                      | Yes                                |
| G3      | Python tooling / baseline docs | `scripts/tests` green (platform skips OK)                | Yes                                |
| G4      | Anti-MEV cross-impl vectors    | `reth-neox-antimev` integration vectors green            | Yes                                |
| G5      | RPC differential vs reference  | `neox-rpc-differential.py` 0 mismatches at chosen height | Needs two live HTTP endpoints      |
| G6      | Full differential              | `neox-full-differential.py` 0 mismatches                 | Needs synced local + reference     |
| G7      | Fresh-datadir MainNet sync     | Head hash matches reference; restart equality            | Needs long run + peers             |
| G8      | Mixed-client DKG epoch         | Successful 7-msg share + round transition                | Needs Geth + prover + ZK artifacts |
| G9      | PKCS#7 strict coordinated      | Both clients patched + activation height set             | Governance / ops                   |


## Design

1. Close every offline/static gate first and record evidence in this file.
2. Attempt live RPC against a public reference if one is reachable; otherwise mark G5–G7 blocked.
3. Do not claim 100% equivalence until G5–G8 pass with reproducible logs.

## Usage

```bash
source /c/Users/Administrator/AppData/Local/Temp/neox-msvc-env.sh
cargo test -p reth-neox-node -p reth-neox-antimev -p reth-neox-network \
  -p reth-neox-consensus -p reth-neox-consensus-engine -p reth-neox-evm \
  -p reth-neox-chainspec -p neox-rs
cargo clippy -p reth-neox-node -p reth-neox-antimev -p reth-neox-network \
  -p reth-neox-consensus -p reth-neox-consensus-engine -p reth-neox-evm \
  -p reth-neox-chainspec -p neox-rs --all-targets --no-deps -- -D warnings
python -m pytest scripts/tests -q
```

## Test cases / expected outcomes


| Case  | Expected                                                                     |
| ----- | ---------------------------------------------------------------------------- |
| G1–G4 | Pass on this host with MSVC env wrapper                                      |
| G5    | Pass only if local `neox-rs` HTTP and a reference Neo X RPC are both healthy |
| G6–G8 | Pass only with full topology; otherwise **BLOCKED** with listed missing deps |


## Results log

### 2026-09-07 host run (post-P2 remediation)


| Gate                                    | Result                                                                                                                                                           | Evidence                                                                                                            |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| G1 Neo X Rust suite                     | **PASS** — 419 tests, 0 failed                                                                                                                                   | `cargo test -p reth-neox-{node,antimev,network,consensus,consensus-engine,evm,chainspec} -p neox-rs --tests --lib`  |
| G2 Strict clippy                        | **PASS**                                                                                                                                                         | same packages, `--all-targets --no-deps -D warnings`                                                                |
| G3 Python tooling                       | **PARTIAL** — protocol/script unit tests **53 OK**; `test_install_sh` **env-blocked** (WSL `bash` timeout + GitHub SSL download failure). Not a protocol defect. | `unittest` excluding install.sh download paths                                                                      |
| G4 Anti-MEV cross-impl vectors          | **PASS** — included in G1 (47 lib + 47 integration)                                                                                                              | `geth_`* integration tests                                                                                          |
| G4b Go DKG prover                       | **PASS**                                                                                                                                                         | `CGO_ENABLED=0 go test ./...` in `tools/neox-dkg-prover`                                                            |
| G5 RPC differential height 0            | **PASS** — `status: ok`, **0 mismatches**, 37 checks                                                                                                             | Local `neox-rs` `:18545` vs `https://mainnet-1.rpc.banelabs.org`; artifact `outputs/rpc-diff-height0-20260907.json` |
| G5b Genesis hash                        | **PASS** — local node + reference both `0x2ee57478315c7d3182997a812d7885dafee48612cd88cb30b615847b0dd8dbd7`; chain id `0xba93` (47763)                           | `outputs/probe_ref_rpc.py`                                                                                          |
| G6 Full differential                    | **BLOCKED** — requires synced local head near reference (~7.63M); fresh sync started but not complete                                                            | Local node at Headers stage with peers=2                                                                            |
| G7 Fresh-datadir MainNet sync + restart | **IN PROGRESS** — Bodies+SenderRecovery **done**; **Execution** stage started (peers=5)                                                                   | `reth.log` / 21:47 checkpoint                                                                     |
| G8 Mixed-client DKG epoch               | **BLOCKED** — no `geth.exe`, no ceremony `.ccs`/`.pk`, no seven-validator topology on host                                                                       | Preconditions unchanged from 2026-09-01 audit                                                                       |
| G9 PKCS#7 strict coordinated activation | **OPEN** — governance; technical blocker removed 2026-09-09 (height-gated `geth-pkcs7-strict-height-gate.patch` verified); still needs both-side deployment + one activation height + dual-mode vector regression | see [2026-09-09-COMMIT-VERIFICATION.md](2026-09-09-COMMIT-VERIFICATION.md)                                           |


### Counts (G1 detail)


| Package                         | Passed           |
| ------------------------------- | ---------------- |
| `reth-neox-node`                | 172              |
| `reth-neox-network`             | 47               |
| `reth-neox-antimev` lib         | 47               |
| `reth-neox-antimev` integration | 47 (3+9+14+5+16) |
| `neox-rs`                       | 29               |
| `reth-neox-evm`                 | 28               |
| `reth-neox-consensus`           | 18               |
| `reth-neox-chainspec`           | 17               |
| `reth-neox-consensus-engine`    | 14               |
| **Total**                       | **419**          |


### Live node notes

- Windows requires `--ipcdisable` (default `/tmp/reth.ipc` is not a named pipe).
- Reference head at probe time: **7,634,618**.
- Height-0 differential skips head-only Policy RPC methods (`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`) by design when heights differ — storage/system-contract checks still ran.

### Still required for a 100% claim

1. Complete G7 to tip; restart equality vs reference hash.
2. Re-run G5/G6 at tip (and sampled historical heights) with 0 mismatches.
3. Execute G8 mixed DKG epoch with successful share settlement.
4. Keep G9 inactive until coordinated Geth strict patch deployment.

**Campaign verdict after this run:** offline/static + genesis RPC gates are green; **100% protocol equivalence is still not proven.**

### Progress checkpoint — 2026-09-07 ~12:42 CST

Live node: `outputs/verify-datadir`, HTTP `127.0.0.1:18545`, metrics `18552`.


| Metric                                                    | Value                                                                                  |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Stage                                                     | `Headers` (tip-first reverse download)                                                 |
| Peers                                                     | 2 (beacon/dbft established; remote head ≈ tip)                                         |
| Headers covered                                           | ~~2.26M of ~7.63M (~~29.6% toward genesis)                                             |
| Latest batch                                              | `from=5384618` → `to=5374619`                                                          |
| Rate                                                      | ~1203 headers/s                                                                        |
| ETA headers→genesis                                       | ~74 min (bodies/execution still after)                                                 |
| Local `eth_blockNumber`                                   | **0** (expected until Headers links to genesis)                                        |
| Reference tip                                             | 7,634,807                                                                              |
| Genesis consistency                                       | **PASS** — local = ref = `0x2ee57478…dd8dbd7`                                          |
| Height-0 RPC differential (recheck)                       | **PASS** — 0 mismatches / 37 checks (`outputs/rpc-diff-height0-recheck-20260907.json`) |
| Mid-chain sample presence (1 / 100 / 1e6 / AntiMev / tip) | local **absent** until Headers completes — not a mismatch yet                          |
| Probe artifact                                            | `outputs/sync-progress-20260907.json`                                                  |


### Progress checkpoint — 2026-09-07 ~14:06 CST


| Metric              | Value                           |
| ------------------- | ------------------------------- |
| Stage               | `Headers` (still reverse)       |
| Peers               | 2                               |
| Headers covered     | ~~6.01M of ~7.63M (~~**78.7%**) |
| Latest batch        | ~`1624618`→`1614619`            |
| Rate                | ~865 headers/s                  |
| ETA headers→genesis | ~**31 min**                     |
| Local head          | still **0** (expected)          |
| Genesis match       | still **PASS**                  |


Previous noon checkpoint was ~30%; node remains healthy and progressing.

### Progress checkpoint — 2026-09-07 ~14:00 CST


| Metric              | Value                                               |
| ------------------- | --------------------------------------------------- |
| Stage               | still `Headers`                                     |
| Peers               | 2                                                   |
| Headers covered     | ~~5.80M of ~7.63M (**~~76%**)                       |
| Latest batch        | `from=1844618` → `to=1834619`                       |
| Rate                | ~878 headers/s                                      |
| ETA headers→genesis | ~35 min                                             |
| Local head          | still **0** (expected)                              |
| Genesis match       | still **PASS**                                      |
| Probe artifact      | `outputs/sync-progress-20260907.json` (overwritten) |


### Progress checkpoint — 2026-09-07 ~13:39 CST


| Metric                          | Value                                                            |
| ------------------------------- | ---------------------------------------------------------------- |
| Stage                           | still `Headers`                                                  |
| Peers                           | 2                                                                |
| Headers covered                 | ~~5.07M of ~7.63M (**~~66%**)                                    |
| Latest batch                    | `to≈2,564,619`                                                   |
| Rate                            | ~955 hdr/s                                                       |
| ETA headers→genesis             | ~**45 min**                                                      |
| Local head                      | 0 (expected)                                                     |
| Genesis / height-0 differential | still **PASS** (recheck `outputs/rpc-diff-height0-1338.json`)    |
| Wait monitor                    | `outputs/sync_wait_headers.py` polling until stage flip / head>0 |


### Progress checkpoint — 2026-09-07 ~13:22 CST


| Metric                          | Value                         |
| ------------------------------- | ----------------------------- |
| Stage                           | still `Headers`               |
| Peers                           | 2                             |
| Headers covered                 | ~~4.43M of ~7.63M (**~~58%**) |
| Latest batch                    | `from=3204618` → `to=3194619` |
| Rate                            | ~1030 headers/s               |
| ETA headers→genesis             | ~52 min                       |
| Local head                      | 0                             |
| Genesis + height-0 differential | still PASS (rechecked)        |
| Uptime                          | ~72 min                       |


Monitor: `outputs/sync_monitor.py` → `outputs/sync-monitor-20260907.jsonl`

### Progress checkpoint — 2026-09-07 ~18:22 CST (peer-stall recovery)

G7 stalled after last header batch `934618→924619` (~88% toward genesis) when
`connected_peers` dropped to 0 (~06:37 UTC) and discovery did not re-dial — the failure mode
documented in [OPERATIONS.md](../OPERATIONS.md). Offline gates G1–G5 / G4b remain green; the three
P2 remediations stay uncommitted in the worktree and are covered by unit tests
(`prepares_submits_checks_and_retries_stable_calldata`,
`transient_backoff_becomes_ready_after_deadline_without_new_contributions`).

| Metric | Value |
| --- | --- |
| Action | Stopped stalled PID; restarted with official MainNet bootnodes as `--trusted-peers` |
| Peers after restart | **2** (stable so far) |
| Stage | `Headers` (tip-first reverse walk restarted from tip ≈7.637M) |
| Progress (~2 min) | last `to_block≈7.497M`; ~1030 hdr/s; ETA headers→genesis ≈**2.0 h** |
| Genesis match | still **PASS** |
| Local head | still **0** (expected until Headers links) |
| Reference tip | ≈7,637,107 |
| Datadir | `outputs/verify-datadir` (~8.7 GiB retained across restart) |
| Monitor | `outputs/sync_wait_headers.py` (log → terminal `942161`, 180 min budget) |
| P2 regression | **PASS** — `cargo test -p reth-neox-node --lib -- prepares_submits… transient_backoff…` |

**Campaign verdict unchanged:** offline/static + genesis RPC gates green; G7 not yet tip-equal;
**100% protocol equivalence is still not proven.**

### Evening follow-up — 2026-09-07 ~18:27 CST

While G7 Headers continues (~4.5% reverse, peers=2, ~1030 hdr/s):

- Closed two P3 audit items: `decrypt_and_validate` now defaults to legacy PKCS#7; added
  `legacy_mode_accepts_reference_client_padding_matrix` in `geth_negative_vectors`.
- `sync_wait_headers.py` now tracks `net_peerCount` and exits with `peerless_stall` after 10
  consecutive zero-peer polls (avoids another silent 4h hang).
- Targeted tests green: antimev decrypt + legacy PKCS#7 matrix.

### Progress checkpoint — 2026-09-07 ~19:15 CST

Cursor's terminal capture for the node (`942161.txt`) froze around 10:48 UTC while Headers kept
advancing; monitors now read `reth.log` as the source of truth.

| Metric | Value |
| --- | --- |
| Stage | still `Headers` (tip-first reverse) |
| Peers | **5** (`net_peerCount`) |
| Headers covered | ~~3.21M of ~7.64M (**~~42%**) |
| Latest batch | `to_block≈4.43M` (from `reth.log`) |
| Rate | ~1040 hdr/s |
| ETA headers→genesis | ~**71 min** |
| Local head | still **0** (expected) |
| Genesis match | still **PASS** |
| Reference tip | ≈7,637,450 |
| Monitor | `outputs/sync_wait_headers.py` → `reth.log` + peerless abort |

### Progress checkpoint — 2026-09-07 ~19:36 CST

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **6** |
| Headers covered | ~~4.32M of ~7.64M (**~~56.6%**) |
| Latest batch | `to_block≈3.32M` |
| Rate | ~978 hdr/s |
| ETA headers→genesis | ~**57 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Reference tip | ≈7,637,609 |
| Follow-on | `outputs/sync_post_headers_gates.py` armed for stage-flip → sampled tip RPC |

### Progress checkpoint — 2026-09-07 ~19:40 CST

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **6** |
| Headers covered | ~~4.45M of ~7.64M (**~~58%**) |
| Latest batch | `to_block≈3.19M` |
| Rate (recent window) | ~870–980 hdr/s |
| ETA headers→genesis | ~**60 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Monitors | headers wait + `sync_post_headers_gates.py` (auto tip sample diffs) |

### Progress checkpoint — 2026-09-07 ~20:23 CST

20-minute watch (`WINDOW_DONE`): no stage flip, `header_to` still above 1M.

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **2** (was 6 earlier in the window) |
| Headers covered | ~~5.90M of ~7.64M (**~~77%**) |
| Latest batch | `to_block≈1.74M` |
| Rate (recent window) | ~555 hdr/s |
| ETA headers→genesis | ~**52 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Downloader | still flushing; `unexpected_errors` rose ~28→63 (non-fatal) |

### Progress checkpoint — 2026-09-07 ~20:39 CST

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **2** (stable) |
| Headers covered | ~~6.35M of ~7.64M (**~~83%**) |
| Latest batch | `to_block≈1.29M` |
| Rate (recent window) | ~517 hdr/s |
| ETA headers→genesis | ~**42 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Note | Approaching prior stall floor (~924k from first run); gap `0…924k` still required |

### Progress checkpoint — 2026-09-07 ~20:48 CST

Watch-to-1M **done**: `header_to` crossed below 1M (`997104`); still on Headers.

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **2** |
| Headers covered | ~~6.65M of ~7.64M (**~~87%**) |
| Latest batch | `to_block≈987k` |
| Rate | ~514 hdr/s |
| ETA headers→genesis | ~**32 min** |
| Local head | still **0** |
| Next | Pass prior stall floor (~924k), then fill gap to genesis |

### Progress checkpoint — 2026-09-07 ~21:04 CST

Prior stall floor (~924k) **cleared**; reverse walk continues through the previously missing gap.

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **3** |
| Headers covered | ~~7.14M of ~7.64M (**~~93.5%**) |
| Latest batch | `to_block≈497k` |
| Rate | ~502 hdr/s |
| ETA headers→genesis | ~**17 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |

### Progress checkpoint — 2026-09-07 ~20:11 CST

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **6** |
| Headers covered | ~~5.60M of ~7.64M (**~~73%**) |
| Latest batch | `to_block≈2.04M` |
| Rate (recent window) | ~656 hdr/s (slower than early ~1k; still advancing) |
| ETA headers→genesis | ~**52 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Reference tip | ≈7,637,851 |
| Note | Approaching prior stall band (~924k); first-run headers above that may merge |

### Progress checkpoint — 2026-09-07 ~20:03 CST

| Metric | Value |
| --- | --- |
| Stage | still `Headers` |
| Peers | **6** |
| Headers covered | ~~5.29M of ~7.64M (**~~69%**) |
| Latest batch | `to_block≈2.35M` |
| Rate (recent window) | ~714 hdr/s (slowed from ~1k earlier) |
| ETA headers→genesis | ~**55 min** |
| Local head | still **0** |
| Genesis match | still **PASS** |
| Reference tip | ≈7,637,791 |
| Note | Approaching prior stalled range (~924k); monitors still green |

### Progress checkpoint — 2026-09-07 ~21:20 CST

Watch returned **NEAR_GENESIS** (`to_block=1`). Reverse header download complete; pipeline now
executing the Headers stage commit (`pipeline_stages=1/13`).

| Metric | Value |
| --- | --- |
| Download | tip→genesis **complete** (`last_to=1`) |
| Stage status line | still reports `Headers` while committing |
| Peers | **4** |
| Local head | still **0** (expected until later stages advance tip) |
| Genesis match | still **PASS** |
| Next | Wait for Headers checkpoint / flip to Bodies → Execution → tip equality |

### Progress checkpoint — 2026-09-07 ~21:36 CST

Headers wait monitor **complete** (`reason=stage_Bodies`). Pipeline flipped to Bodies.

| Metric | Value |
| --- | --- |
| Headers | **DONE** (download + commit) |
| Stage | **Bodies** (`pipeline 2/13`) |
| Bodies checkpoint | advancing fast (~716k / 7.637M, ~9% within ~1 min of flip) |
| Peers | **4** |
| Local head | still **0** |
| Post-headers runner | detected `headers_finished`; waiting for tip catch-up before tip RPC diffs |

### Progress checkpoint — 2026-09-07 ~21:47 CST

Bodies watcher exited **STAGE_PAST_BODIES** after ~10 min: Bodies 100%, SenderRecovery finished,
pipeline now on **Execution** (`4/13`).

| Metric | Value |
| --- | --- |
| Bodies | **DONE** (7,637,103) |
| SenderRecovery | **DONE** |
| Stage | **Execution** (checkpoint starting at 0) |
| Peers | **5** |
| Local head | still **0** (advances as Execution/Finish progress) |
| Next | Execution → hashing/Merkle/history → Finish; then tip hash equality + RPC diffs |