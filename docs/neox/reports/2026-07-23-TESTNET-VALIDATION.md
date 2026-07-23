# Neo X TestNet full-chain validation - 2026-07-23

## Outcome

**Full-node canonical parity: PASS.** A fresh NeoX-Reth database replayed every canonical
TestNet block from genesis through block `9,167,856`, including all `317,350` transactions in
that range. The replay crossed every configured Neo X protocol boundary without a header,
body, execution, state-root, or trie error. Historical RPC comparisons against Neo X Geth also
matched at genesis, periodic heights, every fork boundary, and transaction-bearing samples.

**All-protocol production qualification: NOT YET PASS.** Once the node was brought near the tip it
followed and finalized live dBFT/Anti-MEV blocks correctly, including transaction-bearing blocks.
The original candidate failed an unpinned 6,750-block catch-up, but RC6 subsequently passed an
unpinned 8,026-block catch-up and implemented the reviewed DKG runtime remediations. The remaining
limit is live mixed-client validator/DKG fault requalification, so this evidence does not support
the stronger claim that every validator-originated Neo X protocol path is production-qualified.

**Release status: validator mode remains pre-release.**

## Historical replay identity

| Item | Value |
| --- | --- |
| Rust binary | `target/release/neox-rs` |
| Binary SHA-256 | `503dd3d5da39bbd308e3fb064851501461fed9925dc0c8a19b1c5517f485043c` |
| Embedded commit | `0d34dd1c239ffd3481781256b7f91ba9aa047bdb` |
| Rust client string | `reth/v2.4.1-0d34dd1/x86_64-unknown-linux-gnu` |
| Reference endpoint | `https://testnet-1.rpc.banelabs.org` |
| Reference client | `Geth/./node/v0.6.0-stable-eed1d304/linux-amd64/go1.26.3` |
| Chain | `neox-testnet` (`12227332`) |
| Validation datadir | `/home/neo/.cache/neox-rs-validation/testnet-20260723` |
| Node log | `/home/neo/.cache/reth/logs/12227332/reth.log` |

The repository contained pre-existing uncommitted Neo X changes during validation. The binary
SHA-256 above is therefore the authoritative identity of the replayed artifact; the embedded
commit alone is not a complete source provenance record.

The later RC6 large-gap gate used a separately built max-performance artifact:

| Item | Value |
| --- | --- |
| Rust binary | `target/maxperf/neox-rs` |
| Binary SHA-256 | `89101971d4277e9cad0c15fdc243698fdbcecf3b05b6b268426591100c7537e2` |
| Embedded commit | `0d34dd1c239ffd3481781256b7f91ba9aa047bdb` |
| Build flags | `RUSTFLAGS='-C target-cpu=x86-64'`, profile `maxperf`, locked dependencies |
| Validation clone | `/home/neo/.cache/neox-rs-validation/testnet-rc6-backfill-20260723` |
| Node log | `/home/neo/.cache/neox-rs-validation/rc6-backfill-logs/12227332/rc6-backfill.log` |

This worktree artifact predates the release commit, so its SHA-256, rather than its embedded commit,
identifies the live-gate executable. Published artifacts are built again from the exact annotated
release tag and receive their own checksums.

The TestNet reference was pinned before replay so that a moving live tip could not make the
result ambiguous:

| Point | Height | Hash | State root |
| --- | ---: | --- | --- |
| Genesis | 0 | `0x221f7d0a47dd80fe10f476625d62303947c9cd336113e119c64d919f0e9beb71` | matched Geth |
| Pinned target | 9,167,856 | `0xc92e8e96043ae76ba3d9ed0e3e8e7e141c6f9a04264974ab3e6cc9387c1dd63f` | `0x48298983992344dee28a77ec8ea1912e145e7a9d5c6d3657aff2b55ae6c6623e` |

Genesis chain ID, block hash, state root, `extraData`, and `mixHash` matched the Geth reference.
After a restart, the pinned target's hash, state root, and body also matched.

## Full genesis-to-target replay

The fresh database was run with the pinned target and terminate-after-backfill controls. The
process exited successfully after all 13 forward stages reached block `9,167,856`.

- Headers processed: `9,167,856` after genesis; zero header validation or timeout errors.
- Bodies flushed: `9,167,856`; `210,617` downloaded body responses.
- Transactions executed and persisted: `317,350`.
- Body validation errors: zero. The `1,142` reported unexpected body-download errors were peer
  disconnect/churn events; no block-invalid response occurred and the retry path completed.
- Sender recovery, execution, hashing, Merkle execution, transaction lookup, indexing, and
  finish stages all completed at the pinned target.
- No bad block, required unwind, state-root mismatch, validation failure, or panic occurred.
- The single `engine::tree` internal-event `SendError` appeared only after the node logged its
  terminate-after-backfill decision and graceful shutdown. It was shutdown-channel teardown,
  not an import failure.

The replay crossed these activation boundaries:

| Protocol boundary | Last block before | First active block |
| --- | ---: | ---: |
| DKG | 1,990,079 | 1,990,080 |
| Anti-MEV | 2,087,999 | 2,088,000 |
| Ethereum signatures | 3,749,999 | 3,750,000 |
| Cancun/Prague timestamp boundary | 5,729,057 | 5,729,058 |
| Osaka timestamp boundary | 8,526,007 | 8,526,008 |

## Database integrity

At the pinned target, the principal row counts were:

| Dataset | Entries |
| --- | ---: |
| Headers | 9,167,857 |
| Block body indices | 9,167,857 |
| Transactions | 317,350 |
| Receipts | 317,350 |
| Recovered senders | 317,350 |
| Transaction hash-to-number mappings | 317,350 |

The pinned static-file/RocksDB checksums were:

| Dataset | Checksum |
| --- | --- |
| Headers | `0x4b19b49c85ee6e1` |
| Transactions | `0xa5fe686f860f2a8d` |
| Receipts | `0x35299a237ad923b6` |
| Transaction senders | `0x5d0651942a5500a` |
| Transaction hash numbers | `0x648e5ac06428be9` |

An offline dry-run trie repair found `0` inconsistencies.

The apparent sender-recovery and transaction-lookup checkpoint count differences are storage-V2
reporting semantics, not missing transactions. Sender recovery calculates its progress while its
static-file writer is still live, before pipeline finalization makes the last rows visible to the
counter. Transaction lookup V2 stores every hash-to-number mapping in RocksDB while its generic
MDBX/static-file counter reports zero. The physical row counts above verify the complete datasets.

## Geth RPC differential checks

`scripts/neox-rpc-differential.py` compared the local Rust node with the reference Geth node.
Every completed comparison returned zero mismatches.

- Genesis and every millionth height from `0` through `9,000,000`.
- The block before, at, and after all five protocol boundaries listed above.
- Transaction-bearing execution samples with unrestricted transaction checking:

| Height | Transactions | Differential checks |
| ---: | ---: | ---: |
| 1,990,082 | 13 | 479 |
| 2,087,788 | 1 | 71 |
| 3,750,086 | 1 | 71 |
| 5,728,923 | 1 | 71 |
| 8,526,025 | 2 | 105 |
| 9,167,801 | 1 | 71 |

The execution comparisons covered blocks, transactions, receipts, sender recovery, and supported
historical calls. Head-only fee methods were intentionally skipped for historical heights. One
boundary group and the five-million sample encountered transient reference TLS EOF/timeouts; the
same comparisons passed on retry and produced no content mismatch.

During live follow, an aligned-head differential also passed with height skew `0`, `40` checks,
no skipped methods, and no mismatch. This included `eth_gasPrice`, `eth_envelopeFee`, and
`eth_maxEnvelopeGas` at the shared head.

## Live synchronization and finalization

Three live-sync conditions were tested:

1. Starting unpinned at block `9,167,856`, approximately 6,750 blocks behind the live Geth tip,
   did not make canonical progress for more than nine minutes. The node remained healthy and
   accepted peer gossip, but staged header backfill never started.
2. Pinning the then-current Geth head at block `9,174,606` caused the normal pipeline to fetch
   exactly 6,750 headers and bodies and run all 13 stages to that target successfully.
3. Restarting unpinned from block `9,174,606` followed the live network normally. Rust and Geth
   repeatedly matched height, block hash, and state root. In the sampled interval the Rust node
   validated/finalized 32 propagated blocks with no error; blocks `9,174,667` and `9,174,672`
   each contained a transaction and were imported successfully.

The node was stopped cleanly at local canonical block `9,174,707`. The final offline audit found:

- all forward-stage block checkpoints at `9,174,707`;
- `9,174,708` headers and body-index rows, including genesis;
- `317,444` transactions, receipts, recovered senders, and transaction hash mappings;
- zero trie inconsistencies.

Once that height was historical, Geth returned the same final Rust block hash
`0xc52177604fefd4b918ffc96225801e5b27db3179797d606ff4cf948dfaac744e`, parent hash, state root
`0x486224f9c2af3318fe89ab4452b90d1f9e9684a690a7cc7d74dcb4fdbd006366`, transaction root, and
receipts root at block `9,174,707`.

Final live-tip checksums:

| Dataset | Entries | Checksum |
| --- | ---: | --- |
| Headers | 9,174,708 | `0x6d212baec6f02262` |
| Transactions | 317,444 | `0xb4c72d5a5071671d` |
| Receipts | 317,444 | `0x3050a3accff0ed05` |
| Transaction senders | 317,444 | `0xd6e114c42cf2b96a` |
| Transaction hash numbers | 317,444 | `0xb764769d58a931fd` |

## Reproducible large-gap live-sync limitation (historical candidate)

The failed unpinned catch-up is a real synchronization defect, not a canonical data mismatch.
Observed metrics during the stalled run included:

- canonical updates: `0`;
- downloaded/flushed/queued headers: `0`;
- more than 250 syncing forkchoice responses;
- active block-download accounting growing beyond one million;
- repeated `canonical gap; requesting descendant backfill` messages.

The Neo X path schedules `NewBlockHashes` through `DescendantSyncTargets` in
`crates/neox/node/src/sync.rs`, but propagated full blocks directly submit a forkchoice target with
the current canonical head as both safe and finalized. The Reth engine treats the unknown head as
a single-block/range download instead of starting staged backfill. Repeated propagated blocks then
append large range requests, whose requested length exceeds the normal 1,024-header peer response
limit. This accounts for the stalled pipeline and growing download metric. A fixed target avoids
the path, which is why the 6,750-block pinned catch-up completed.

This historical failure established the required release regression: start unpinned several
thousand blocks behind, enter one bounded staged backfill, reach the moving head, and transition to
live dBFT follow without operator pinning. RC6 satisfies that regression below.

## RC6 large-gap remediation requalification

The `neox-v2.4.1-rc.6` candidate changes far-ahead full-block handling to coalesce descendant
targets and submit an optimistic forkchoice target whose safe and finalized hashes are zero. A
fresh live test on 2026-07-23 repeated the previously failing unpinned scenario against a clone of
this TestNet database:

- the clone was unwound from block `9,174,707` to `9,167,856` without modifying the source database;
- the start was block `9,167,856`, hash
  `0xc92e8e96043ae76ba3d9ed0e3e8e7e141c6f9a04264974ab3e6cc9387c1dd63f`;
- the live peer target was block `9,175,882`, hash
  `0xb118968c6df0d0520f573c7a44820148bcfbfbe9d7165761efbe979d6b71f81e`, an
  `8,026`-block gap;
- exactly one staged backfill downloaded `8,026` headers and bodies, processed 112 transactions in
  the recovered range, and completed all 13 stages at the target;
- the node transitioned without operator pinning to live dBFT/Anti-MEV processing and continued
  finalizing 111 contiguous canonical blocks from `9,175,883` through `9,175,993`, whose final hash
  was `0x2f295388d21a980b9ec8ff328717b5e9dcd31cb7c18a6a143b1fbe92b78986d3`;
- live blocks `9,175,897`, `9,175,908`, `9,175,957`, and `9,175,991` each carried a transaction;
- block `9,175,905` passed 37 RPC comparisons at zero head skew with no mismatch; and
- transaction-bearing block `9,175,897` passed 71 comparisons, including its transaction and
  receipt, with no mismatch.

The node shut down cleanly with every forward-stage checkpoint at `9,175,993`. A separate offline
trie consistency command found zero inconsistencies; the RPC differentials above were also separate
command gates rather than values inferred from the node log. This supersedes the historical
candidate's unattended large-gap **FAIL** above for RC6. It does not expand the validator
qualification claim: mixed-client DKG and validator fault scenarios remain prerelease gates.

## Validator and DKG qualification

Production wiring for dBFT, Anti-MEV, threshold encryption, proposal reconstruction, DKG share
handling, and the managed DKG runtime is present. Canonical replay exercises the historical
consensus and execution rules, and near-tip follow exercised live block validation/finalization.
It does not exercise every validator-originated fault path.

The candidate review identified four runtime risks that required remediation and fault-injection
coverage before validator release:

- same-head DKG maintenance can skip a heartbeat, delaying a proof completed after its spawning
  heartbeat until the next block and potentially beyond an exclusive deadline;
- DKG transaction ownership can be discarded on receipt/task retirement before the final head
  fence, leaving a transaction reinserted by reorg untracked;
- an initial heartbeat failure can return without the same signer/pool cleanup used by later
  failure paths;
- an empty changed recovery snapshot resets memory without necessarily persisting the reset.

RC6 implements code fixes for all four cases: same-head heartbeats perform maintenance, owned
transactions remain fenced through the final canonical-head check, initial heartbeat failures use
the canonical invalidation path, and changed empty recovery snapshots are persisted. Their live
mixed-client fault-injection qualification remains open.

The final mixed-client validator gate must still run one Rust validator with the remaining Geth
validators through complete DKG epoch transitions, prover delay/failure, transaction replacement,
reorg, and live Anti-MEV encrypted transaction decryption/reconstruction. No funded user
transaction was broadcast as part of this read-only public TestNet validation.

## Qualification decision

| Claim | Decision |
| --- | --- |
| Rust full node reproduces the Geth TestNet canonical chain | **PASS** |
| All historical TestNet blocks and transactions through the pinned target execute consistently | **PASS** |
| Near-tip dBFT/Anti-MEV live import and finalization are consistent | **PASS for the observed interval** |
| Unattended live catch-up from a multi-thousand-block gap | **FAIL in the historical candidate; PASS in the RC6 requalification** |
| Every validator/DKG/Anti-MEV production path is fully qualified | **NOT YET** |
| Validator release readiness | **PRE-RELEASE** |

No invalid block acceptance, state-root divergence, or canonical chain split was observed. RC6
closes the reproduced synchronization liveness defect. The remaining negative qualification is
limited to unrerun live validator fault-injection gates, not a demonstrated disagreement in the
canonical blocks that were replayed.
