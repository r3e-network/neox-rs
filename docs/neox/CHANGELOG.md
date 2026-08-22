# neox-rs changelog

Neo X release history for `neox-rs`, the Neo X execution and full-node client built on Reth. Reth's
own version history is upstream; this file tracks the Neo X layer.

## Unreleased

The compatibility baseline now follows Reth `dc83c609a8` (`2.5.1`) and Neo X Geth
`76580e6a54d7` (`bane-main`, `0.7.0-dev`). The Geth comparison contains 16 commits and 24 files;
the canonical MainNet and T4 genesis files are unchanged.

- Match Neo X Geth v0.6.2's Policy blacklist at every EVM call boundary. A blacklisted target now
  reverts `CALL`, `CALLCODE`, `DELEGATECALL`, and `STATICCALL` frames without aborting the parent,
  while precompiles remain exempt. The check reads current journaled Policy state without warming a
  storage slot, and the EIP-158 zero-value call to a nonexistent account keeps Geth's early-success
  edge case. Coverage includes internal calls, top-level targets, and precompile ordering.
- Sync the Reth execution/storage/RPC stack through `2.5.1`, including the provider-overlay and
  state-root API changes, BAL execution updates, and the generalized precompile-set boundary needed
  by the Neo X Policy-aware provider.
- Record the oracle's new GovPaymaster/private-genesis work as pending deployment work. No canonical
  chain spec is changed until the corresponding MainNet/T4 contract code and genesis hash move.
- Accept Geth's private-network validator counts (including the official one- and four-validator
  fixtures) end to end: chainspec parsing, dBFT difficulty/extra-data validation, Governance set
  decoding, canonical DKG storage/replay, keystore migration, and `KeyManagement` ABI encoding all
  use the configured committee size. New keystores can be initialized with
  `--validator.dkg-size`; threshold and interpolation scaler follow Geth's `antimev init` rules.
  ZK-v0 supports every deployed committee size, while ZK-v1 keeps Geth's one/two/seven circuit
  boundary.

## neox-v2.4.4 - 2026-07-28

Code review across three Neo X surfaces: the DKG keystore and its callers, the dBFT wire layer, and
the beacon protocol handler. Nothing here is consensus-visible — no block this client produces or
accepts changes, the on-disk keystore format is unchanged, and the pinned Reth baseline is unchanged
from `neox-v2.4.1`. The keystore fixes are in validator-only paths; the dBFT and beacon changes sit on
paths fed by unauthenticated peers.

The two keystore defects were found by reading `dkg_keystore.rs`, which is this client's own format
with no reference client to differ against. The dBFT and beacon work came out of differential review
against the pinned reference client, and the fork-id filter was confirmed to match it rule for rule.

- Keep the encrypted keystore off the async worker that hosts the DKG runtime. Every keystore read
  and write derives its AES key with scrypt at `log_n = 17`, which costs on the order of a quarter
  second of CPU and 128 MiB before any I/O happens, and `run_dkg_runtime` is spawned with
  `spawn_critical_task` — the shared async pool, whose workers also drive dBFT and networking. The
  five persist sites each ran that inline. Worst case is the round-revert branch, which loads and
  then immediately saves, blocking a worker for roughly half a second in one stretch. Keystore work
  now goes through `block_in_place`, which hands the worker's other tasks to a sibling thread first;
  callers with no multi-thread runtime under them (the pre-runtime CLI keystore commands, unit tests
  on `#[tokio::test]`) still run it directly, where blocking the caller is the intended behaviour.
- Report success from `atomic_write_new` once the keystore exists. The hard link is the commit point,
  but the function then unlinked its temporary and propagated any failure from that unlink, so a
  concurrent deleter — a tmp-reaper, a backup job, an operator sweeping `.<name>.tmp-*` out of the
  datadir — could make a completed write return an error, skipping the parent-directory `fsync` on
  the way out. From `create_encrypted_for_validator` that loses a freshly generated message private
  key from memory while a file containing it sits on disk, and the obvious retry then fails with
  `TargetAlreadyExists`. The durability barrier now runs before the cleanup, and the cleanup can no
  longer fail the call. Recovery for an operator who already hit this is unchanged: load the existing
  keystore with the same password.
- Hash each inbound dBFT consensus message once instead of twice. Authenticating a message recovers
  its witness against a keccak of the whole encoded message, and both the publish and inbound paths
  then called `hash()` again to key the dedup cache and announce the message. The wire limit allows a
  message to reach 4 MiB, so that second call re-encoded and re-hashed megabytes per message.
  `verify_witness` now hands back the hash it already computed.
- Derive both dBFT seal schemes from one reconstructed unsigned header. `ecdsa_seal_hash` and
  `threshold_seal_message` each rebuilt the header independently, so the two schemes could drift on
  which bytes a seal commits to while each kept verifying against its own view. Behaviour is
  unchanged: the live MainNet V0 ECDSA and V2 threshold vectors still validate and a tampered
  signature still rejects.
- Log beacon streams declined at the admitted-peer ceiling. A connection that cannot reserve its
  lifecycle event slots is refused at admission so it can always report its own disconnect, but the
  peer still completes the RLPx handshake, so the stream simply looked idle with nothing in the logs
  to explain it. The refusal and the ceiling it hit are now recorded. Note that the ceiling is fixed
  at 128 concurrent beacon peers and does not widen with the node's peer limit.
- Pin the `alloy-rlp` bounds check that dBFT message parsing depends on. `take_rlp_item` splits a
  buffer at a length taken from an item header, which is sound only because `Header::decode` rejects a
  declared payload length that runs past the buffer. That check lives in the dependency, so a
  regression test now fails if it ever goes away rather than a malformed peer message panicking the
  node.
- Recover tagged releases independently of the Reth package version. The release workflow takes its
  version from the `neox-v*` tag, so a Neo X-only release no longer needs the workspace version to
  move, and a failed tag run can be repackaged by dispatch against the exact tag commit.

## neox-v2.4.3 - 2026-07-26

Two fixes found by differential review against the pinned reference client. Neither is
consensus-visible: no block this client produces or accepts changes, and the pinned Reth baseline is
unchanged from `neox-v2.4.1`. The blob-sidecar fix closes a remotely triggerable way to lose beacon
peers, and the keystore fix unblocks Geth Anti-MEV keystore migration for any operator whose password
is not pure printable ASCII.

Both defects share a shape worth naming: a rule the code recorded correctly in a comment or borrowed
from a Go library, and then did not apply. `MAX_BLOB_REQUEST_TTL` documented the oracle's bound and
was referenced nowhere; the keystore reimplemented the reference encryptor's envelope faithfully and
skipped the passphrase normalisation that runs before it.

This release has been validated against the full MainNet chain. Every canonical block from `1` through
`7,214,807` was re-executed with the release binary and reproduced every stored state root, with no
mismatch, bad block, or required unwind; the same datadir then restarted on the release, caught the
backlog, and followed dBFT production to the reference head with matching hash and state root. Note
that neither fix is reachable from block execution — one is in beacon request serving, the other in an
offline migration utility — so this run establishes that neither regressed historical execution rather
than exercising the fixes, which are covered by their unit tests. Validator mode remains experimental.
See [MainNet validation — 2026-07-26](reports/2026-07-26-MAINNET-VALIDATION.md).

- Enforce the reference client's `GetBlobs` TTL bounds when serving or forwarding a blob-sidecar
  request. `MAX_BLOB_REQUEST_TTL = 3` was declared with the oracle's rule in its doc comment and
  never referenced, so this client accepted any TTL up to `255`. Because the forwarding path re-emits
  `ttl - 1` to its own peers, a single request from one peer carrying `ttl = 255` made this node send
  an over-range request onward, and the reference client treats an out-of-range TTL as a
  connection-terminating protocol error: `handleGetBlobs` rejects `Ttl < 1` and
  `handleGetBlobsPacket` rejects `Ttl > 3`, both returning an error from the message loop that
  disconnects the sender. One inbound message could therefore cost this node every Geth beacon peer
  it forwarded to. The bound is now checked before the store lookup, matching the oracle's ordering
  so the set of requests that produce a reply is identical. Not consensus-visible; blob sidecars do
  not contribute to the state root.
- Apply the EIP-2335 password rules when migrating an encrypted Geth Anti-MEV keystore. The reference
  client encrypts through `wealdtech/go-eth2-wallet-encryptor-keystorev4`, whose `normPassphrase`
  normalises the passphrase to NFKD and strips the C0, DEL and C1 code points before the KDF runs, so
  the stored key commits to the normalised text rather than to the bytes the operator supplied. This
  client derived from the raw password bytes, which agrees with the oracle only when the password is
  pure printable ASCII. A validator whose Geth password contained a composed non-ASCII character, a
  Unicode compatibility form, or an embedded control character could not migrate its keystore: the
  derived key differed, and the failure surfaced as an authentication error indistinguishable from a
  wrong password, with the correct password and an intact file. Migration-only and not
  network-visible, but it blocked the migration path with a misleading diagnosis. Passwords that are
  not valid UTF-8 are now rejected explicitly instead of being fed to the KDF as bytes. The oracle's
  secondary `altNormPassphrase` retry, which exists to read keystores written by superseded library
  versions, is not reproduced; keystores written by the pinned reference client use the standard form.

## neox-v2.4.2 - 2026-07-25

This release fixes four divergences from the reference client that changed the block this client
produced or accepted, and two that cost round-recovery time. It stays on the same pinned Reth
baseline as `neox-v2.4.1`. Anyone running `neox-v2.4.1` should upgrade: three of the four consensus
fixes affect any block carrying an Anti-MEV Envelope, and the fourth affects proposal signing.

This release has been re-validated against the full MainNet chain. Every canonical block from `1`
through `7,212,903` was re-executed with the release binary and reproduced every stored state root,
with no mismatch, bad block, or required unwind; the same datadir then restarted on the release,
caught the live backlog, and followed dBFT production to the reference head with matching hash and
state root. Note that MainNet history contains no Envelope-bearing block, so this run establishes
that none of the six fixes regressed historical execution rather than exercising the reconstruction
changes themselves, which remain covered by their unit tests and by earlier TestNet runs. Validator
mode remains experimental. See
[MainNet validation — 2026-07-25](reports/2026-07-25-MAINNET-VALIDATION.md).

- Document and pin the BLS12-381 infinity divergence from the Neo X Geth oracle. This client rejects
  points at infinity wherever a BLS point carries a consensus guarantee: the G1 threshold public key
  and G2 threshold signature of a dBFT header seal, and the global DKG public key and aggregated
  threshold signature in Anti-MEV share aggregation. gnark-crypto's `MillerLoop` filters infinity
  inputs, so Geth's `PairingCheck` accepts degenerate proofs at both sites. The Envelope ciphertext
  commitment is deliberately excluded and still accepts infinity, since Envelope recognition is
  consensus-visible and rejecting calldata the oracle accepts would fork the chain. Both strict
  sites require a colluding validator quorum to reach. No behavior change; the checks were already
  in place. See [Deliberate divergences from the oracle](README.md#deliberate-divergences-from-the-oracle).
- Apply the on-chain fee policy to RPC simulation, not only to block execution. The reference client
  checks the policy in `preCheck`, which every state transition passes through, so `eth_call` and
  `eth_estimateGas` reject a blacklisted sender, an oversized or underfunded Envelope, and any
  transaction below the `PolicyProxy` minimum tip. This client only reached the check from the block
  executor, so simulation returned a result for transactions the pool then refused on submission. A
  `NeoXEvm` wrapper now enforces it on every `transact_raw`, under the same guards as `preCheck`:
  London-gated, skipped when the base fee check is disabled and both fee fields are zero, and
  deferring to revm when a fee cap below the base fee or a tip above the fee cap would be reported
  first. System calls bypass the check, matching the reference client. Consensus behavior is
  unchanged.
- Pin that `PreCommit` decryption-share counts are summed at full width. The reference client adds
  the two `uint32` counts as `uint32`, so a payload declaring `2^32 - 1` current and one previous
  share wraps to zero, clears the per-block ceiling, and reaches an allocation sized by the
  unwrapped first count. This client widens both counts before adding, so the ceiling stays
  authoritative and the payload is rejected. No behavior change; the widening was already in place.
- Fix two consensus divergences in Anti-MEV block reconstruction, both of which changed the final
  transaction list of an Envelope-bearing block and would have forked the chain.

  Envelope recognition now walks the Envelope positions with a cursor instead of looking each
  position up directly. The reference client advances its cursor only for an Envelope the
  reconstruction loop actually reaches, so an Envelope skipped because an earlier transaction from
  the same sender failed leaves the cursor parked on that position; every later position then
  compares against an index already behind it, and no remaining Envelope in the block is recognized
  or decrypted. This client decrypted them.

  Every reconstructed transaction is now gated on the reference client's reconstruction-pool
  admission rules. That pool is a legacy pool, so its accepted-type mask excludes blob transactions:
  an Envelope-bearing block loses every blob transaction it carried, along with every later
  transaction from those senders, even though the same block passed pre-block verification, which
  filters blob transactions out before its own pool check. The gate also rejects a set-code
  transaction with no authorization, an encoded size above 128 KiB, and a tip below the pool's 1 wei
  price floor, which binds independently of the on-chain Policy minimum. A refused decrypted
  transaction falls back to its Envelope; a refused outer transaction is dropped and its sender
  skipped. The pool's nonce and balance checks are not reproduced: they run against the parent state
  and are strictly weaker than sequential execution, and its capacity limits cannot bind within a
  single block.
- Apply the same static-pool gate at proposal-verification time, where the reference client refuses
  the whole proposal if the pool refuses any transaction. This client had no such check, so it would
  sign proposals no reference-client validator will sign. Blob transactions are exempt here, unlike
  in reconstruction, because the reference client filters them out before its pool call. The gate
  also covers the pool's gas ceiling, which is the parent's gas limit rather than the proposed
  block's: a block that raises its own limit can carry a transaction that fits it and is still
  refused. Only the live consensus path is affected; block import is unchanged, so already-committed
  history still replays.
- Truncate the height to 32 bits when selecting the round primary. The reference client's dBFT
  context stores the block index as a `uint32`, so from height 2^32 onward it selects the primary
  from the wrapped value while this client used the full height. The two clients would disagree on
  who may propose and no round would reach consensus. Fixed in both the round state and recovery-
  message expansion. The turn-ness difficulty rule is unaffected: the reference client computes it
  from the full `uint64` block number.
- Reset the dBFT timer to one block period once this node records its own `PreCommit` or `Commit`,
  matching the reference client. Previously the longer view timeout kept running, so a node that had
  already committed waited it out before resending its commit by recovery message. A round that lost
  its quorum therefore recovered slower here than on the reference client, by up to
  `block_period << (view + 1)` instead of `block_period`. Liveness only; no consensus behavior
  changes.
- Cache authenticated dBFT messages for a height or view the active round has not reached, and replay
  them when it does, matching the reference client. Previously they were dropped: a validator briefly
  behind on canonical state lost every message for the next height, started that round with nothing,
  and had to wait out a view timeout and recover state its peers had already sent. Since block import
  in validator mode is asynchronous, that window opens on every block. Replay order is the reference
  client's: preparation, change view, pre-commit, commit. Unlike the reference client the cache is
  bounded, at 8 heights, one message per validator and type per height, and 16 MiB total, evicting the
  highest height first so a flood of far-future messages cannot displace the height the round is about
  to reach; heights the round passed are also pruned, which the reference client never does. Liveness
  only; no consensus behavior changes.
- Document and pin two DKG divergences from the reference client, neither of which changes behavior
  that was already in place. Its DKG transaction watcher reads a receipt only when it observes a
  task at a gap of *exactly* three blocks and marks every other submitted task successful without
  checking, so a contribution that reverted or never reached a block is normally abandoned and the
  round settles short by that member's share; this client keeps checking past three and resubmits
  until the phase deadline. Its `ZK_VERSION()` getter also infers a verifier version, mapping one
  ABI decoder error string to version zero — a string that covers any failed execution, so an
  out-of-gas or invalid-opcode halt reads as version zero too, alongside truncating an over-long
  return to its first word and a `>u64` version to its low bits. This client accepts only one
  32-bit-wide word or the empty revert of a legacy implementation, and treats anything else as an
  incident affecting validator liveness. See
  [Deliberate divergences from the oracle](README.md#deliberate-divergences-from-the-oracle).
- Pin the DKG prover IPC wire format in both languages. The node serializes the prover request from
  its own struct and the sandboxed Go helper decodes it rejecting unknown fields, but neither side
  covered the field names: the node's tests checked only the response shape, and the helper's built
  requests from its struct rather than from literal JSON. A rename on either side compiled and passed
  every unit test, surfacing only against the live helper during a DKG round. No behavior change.

## neox-v2.4.1 - 2026-07-24

This prerelease follows `rc.6` and incorporates the Reth synchronization update, validator
persistence hardening, and canonical settled-DKG replay work. It is suitable for independent
non-validator full-node evaluation and mixed-client block-consensus testing. Validator mode remains
experimental.

- Sync the pinned Reth baseline from `e3823342ab0f07a909d886b8b4a9b65a1a3a8be3` to
  `32de8f9c78ff03edb74f846a356df81d6935a494`. This imports provider-overlay persistence and pruning
  fixes, bounded partial-trie proofs, parallel exact sparse-trie retention, ExEx catch-up after a
  pause, configurable development defaults, and Geth-aligned debug trace errors.
- Validator mode now forces `--engine.persistence-threshold=0`,
  `--engine.memory-block-buffer-target=0`, and `--engine.persistence-backpressure-threshold=1`,
  while disabling persistence suppression. This queues each finalized dBFT block for asynchronous
  disk persistence immediately and bounds the engine's unpersisted tail while full nodes retain the
  upstream Reth defaults.
- Reth now retains five executed blocks in memory and persists seven by default. The removed
  sparse-trie LFU tuning flags were not used by repository configuration, but operators passing
  `--engine.sparse-trie-max-hot-slots`, `--engine.sparse-trie-max-hot-accounts`, or the former alias
  must remove those arguments.
- Settled DKG reconciliation now persists canonical PVSS material, validates the aggregate and
  per-validator share before reuse, and falls back to strict message replay when local state is
  incomplete or inconsistent.
- Add the reproducible all-height block/transaction/receipt differential gate in
  [`scripts/neox-full-differential.py`](../../scripts/neox-full-differential.py).

### Verification boundary

- MainNet full-chain validation passed: all `7,195,922` blocks re-executed through the Neo X EVM
  with zero state-root mismatches, every block hash and header field matched the public reference
  at `mainnet-1.rpc.banelabs.org` across sparse (step 10,000) and dense (last 200) scans, and all
  `368,040` transactions produced identical receipts. The full-chain differential gate
  (`scripts/neox-full-differential.py`) confirmed zero Rust↔Go block, transaction, or receipt
  mismatches.
- The official nine-client TestNet topology matched exactly from genesis through block `830`:
  `831` blocks, `9` transactions, and zero Rust↔Go block, transaction, or receipt mismatches.
- The live DKG share calls all reverted in the deployed seven-message verifier with
  `CommitmentInvalid()`; no DKG round transition was observed. Mixed-client DKG and validator fault
  scenarios remain experimental and are not production-qualified. See
  [`reports/2026-07-24-TESTNET-VALIDATION.md`](reports/2026-07-24-TESTNET-VALIDATION.md).

## neox-v2.4.1-rc.6 - 2026-07-23

This prerelease follows `rc.5` and incorporates the audited Neo X protocol hardening, managed DKG
runtime, and public-network replay work from the `neox` integration branch. It is suitable for
independent non-validator full-node evaluation. Validator mode remains prerelease and must not be
treated as MainNet validator qualification.

### Changes in this release

- Sync the Reth baseline from `9ebad6c4b77e053cd15de448e8a402d40905e58e` to
  `e3823342ab0f07a909d886b8b4a9b65a1a3a8be3`. This imports the custom-chain discv5 fork-ENR fix,
  Geth-compatible SNAP storage-range bounds, partial-proof trie-root corrections, payload state-root
  receiver support, and trie/engine performance observability changes.
- Harden chain-spec, dBFT seal/message validation, EVM policy execution, Anti-MEV reconstruction,
  transaction-pool snapshots, sidecar recovery, and validator rotation behavior against the
  findings recorded in [`reports/2026-07-22-REVIEW.md`](reports/2026-07-22-REVIEW.md).
- Rework managed DKG reconciliation around exact canonical state, branch-safe settled-share rebuilds,
  bounded asynchronous proving, canonical-head fencing, owned transaction cleanup, and persistent
  recovery resets. Linux release bundles now ship a statically linked, sandboxed DKG prover; macOS
  remains a non-validator full-node bundle.
- Route multi-thousand-block peer and propagated-block gaps through one bounded staged-backfill
  scheduler. Backfill forkchoice updates leave safe and finalized unset, while direct-child blocks
  continue through payload validation before dBFT finalization.
- Partition each Beacon peer's bounded inbound budget between droppable announcements and required
  events, preventing same-peer gossip saturation from rejecting required sync/consensus traffic
  while retaining the global event and byte ceilings.
- Isolate upstream Reth publication workflows from this fork, include the prerelease suffix in draft
  release titles, and build the advertised x86_64 Linux artifact for the architecture baseline.

### Verification and release boundary

- Full MainNet replay covered the approximately 6.98-million-block historical gap and then followed
  the live network without a canonical mismatch. Full TestNet replay executed all `9,167,856`
  post-genesis blocks and `317,350` transactions through every configured protocol boundary, with
  exact Geth block/state-root differentials and zero trie inconsistencies. See
  [`reports/2026-07-22-REVIEW.md`](reports/2026-07-22-REVIEW.md) and
  [`reports/2026-07-23-TESTNET-VALIDATION.md`](reports/2026-07-23-TESTNET-VALIDATION.md).
- The RC6 TestNet candidate repeated the previously failing unpinned path from an `8,026`-block gap,
  completed all 13 stages, transitioned to 111 contiguous live blocks, and passed block plus
  transaction/receipt RPC differentials with zero mismatch.
- Historical execution and observed live dBFT/Anti-MEV import qualify the non-validator full-node
  path. Mixed-client full DKG epoch transitions, prover failure/delay, replacement, controlled reorg,
  and end-to-end encrypted transaction reconstruction remain release gates. This is not a stable
  validator release.

## neox-v2.4.1-rc.5 - 2026-07-20

- Add the Neo X health watcher, Better Stack and generic webhook notification, Prometheus alerts,
  hardened service units, and bundled operational tooling.
- Remove redundant work from Neo X consensus, Anti-MEV, propagation, and sidecar hot paths.
- Consolidate orchestration and protocol types without changing their wire behavior, and record the
  audited Reth baseline update that is completed in `rc.6`.
- Validator mode remained prerelease; no stable `neox-v2.4.1` tag was published.

## neox-v2.4.1-rc.4 - 2026-07-20

This pre-release follows `rc.3` and carries the DKG runtime liveness fixes from the `neox` integration
branch. It is still a validator pre-release; it is not a MainNet validator release.

### Changes in this release

- fix(dkg): release the MDBX read provider before invoking the external prover, so a long proof does
  not hold a canonical read transaction open.
- fix(dkg): move external proving to an abortable asynchronous worker and poll readiness from the
  canonical heartbeat, with at most one new preparation in flight.
- fix(dkg): retry failed signer installation and reset the worker on runtime teardown or round reset.
- Verification: the official nine-client `privnet/zk` Anti-MEV consensus smoke and the synthetic
  short-epoch async-worker smoke both passed their stated boundaries; see
  [`reports/zk-network-2026-07-20.md`](reports/zk-network-2026-07-20.md) and
  [`reports/zk-short-epoch-dkg-2026-07-20.md`](reports/zk-short-epoch-dkg-2026-07-20.md).

### Release boundary

- Non-validator full-node behavior remains operational and verified against the Neo X Geth oracle.
- The async worker prevents canonical processing from waiting on the external prover, but this run
  does not prove successful seven-message proving, on-chain DKG submission, receipt confirmation, or
  Anti-MEV decryption. The official DKG window at heights 360–720 and the remaining validator fault
  gates remain open.

## 2.4.1 release-candidate baseline - 2026-07-20

Baseline prepared for the Neo X `2.4.1` release-candidate series, built on Reth `2.4.1`
(`9ebad6c4b77e053cd15de448e8a402d40905e58e`); behavior oracle is Neo X Geth
`a0c80295ab2c7a6d0bc218e4bc85270f5610948c`.

### Status

- **Non-validator full node: operational and verified.** A full MainNet sync (~7.15M blocks) executes
  with zero state-root mismatch, and block hashes and state roots match the public reference at
  checkpoints spanning the pre-DKG, DKG (3,623,040), and Anti-MEV (3,749,760) eras. dBFT ECDSA quorum
  and BLS12-381 threshold verification are confirmed on live MainNet blocks.
- **Validator mode: pre-release.** Both an all-Reth seven-validator network and a **mixed
  Neo X Geth + neox-rs** network now sustain dBFT block production and finalize in lockstep at a
  5-of-7 quorum, including cross-client block proposals (Geth accepts neox-rs primary proposals and
  vice versa); see [`reports/mixed-network-2026-07-20.md`](reports/mixed-network-2026-07-20.md). The
  remaining live private-network fault gates (view-change under crash, prover delay, transaction
  replacement, Anti-MEV/ZK decryption, reorg) and an independent protocol/security review are not
  complete. Do not run this release as a validator or claim MainNet validator compatibility.

### Implemented

- Canonical MainNet and T4 TestNet chain specs, genesis, fork schedule, and bootnodes.
- V0/V1/V2 dBFT header codecs; ECDSA quorum and BLS12-381 threshold finality.
- Neo X system-contract execution, Policy-aware transaction pool, and Governance/Policy/KeyManagement
  storage models verified against live testnet storage.
- BEACON/2 and dBFT wire protocols; missing-transaction recovery; timeout view changes; recovery
  messages; automatic primary proposals; final block import.
- Anti-MEV Envelope parsing, TPKE share verification/aggregation, and reconstruction with fallback;
  5-of-7 DKG (PVSS/ECIES/share/reshare/recover) with a crash-safe, validator-bound encrypted keystore
  and a one-shot Geth-keystore migration utility.
- `neox-rs` full-node binary; custom RPC (`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`,
  `eth_getCachedTransaction`); Prometheus metrics; container packaging; snapshot backup/restore.
- One-line curl installer (`scripts/install.sh`): platform detection, checksum-verified release
  bundle download, `~/.neox-rs/bin` install with shell `PATH` setup, covered by hermetic tests.
- Operational exception notification: a health watcher (`scripts/neox-health-notify.py`) that polls
  RPC/metrics, evaluates the documented health criteria, and reports to a Better Stack heartbeat
  (with `/fail` escalation), the Better Stack incidents API, or a generic webhook; Prometheus alert
  rules (`etc/neox/prometheus-alerts.yml`); and hardened systemd units (`pkg/neox/`). Covered by
  hermetic tests and shipped in the release bundle's `ops/` directory.

### Changes in this release

- Rename the node binary and package from `neox-reth` to `neox-rs`.
- fix(dBFT): the primary now attaches the parent reseal witness for ECDSA parents, and propagated-block
  import respects dBFT instant finality (import only head-extending blocks) — an all-Reth validator
  network now converges instead of stalling at block 1.
- fix(dBFT): recovery-message construction (`DbftRecoveryMessage::add_message`) no longer rejects a
  PrepareRequest/PrepareResponse whose hash differs from the accumulated preparation hash. Neo X Geth
  tolerates this (the compact form keeps one shared preparation hash); the strict check aborted
  recovery and stalled sustained block production. Now mirrors Geth's `recoveryMessage.AddPayload`.
- Verification: a live mixed-client network (Neo X Geth + neox-rs on one genesis) finalizes dBFT
  blocks in lockstep with bidirectional cross-client proposals, and an all-Reth network runs past the
  former block-15 recovery stall — see [`reports/mixed-network-2026-07-20.md`](reports/mixed-network-2026-07-20.md).
- fix(dBFT/net): a restarted validator is no longer permanently rejected by its peers. The beacon
  handshake advertises and accepts the chain spec's reachable fork-id family, and the core eth-protocol
  `Status` advertises the folded fork id so reth's pipeline backfill has eth peers to sync from. Without
  this, a validator that fell behind sat at its stale head with zero eth peers. No-op on MainNet/TestNet
  (both have a Paris fork); fixes crash recovery on private/custom chains. See
  [`reports/fault-injection-2026-07-20.md`](reports/fault-injection-2026-07-20.md).
- fix(dkg-prover): route gnark's solver/prover logging to stderr so the ZK-v1 stdout response stays
  a single parseable JSON object; verified by generating a committed Groth16 proof against the
  production ceremony artifacts.
- fix(dBFT/security): decode a `RecoveryMessage` payload only after the sender is authorized against
  the validator set, so an unauthenticated `dbft/0` peer can no longer force ~10^5 BLS12-381 subgroup
  checks per frame (pre-authorization CPU DoS). fix(security): zeroize the raw 32-byte private-key read
  buffer. Both from an internal adversarial review — see
  [`reports/security-review-2026-07-20.md`](reports/security-review-2026-07-20.md).
- perf(neox): result-identical hot-path cleanups — TPKE batch decrypt decodes the DKG global key and
  each G2 signature share once instead of per combination; the Anti-MEV block bloom is OR-ed from the
  receipt blooms; a propagated block is encoded once and fanned out as a raw frame; and the sidecar
  store's existence check stats instead of decoding. See
  [`reports/optimizations-2026-07-20.md`](reports/optimizations-2026-07-20.md).
- refactor(neox): behavior-preserving consolidation of duplication and type/style alignment across the
  Neo X crates (verified by an adversarial audit; no functional change).
- fix(rpc-differential): compare head-only Policy RPC methods only when both nodes share the checked
  height.
- Verification: live-MainNet BLS threshold consensus test, codec fuzz sweeps, full-sync state-consistency
  and live-node run reports, an internal audit (findings NX-1…NX-8), and an all-Reth private-network
  report.

### Known issues

- Validator mode is pre-release. The live fault-injection gates for crash + view change, single-node
  transaction inclusion, crash recovery / pipeline backfill, and whole-cluster restart now pass on a
  seven-validator private network (see [`reports/fault-injection-2026-07-20.md`](reports/fault-injection-2026-07-20.md)),
  but prover-delay behavior, transaction-replacement / Anti-MEV decryption during production, and reorg
  beyond a single validator drop are still not exercised, and an independent security review is
  outstanding.
- The live ZK-v1 Anti-MEV block-production path (TPKE decryption while building blocks) is not yet
  exercised end-to-end on a network, though the DKG proving boundary is: the `neox-dkg-prover` produces
  a committed Groth16 proof from the production ceremony artifacts. A full network run needs the `zk`
  privnet layout with DKG/Anti-MEV forks active. The mixed-client run covers the pre-anti-MEV (ECDSA)
  regime.
