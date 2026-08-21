# Neo X client development

`neox-rs` is an independent Rust implementation of the Neo X execution and full-node protocol
built on Reth. The `neox` branch is the integration and default branch.

## Compatibility baseline

| Component | Baseline |
|---|---|
| Reth | `dc83c609a8336c1d3e29b467ddbc9d896908bd14` (`2.5.1`) |
| Neo X Geth | `76580e6a54d7af46b6e0d8f19756cec40670805` (`bane-main`, `0.7.0-dev`) |
| MainNet genesis SHA-256 | `bdb5f93f77871ffc77ae7b063e93eae116aa9c2af6230138f2df8f6daeac8fa5` |
| T4 TestNet genesis SHA-256 | `2b49c4d6701222396b9217b7c76e29fd150ab29fc91472b2f398d7620734a1ae` |

The pinned Neo X Geth source and canonical genesis files remain the behavior oracle until an
independent protocol specification covers every Neo X extension. Update
`docs/neox/source-baseline.toml` deliberately when that oracle changes.

The current oracle includes the v0.6.2 blacklist execution change: Policy blacklisted targets are
reverted for internal `CALL`, `CALLCODE`, `DELEGATECALL`, and `STATICCALL` frames, while precompiles
remain callable. The oracle's GovPaymaster and private-network genesis updates are not copied into
the canonical MainNet/T4 chain specs because those genesis files did not change in the pinned
oracle comparison; they become active here only when a canonical deployment and genesis hash are
published.

## Deliberate divergences from the oracle

Oracle parity is the default. Every case where this client knowingly does something else is listed
here, with the reachability argument that justifies it. Each one is pinned by a test so it cannot
regress silently.

### BLS12-381 points at infinity in threshold verification

This client rejects the point at infinity wherever a BLS point carries a consensus guarantee. The
reference client accepts it. gnark-crypto's `MillerLoop` filters infinity inputs before pairing, so
when every pair in a check involves an infinity point the accumulator stays at one and Geth's
`PairingCheck` reports success for a proof that establishes nothing. blst rejects the same inputs:
`key_validate` always fails on infinity, and `sig_validate` is called with `sig_infcheck = true`.

This is one validation policy, not a single-site special case. It applies at:

- `decode_threshold_points` in [`crates/neox/consensus/src/validation.rs`](../../crates/neox/consensus/src/validation.rs),
  for the G1 threshold public key and G2 threshold signature of a dBFT header seal.
- `aggregate_and_verify_signature_shares` in [`crates/neox/antimev/src/tpke.rs`](../../crates/neox/antimev/src/tpke.rs),
  for the global DKG public key and the aggregated threshold signature. Geth's `PublicKey.Verify`
  pairs `(pk, hash)` and `(-g1, sig)`, so an infinity key with an infinity aggregate drops both
  pairs and `VerifySig` returns true.

The Envelope ciphertext commitment is deliberately excluded. `TpkeCiphertext::decode` accepts
infinity, matching gnark's `SetBytes`, because Envelope recognition is consensus-visible: rejecting
calldata the oracle accepts would change the block's Envelope count and fork the chain. A zero
encryption scalar only exposes the sender's own payload and forges nothing.

Neither site is reachable by an external peer; both require a colluding validator quorum. The
threshold key is only consulted after `validate_parent_consensus` has matched
`keccak256(public_key)` against the parent's next-consensus commitment, so the parent header must
already commit to the hash of the infinity encoding. On the full header path the substitution is
therefore caught by the next-consensus link before the seal check runs, making the infinity
rejection defense in depth behind that link rather than the only barrier. The global DKG key is
likewise read from the `KeyManagement` contract commitment, so an infinity value there requires the
on-chain ceremony to have settled one.

Accepting a degenerate proof to stay bit-compatible would trade a real cryptographic guarantee for
oracle parity, so the strict check is kept. The consequence is bounded and fail-stop: a chain that
finalized such a header would stall this client instead of being followed.

Pinned by two tests. `rejects_infinity_threshold_points_accepted_by_the_geth_oracle` asserts
rejection at the key check, at the signature check with a valid key (proving `sig_infcheck` is what
rejects it rather than the key check short-circuiting), and on the full header path.
`rejects_infinity_signature_inputs_accepted_by_the_geth_oracle` covers the Anti-MEV path and also
asserts that ciphertext decoding still accepts infinity, so the exclusion above cannot be tightened
into a consensus fork by a later change.

### DKG transaction retry after the confirmation delay

This client checks the receipt of every submitted DKG transaction once the three-block confirmation
delay has elapsed, and resubmits while the receipt is missing or reverted until the phase deadline.
The reference client only checks a receipt when the watcher observes the task at a gap of *exactly*
three blocks:

```go
if item.TxHash != nil && currentHeight-item.SendHeight == 3 { ...check receipt... }
...
} else { item.ConfirmedSuccess = true }
```

`dkgTaskWatcher` drops any task it does not mark `needRetry`, so at any other gap a submitted task is
recorded as successful without its receipt ever being read. The gap is not controlled: `SendHeight`
is the height at which the task was *planned*, the watch list only reaches the watcher after
`dkgTaskExecutor` has finished Groth16 proving for every task in the batch, and `handleDKG` sends a
heartbeat every block. The usual outcome is therefore that the reference client abandons a DKG
contribution that reverted or never reached a block, and the round settles short by that member's
share, forcing the recovery path.

The divergence is one-directional and not consensus-visible: it can only cause this client to send a
contribution the reference client would have dropped. `KeyManagement` rejects a duplicate for a slot
it already holds, so a retry that races a late inclusion reverts and costs the validator gas rather
than corrupting round state. Reproducing the reference behavior would mean discarding a known-failed
contribution and degrading the round to recovery on purpose, so the receipt check is kept.

Pinned by `checks_receipts_the_geth_oracle_confirms_blindly` in
[`crates/neox/node/src/dkg.rs`](../../crates/neox/node/src/dkg.rs), which asserts the retry decision
at the gaps past three where the oracle sets `ConfirmedSuccess`, and by
`prepares_submits_checks_and_retries_stable_calldata` in
[`dkg_executor.rs`](../../crates/neox/node/src/dkg_executor.rs) for the queue that drives it.

### Strict decoding of `KeyManagement.ZK_VERSION()`

The deployed verifier version selects which of the two DKG ABIs a contribution must use, so this
client only accepts an unambiguous answer from the getter: one 32-byte word that fits `u64`, or the
empty revert of a legacy implementation that predates the selector. Anything else is an error that
suspends active DKG task work while retaining reconciled settled shares.

The reference client infers a version instead. `getZKVersion` maps one specific ABI decoder error to
version zero:

```go
if strings.Contains(err.Error(), "abi: attempting to unmarshal an empty string while arguments are expected") {
    // Old KeyManagement version doesn't contain ZK_VERSION method in fact, so treat this error as zero version.
    return 0, nil
}
```

That string is produced whenever `Arguments.Unpack` receives no data, and `unpackContractExecutionResult`
passes it `result.Return()`, which is nil for *any* failed execution and not just a revert. An
out-of-gas or invalid-opcode halt therefore also reads as version zero, because `Revert()` is only
non-nil for `vm.ErrExecutionReverted` and the empty-revert case never enters the revert branch either.
Two further cases are decoded leniently: `Arguments.UnpackValues` applies no total-length check, so
return data longer than one word is truncated to its first word, and `big.Int.Uint64()` truncates a
version that exceeds 64 bits — which then either selects an ABI by its low word or reaches the
`panic(fmt.Errorf("unknown ZK version %d", zkVersion))` in `sendTransactionToKeyManagement`.

Reproducing the inference would mean building proofless ZK-v0 calldata on the strength of a getter
that failed for an unrelated reason. This client cross-checks the on-chain answer against
`--validator.dkg-zk-version` regardless, so a wrong guess is caught either way; failing closed keeps
it from being caught by a reverted transaction. The divergence is one-directional: it can only stop
this client from sending a contribution, never make it send one the reference client would not.

Failing closed is not free. A getter that halts for a chain-wide reason — a botched proxy upgrade,
say — would stop every node running this client while reference nodes carried the round on as
version zero, degrading the round to recovery or failing it outright. That cost is accepted because
the alternative reads a verifier version out of an unrelated execution failure, and because the
operator's configured version is the authority this client can actually check the answer against.
Treat a logged ZK-version failure as an incident affecting validator liveness, not a warning.

Pinned by `accepts_only_empty_revert_as_geth_v0_fallback`, `rejects_halted_zk_version_getter`, and
`decodes_zk_version_with_geth_v0_fallback` in
[`crates/neox/node/src/dkg_call.rs`](../../crates/neox/node/src/dkg_call.rs).

## Implemented

- Canonical MainNet and T4 TestNet chain specs, genesis state, fork schedule, and bootnodes.
- V0/V1/V2 dBFT header codecs, proposer/difficulty checks, ECDSA and BLS threshold finality.
- Neo X system-contract execution hooks and Policy-aware transaction-pool validation.
- BEACON/2 and dBFT wire protocols, authenticated messages, missing-transaction recovery, timeout
  view changes, recovery messages, automatic primary proposals, and final block import.
- Anti-MEV Envelope parsing, current/previous DKG epoch classification, TPKE share verification and
  aggregation, reconstruction retry, fallback execution, and blob-sidecar preservation.
- `neox-rs` full-node executable with MainNet synchronization proven against live Neo X Geth
  block hashes and execution roots.
- Neo X RPC behavior for `eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`, and
  `eth_getCachedTransaction`.
- Optional Geth-compatible secret-transaction caching with `--txpool.amevcache`. Cached secret
  transactions are validated but are not inserted into or propagated by the public pool.
- A real private-network mixed-client smoke and restart-recovery run with one Reth validator, six
  Neo X Geth validators, and one Geth observer; the evidence is recorded in
  [`reports/mixed-client-e2e-2026-07-19.json`](reports/mixed-client-e2e-2026-07-19.json).
- Mode-0600 validator identity/share loading and canonical-round DKG share rotation from a key
  directory shared by all signer clones.
- Geth-compatible 5-of-7 DKG polynomial/PVSS generation, ECIES share decryption, share/reshare/
  recover state transitions, current/previous epoch key rotation, and crash-safe encrypted state.
- A validator-bound DKG keystore using scrypt and authenticated AES-256-GCM, with atomic mode-0600
  persistence and startup recovery through `neox-rs`.
- A canonical-block DKG validator runtime that rebuilds unfinished rounds from `KeyManagement`
  storage, plans checkpoint transactions, persists secret material before proving, submits and
  replaces transactions with Policy-aware fees, checks receipts, and rotates signer shares across
  epoch changes and reorgs.
- A repeatable live JSON-RPC differential gate covering canonical block fields, Policy state and
  Neo X system-contract code.
- A reproducible Reth-style Neo X Geth versus `neox-rs` benchmark harness covering deterministic
  RPC/state-read cases, semantic preflight, paired rounds, concurrency levels, and raw JSON output;
  see [`reports/benchmark-2026-07-20.md`](reports/benchmark-2026-07-20.md).

## Remaining release gates

- The one-Reth/six-Geth DKG epoch gate and lifecycle assertions are implemented. Mixed-client
  block agreement, a real Reth restart recovery, crash/view-change, single-node transaction
  inclusion, and whole-cluster restart have passed. The live share calls reached the deployed
  seven-message verifier but reverted with `CommitmentInvalid()`; no DKG round transition is
  claimed. Prover delay, transaction replacement, Anti-MEV decryption during production, controlled
  reorg, and a successful mixed-client DKG epoch remain open before validator release.
- The official `privnet/zk` topology has also passed a nine-client Anti-MEV consensus smoke gate
  (one Reth, six Geth validators, two Geth observers). Its DKG share window begins at height 360,
  so this run is recorded as a boot/consensus boundary rather than a second full DKG-epoch claim;
  see [`reports/zk-network-2026-07-20.md`](reports/zk-network-2026-07-20.md).
- MainNet archive synchronization, metrics, container packaging, and snapshot backup/restore have
  been exercised. Qualify tracing, pruning, and binary/schema upgrade paths under sustained load.
- Complete independent protocol/security review before a validator or MainNet release claim.
- Code remediations for the validator-runtime hardening findings (NX-2 through NX-8) recorded in
  [`reports/audit-2026-07-19.md`](reports/audit-2026-07-19.md) are implemented and reviewed in
  [`reports/2026-07-22-REVIEW.md`](reports/2026-07-22-REVIEW.md). The matching live fault-injection
  and mixed-client requalification gates remain open for validator release.
- An all-Reth private validator network now converges and finalizes dBFT blocks at a 5-of-7 quorum
  after the recovery-path fixes (see
  [`reports/private-network-2026-07-19.md`](reports/private-network-2026-07-19.md) and
  [`reports/mixed-network-2026-07-20.md`](reports/mixed-network-2026-07-20.md)). The remaining
  validator release risk is requalification of the remediated validator runtime under the live
  ZK/Anti-MEV production lifecycle and fault scenarios, not the former recovery merge stall.

An independently syncing non-validator full node and mixed-client block production are
operational. Validator mode remains experimental; mixed-client DKG and validator fault scenarios
are not production-qualified. See
[`reports/2026-07-24-TESTNET-VALIDATION.md`](reports/2026-07-24-TESTNET-VALIDATION.md).

## Build and run

The workspace currently requires the stable Rust toolchain for compilation. The repository's
formatting configuration still uses nightly rustfmt.

```sh
cargo +stable build -p neox-rs
target/debug/neox-rs node --chain neox-mainnet --http
```

### Container image

Build a local image for the Docker host architecture:

```sh
docker buildx build --load --target runtime \
  --build-arg BINARY=neox-rs \
  --build-arg MANIFEST_PATH=bin/neox-rs \
  --build-arg SOURCE_URL=https://github.com/r3e-network/neox-rs \
  -t neox-rs:local .
docker run --rm neox-rs:local --version
```

The `neox` bake target produces the release image for both supported Linux architectures. Registry
publication is a release-maintainer operation:

```sh
TAG=v0.1.0 docker buildx bake neox --push
```

Run a non-validator MainNet full node with persistent chain data and explicitly published RPC,
WebSocket, metrics, and P2P ports:

```sh
docker volume create neox-data
docker run --name neox-rs --restart unless-stopped \
  -v neox-data:/data \
  -p 30303:30303/tcp -p 30303:30303/udp \
  -p 8545:8545 -p 8546:8546 -p 9001:9001 \
  ghcr.io/r3e-network/neox-rs:latest \
  node --chain neox-mainnet --datadir /data \
  --http --http.addr 0.0.0.0 \
  --ws --ws.addr 0.0.0.0 \
  --metrics 0.0.0.0:9001
```

The image intentionally contains only `neox-rs`. A validator deployment must mount its ECDSA
key, encrypted DKG keystore, password file, pinned DKG prover helper, manifest, and network-approved
ZK artifacts from separately managed secret/read-only volumes. Do not bake validator secrets or
ceremony artifacts into the image.

See [`OPERATIONS.md`](OPERATIONS.md) for the tested snapshot round trip, upgrade/rollback sequence,
validator fencing rules, and release health checks.

Enable the private Anti-MEV construction cache only on an endpoint intended to receive secret
transactions:

```sh
target/debug/neox-rs node --chain neox-mainnet --http --txpool.amevcache
```

Validator key files must be readable only by their owner. Static share files and round-key
directories remain compatibility modes; the managed keystore below is the branch-safe validator
path. Public MainNet/TestNet validator startup also requires the explicit
`--validator.experimental` acknowledgement because validator qualification is still prerelease. A
round-key directory is useful for planned epoch transitions:

```text
/secure/neox-dkg/
  87.key
  88.key
```

```sh
target/debug/neox-rs node \
  --chain neox-mainnet \
  --validator.experimental \
  --validator.ecdsa-key /secure/validator.key \
  --validator.dkg-key-dir /secure/neox-dkg
```

At each canonical head, the node installs `<round>.key` as current and `<round-1>.key` as previous,
binding both shares to that head and the native Governance validator order. The current scalar must
match the sum of all seven canonical fresh-share PVSS public evaluations for its receiver position;
the previous scalar must match the seven same-round reshare evaluations. Missing, malformed, or
nonmatching files clear validator shares and are retried once per second at that exact canonical
head, so recovery does not depend on producing another block. Any reorg, detached or noncontiguous
commit, or notification gap permanently disables this legacy reload task for the rest of the
process. Restarting safely repeats the full canonical PVSS verification; use the managed keystore
for automatic in-process reorg recovery.

### Managed DKG validator runtime

The managed runtime is the preferred validator path and requires Linux. It executes a native,
statically linked ELF helper inside a Linux-specific process sandbox; helpers containing a dynamic
loader (`PT_INTERP`) are rejected. macOS release bundles remain supported for non-validator
full-node operation and intentionally omit `neox-dkg-prover`.

Build the pinned helper with CGO disabled, install the network-approved one-, two-, and seven-message
R1CS/proving-key pairs, and record each artifact's SHA-256 digest in a manifest based on
[`dkg-prover-manifest.example.json`](dkg-prover-manifest.example.json). All paths must be absolute.
Do not regenerate ceremony artifacts locally or reuse artifacts from another network.

```sh
cd tools/neox-dkg-prover
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/neox-dkg-prover .
file /tmp/neox-dkg-prover | grep 'ELF .*statically linked'
! readelf -lW /tmp/neox-dkg-prover | grep INTERP >/dev/null
install -m 700 /tmp/neox-dkg-prover /secure/neox-dkg-prover

sha256sum /secure/neox-zk/one_message.ccs /secure/neox-zk/one_message.pk
sha256sum /secure/neox-zk/two_message.ccs /secure/neox-zk/two_message.pk
sha256sum /secure/neox-zk/seven_message.ccs /secure/neox-zk/seven_message.pk
```

Replace every placeholder digest in the manifest with the output before starting the node. The node
rejects missing, relative, symlinked, or non-regular manifest paths and rejects missing, relative,
or non-regular artifact paths. The helper recomputes the selected artifact hashes for every proof.

Create a mode-0600 password file without placing the password in process arguments, then initialize
the keystore once. Initialization creates the file without overwriting an existing entry, binds it
to the ECDSA validator address, logs only the public message key, and continues launching the node:

```sh
install -m 600 /dev/null /secure/neox-dkg.password
# Populate /secure/neox-dkg.password from a protected prompt or secret manager.
target/debug/neox-rs node \
  --chain neox-mainnet \
  --validator.experimental \
  --validator.ecdsa-key /secure/validator.key \
  --validator.dkg-keystore /secure/neox-dkg.json \
  --validator.dkg-password-file /secure/neox-dkg.password \
  --validator.dkg-prover /secure/neox-dkg-prover \
  --validator.dkg-prover-manifest /secure/neox-dkg-prover.json \
  --validator.dkg-zk-version 1 \
  --validator.dkg-init
```

The command above generates a new message identity and is only valid before that public key is
registered for a new validator enrollment. When replacing a Geth validator before its first DKG
round, use an audited offline procedure to export its message private key to a temporary mode-0600
raw or hex file and add
`--validator.dkg-message-key /secure/existing-message.key` to the one-time initialization command.
The logged public key must exactly match `KeyManagement.messagePubkeys(validator)` before the node
is allowed to perform validator duty. Delete the temporary plaintext key after the encrypted Reth
keystore has been backed up and verified. This import path intentionally works only with
`--validator.dkg-init` and never overwrites an existing keystore. It does not migrate settled or
in-progress key groups from a validator that has already participated in DKG.

For a validator with settled or in-progress Geth state, stop its validator duty first and run the
one-shot encrypted migration utility. Never read a keystore while Geth may still be writing it:

```sh
cargo +stable build -p neox-rs --bin neox-dkg-migrate
target/debug/neox-dkg-migrate \
  --source /secure/geth-antimev-keystore \
  --source-password-file /secure/geth-antimev.password \
  --destination /secure/neox-dkg.json \
  --destination-password-file /secure/neox-dkg.password \
  --validator 0x0123456789abcdef0123456789abcdef01234567
```

The source, both password files, and their parent directory should be available only to the
migration account. The utility accepts the bounded EIP-2335 v4 PBKDF2/Scrypt and AES-128-CTR format
used by Neo X Geth, authenticates its checksum, converts every current, previous, pending, sharing,
resharing, and recovery key group, verifies the embedded validator identity and cryptographic field
widths, atomically creates the Reth keystore, prints only public metadata, and exits. It never
overwrites the destination. Start `neox-rs` with the subsequent-start command below and without
`--validator.dkg-init`; confirm that the printed round and message public key match the stopped Geth
validator before removing the source backup.

On subsequent starts, omit `--validator.dkg-init`:

```sh
target/debug/neox-rs node \
  --chain neox-mainnet \
  --validator.experimental \
  --validator.ecdsa-key /secure/validator.key \
  --validator.dkg-keystore /secure/neox-dkg.json \
  --validator.dkg-password-file /secure/neox-dkg.password \
  --validator.dkg-prover /secure/neox-dkg-prover \
  --validator.dkg-prover-manifest /secure/neox-dkg-prover.json \
  --validator.dkg-zk-version 1
```

The keystore loader rejects symlinks, non-regular files, group/world permissions, oversized input,
wrong passwords, modified ciphertext, invalid scalars, cross-validator reuse, and inconsistent DKG
round state. A single trailing LF or CRLF in the password file is removed; all other bytes are part
of the password.

`--validator.dkg-zk-version=1` is the default and requires the complete manifest. Version zero is
only for a legacy deployment; it still requires the helper but does not require a manifest. During
each active-round canonical reconciliation, the runtime executes `KeyManagement.ZK_VERSION()`
against the exact canonical state and header through the Neo X EVM. An empty legacy revert is
treated as version zero; any other call failure or a mismatch with the configured version suspends
and clears active DKG transaction/prover work while retaining the already reconciled settled signer
shares. Never change the configured version during an active round.

At every canonical update, the runtime first reconciles the settled round from the exact Governance
and `KeyManagement` snapshot. It can rebuild and atomically persist settled current/previous shares
across arbitrary local round gaps, rollbacks, or branch changes before installing them in every
signer clone; nodes outside the canonical validator set have both shares cleared. Active share,
reshare, and recovery material is then replayed idempotently. Newly generated secret material is
persisted before invoking the helper, nonces are reserved per DKG task, and missing or failed
receipts are retried with a protocol-valid fee bump. Active-round read, replay, or ZK-version
failures reset only task work and do not revoke a valid settled signer share.

A one-second maintenance heartbeat compares the provider's latest canonical head with the last
reconciled head, repairing progress if a canonical notification was dropped while avoiding repeated
work at an unchanged head. Reorgs, task invalidation, expiry, and canonical task completion remove
transactions created by this runtime from the local pool. A transaction copy already propagated to
another peer cannot be revoked, however, and the DKG contract methods select the round implicitly
from current contract state. Operators must therefore monitor canonical task completion and keep
validator duty fenced during incident recovery.

#### Recovery rules

- Back up the encrypted keystore after initialization and after every logged epoch transition. Keep
  the password and validator ECDSA key in separate secret-manager entries.
- Restart with the same keystore after a crash. The runtime reconstructs unfinished task state and
  settled signer shares from canonical contract storage without transaction logs, including when
  the local keystore is arbitrarily ahead of or behind the canonical round after a reorg or extended
  outage.
- Never rerun `--validator.dkg-init` for an existing validator identity and never copy another
  validator's keystore. Both operations are rejected or produce unusable message keys.
- A round gap by itself does not require restoring a backup. Stop validator duty and restore only
  when the encrypted keystore cannot be read or authenticated, its validator/message identity does
  not match the registered canonical identity, or its secret material is otherwise rejected as
  malformed. Do not delete or reinitialize the keystore to make such an error disappear.
- After restoring, use the deployment's validator-duty fencing procedure while confirming that DKG
  reconciliation completes without warnings, then return the validator to service.

## Live differential gate

Run a local node near the reference head, then compare one shared canonical height:

```sh
scripts/neox-rpc-differential.py \
  --local http://127.0.0.1:8545 \
  --reference https://mainnet-1.rpc.banelabs.org
```

The command exits non-zero for excessive height skew, canonical header/root divergence, Policy RPC
or storage divergence, missing custom methods, and system-contract bytecode differences. Use
`--height` to pin a reproducible historical block. The head-only Policy RPC methods
(`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`) take no block parameter and are compared
only when the checked height is both nodes' head; otherwise they are reported under `skipped`, while
the height-addressed Policy storage checks still verify state at the pinned block.

For a bounded execution compatibility check, add `--check-execution --max-transactions 64`.
This fetches the first 64 transaction hashes from the checked block and compares each transaction
and receipt field against Neo X Geth; keep the bound explicit when running against public RPCs.

## Neo X metrics

Enable Reth's metrics endpoint with `--metrics <address>:<port>`. The Neo X synchronization driver
exports the following Prometheus series in addition to the standard Reth metrics:

- `reth_neox_sync_canonical_height`, `reth_neox_sync_beacon_peers`, and
  `reth_neox_sync_dbft_peers` report the live chain and protocol-peer gauges.
- `reth_neox_sync_beacon_events_total`, `reth_neox_sync_dbft_events_total`, and
  `reth_neox_sync_canonical_updates_total` report protocol and canonical-chain progress.
- `reth_neox_sync_dbft_transitions_accepted_total`,
  `reth_neox_sync_dbft_transitions_stale_total`, and
  `reth_neox_sync_dbft_transitions_rejected_total` distinguish useful consensus traffic from
  harmless late messages and invalid messages.
- `reth_neox_sync_dbft_view_changes_total` counts authenticated dBFT view changes accepted by
  the active round.
- `reth_neox_sync_canonical_reorgs_total` reports canonical reorganization processing.
- `reth_neox_dkg_canonical_reconciliations_total` and `reth_neox_dkg_canonical_reorgs_total`
  report validator DKG heartbeat and reorganization recovery activity.
- `reth_neox_dkg_validator_set_changes_total` counts current/pending governance membership or
  index changes that force the validator task queue to restart from canonical state.
- `reth_neox_dkg_task_preparations_total`, `reth_neox_dkg_task_preparation_failures_total`,
  `reth_neox_dkg_prover_attempts_total`, and `reth_neox_dkg_prover_duration_seconds` expose
  external ZK prover attempts and latency.
- `reth_neox_dkg_submissions_total`, `reth_neox_dkg_submission_failures_total`,
  `reth_neox_dkg_receipt_checks_total`, `reth_neox_dkg_receipt_check_failures_total`,
  `reth_neox_dkg_replacements_total`, `reth_neox_dkg_confirmed_total`, and
  `reth_neox_dkg_expired_total` distinguish each validator task lifecycle outcome.
- `reth_neox_dkg_current_round` and `reth_neox_dkg_queued_tasks` expose the current canonical
  round and outstanding validator work.

Alert on a stalled canonical height, zero protocol peers, sustained rejected-transition growth, or
unexpected reorg growth. A non-zero stale-transition count is not itself a fault: authenticated
messages can already be queued when a canonical notification advances the local dBFT round.

## Mixed-validator DKG gate

Launch a private network with exactly one `neox-rs` validator and six Neo X Geth validators, then
run the epoch gate with every validator's JSON-RPC endpoint:

```sh
scripts/neox-mixed-dkg-e2e.py \
  --reth http://127.0.0.1:8650 \
  --geth http://127.0.0.1:8562 \
  --geth http://127.0.0.1:8563 \
  --geth http://127.0.0.1:8564 \
  --geth http://127.0.0.1:8565 \
  --geth http://127.0.0.1:8566 \
  --geth http://127.0.0.1:8567
```

The gate starts only from a settled common DKG round. It then requires all seven clients to advance
at least three blocks, agree on each checked block hash and execution root, cross the same DKG round,
and return the identical 128-byte aggregate commitment for the new round. By default it tolerates
up to 30 transient JSON-RPC poll errors so one or more nodes can be restarted during the run; chain,
block, peer, height-skew, and commitment disagreements are never treated as transient. Use
`--no-round-advance` only as a shorter mixed-client sync smoke test, not as the validator release
gate.

For a lifecycle gate, run the same command with `--allow-reorgs --require-reorg
--require-transient-recovery` while an external harness restarts one validator and injects a
controlled testnet reorg. The gate records converged head discontinuities and fails unless both the
restart outage and at least one common reorganization were observed. A normal epoch gate leaves
these options disabled so an unexpected reorg remains a hard failure.

To exercise DKG transaction replacement, expose the Reth validator metrics endpoint and add
`--reth-metrics http://127.0.0.1:19552 --require-replacements`. The gate snapshots
`reth_neox_dkg_replacements_total` before and after the epoch and fails unless the counter grows;
the external harness must first make a DKG receipt missing or reverted so the runtime submits a
same-nonce fee replacement.

To require an explicit dBFT view change in the same lifecycle run, add
`--require-view-change`. The gate compares `reth_neox_sync_dbft_view_changes_total` before and
after the run, so the harness must delay or isolate the active proposer long enough for a signed
change-view transition to be accepted and then allow the network to reconverge.

To exercise prover delay, add `--require-prover-attempts --min-prover-average-seconds 2`. The gate
compares the DKG prover attempt counter and histogram sum/count around the run; inject the delay
in the external prover harness rather than changing consensus timing in the node.

## Release rule

No release may claim validator compatibility until it independently obtains blocks through P2P,
reproduces canonical execution roots, completes mixed-client consensus and DKG epoch transitions,
and passes the operational and security gates above.
