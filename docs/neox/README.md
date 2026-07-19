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
- Geth-compatible 5-of-7 DKG polynomial/PVSS generation, ECIES share decryption, share/reshare/
  recover state transitions, current/previous epoch key rotation, and crash-safe encrypted state.
- A validator-bound DKG keystore using scrypt and authenticated AES-256-GCM, with atomic mode-0600
  persistence and startup recovery through `neox-reth`.
- A canonical-block DKG validator runtime that rebuilds unfinished rounds from `KeyManagement`
  storage, plans checkpoint transactions, persists secret material before proving, submits and
  replaces transactions with Policy-aware fees, checks receipts, and rotates signer shares across
  epoch changes and reorgs.
- A repeatable live JSON-RPC differential gate covering canonical block fields, Policy state and
  Neo X system-contract code.

## Remaining release gates

- Run a seven-validator mixed Geth/Reth testnet through proposal, view-change, validator-set change,
  DKG epoch transition, prover delay, transaction replacement, Anti-MEV decryption, restart, and
  reorg scenarios.
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

### Container image

Build a local image for the Docker host architecture:

```sh
docker buildx build --load --target runtime \
  --build-arg BINARY=neox-reth \
  --build-arg MANIFEST_PATH=bin/neox-reth \
  --build-arg SOURCE_URL=https://github.com/r3e-network/neox-rs \
  -t neox-reth:local .
docker run --rm neox-reth:local --version
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
docker run --name neox-reth --restart unless-stopped \
  -v neox-data:/data \
  -p 30303:30303/tcp -p 30303:30303/udp \
  -p 8545:8545 -p 8546:8546 -p 9001:9001 \
  ghcr.io/r3e-network/neox-reth:latest \
  node --chain neox-mainnet --datadir /data \
  --http --http.addr 0.0.0.0 \
  --ws --ws.addr 0.0.0.0 \
  --metrics 0.0.0.0:9001
```

The image intentionally contains only `neox-reth`. A validator deployment must mount its ECDSA
key, encrypted DKG keystore, password file, pinned DKG prover helper, manifest, and network-approved
ZK artifacts from separately managed secret/read-only volumes. Do not bake validator secrets or
ceremony artifacts into the image.

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

### Managed DKG validator runtime

The managed runtime is the preferred validator path. Build the pinned helper as a separate binary,
install the network-approved one-, two-, and seven-message R1CS/proving-key pairs, and record each
artifact's SHA-256 digest in a manifest based on
[`dkg-prover-manifest.example.json`](dkg-prover-manifest.example.json). All paths must be absolute.
Do not regenerate ceremony artifacts locally or reuse artifacts from another network.

```sh
cd tools/neox-dkg-prover
go test ./...
go build -trimpath -o /tmp/neox-dkg-prover .
install -m 700 /tmp/neox-dkg-prover /secure/neox-dkg-prover

sha256sum /secure/neox-zk/one_message.ccs /secure/neox-zk/one_message.pk
sha256sum /secure/neox-zk/two_message.ccs /secure/neox-zk/two_message.pk
sha256sum /secure/neox-zk/seven_message.ccs /secure/neox-zk/seven_message.pk
```

On macOS, use `shasum -a 256` in place of `sha256sum`. Replace every placeholder digest in the
manifest with the output before starting the node. The node rejects missing, relative, symlinked,
or non-regular manifest paths and rejects missing, relative, or non-regular artifact paths. The
helper recomputes the selected artifact hashes for every proof.

Create a mode-0600 password file without placing the password in process arguments, then initialize
the keystore once. Initialization creates the file without overwriting an existing entry, binds it
to the ECDSA validator address, logs only the public message key, and continues launching the node:

```sh
install -m 600 /dev/null /secure/neox-dkg.password
# Populate /secure/neox-dkg.password from a protected prompt or secret manager.
target/debug/neox-reth node \
  --chain neox-mainnet \
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
cargo +stable build -p neox-reth --bin neox-dkg-migrate
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
overwrites the destination. Start `neox-reth` with the subsequent-start command below and without
`--validator.dkg-init`; confirm that the printed round and message public key match the stopped Geth
validator before removing the source backup.

On subsequent starts, omit `--validator.dkg-init`:

```sh
target/debug/neox-reth node \
  --chain neox-mainnet \
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
only for a legacy deployment whose `KeyManagement.ZK_VERSION` has been independently verified as
zero; it still requires the helper but does not require a manifest. Never change the configured
version during an active round.

At every canonical update, the runtime reads Governance and `KeyManagement` storage directly. It
replays share, reshare, and recovery material idempotently; persists newly generated secret material
before invoking the helper; reserves nonces per DKG task; and retries missing or failed receipts
with a protocol-valid fee bump. A canonical reorg discards task and nonce queues and rebuilds them
from the new head. When the contract round settles, the encrypted keystore advances atomically and
all signer clones receive the current and previous shares. Nodes outside the new validator set have
both shares cleared.

#### Recovery rules

- Back up the encrypted keystore after initialization and after every logged epoch transition. Keep
  the password and validator ECDSA key in separate secret-manager entries.
- Restart with the same keystore after a crash. The runtime reconstructs an unfinished round from
  canonical contract storage and does not require transaction logs.
- Never rerun `--validator.dkg-init` for an existing validator identity and never copy another
  validator's keystore. Both operations are rejected or produce unusable message keys.
- If the log reports that the local keystore is ahead of the canonical round or more than one round
  behind, stop validator duty and restore a matching backup. Do not delete the keystore to make the
  warning disappear.
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
`--height` to pin a reproducible historical block.

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
- `reth_neox_sync_canonical_reorgs_total` reports canonical reorganization processing.

Alert on a stalled canonical height, zero protocol peers, sustained rejected-transition growth, or
unexpected reorg growth. A non-zero stale-transition count is not itself a fault: authenticated
messages can already be queued when a canonical notification advances the local dBFT round.

## Mixed-validator DKG gate

Launch a private network with exactly one `neox-reth` validator and six Neo X Geth validators, then
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

## Release rule

No release may claim validator compatibility until it independently obtains blocks through P2P,
reproduces canonical execution roots, completes mixed-client consensus and DKG epoch transitions,
and passes the operational and security gates above.
