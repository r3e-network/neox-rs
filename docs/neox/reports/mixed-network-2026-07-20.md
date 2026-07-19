# Neo X mixed-client network (Neo X Geth + neox-rs) — 2026-07-20

Runs a live private dBFT network with validators of **both** client types — Neo X Geth and
`neox-rs` — on one shared genesis, to verify wire-protocol and consensus interoperability and to
use Geth as a behavior oracle for the dBFT recovery path. This closes the two items that kept
validator mode pre-release: the all-Reth recovery-state stall and the (previously unrun)
mixed-client gate.

## Clients and genesis

- **Neo X Geth** `v0.6.2-unstable-a0c80295` (behavior oracle
  `a0c80295ab2c7a6d0bc218e4bc85270f5610948c`), built from the public fork.
- **neox-rs** `2.4.1` release build.
- One shared genesis: MainNet-derived, private `chainId` 47763777, DKG/AntiMev/EthSig forks pushed
  far out (pure-ECDSA regime), seven deterministic validators (secp256k1 secrets `0x01`..`0x07`) in
  both `config.dbft.standbyValidators` and the Governance proxy `currentConsensus` storage.
- Genesis hash is identical on both clients: `0x32a07b…e1d1a7`. Geth must be initialised with
  `--state.scheme hash` so the full genesis state trie is committed (otherwise it waits for snap
  sync and cannot build the first payload).

## Geth-only oracle run (recovery stall is Rust-specific)

Seven Geth validators on this genesis produce and finalise dBFT blocks continuously and sail past
block 15 — the height at which the all-Reth network previously stalled — with all seven nodes in
hash agreement (block 15 `0x5f12d79f…`, block 20 `0xd3eb664f…`, climbing steadily to 176+). This
proved the stall was **not** inherent to the protocol, genesis, or validator set, and localised it
to `neox-rs`.

Root cause: `DbftRecoveryMessage::add_message` (build side) rejected a PrepareRequest/PrepareResponse
whose hash differed from the accumulated preparation hash. Neo X Geth's `recoveryMessage.AddPayload`
does not — the compact recovery form stores a single shared preparation hash (the PrepareRequest's
hash is authoritative; a PrepareResponse only fills it when unset), and reconstruction stamps every
response with that one hash. The strict check turned a state Geth tolerates into a fatal error that
aborted `ConsensusState::recovery_message` and stalled the round. Fixed to mirror Geth exactly
(regression test `dbft_payload::tests::recovery_build_tolerates_prepare_response_hash_mismatch`).

After the fix, an all-Reth seven-validator network (same setup that stalled at 15) runs to block
143+ with perfect hash agreement (blocks 15 `0x69ee5c3f…`, 50 `0x9c9f99f0…`), zero
`invalid dBFT recovery entry` errors and zero panics across all seven nodes.

## Mixed-client run (bidirectional consensus interop)

Five Geth validators (indices 0–4) and two `neox-rs` validators (indices 5, 6, holding the same
keys the two stopped Geth nodes held) run together. The `neox-rs` nodes dial the five Geth nodes as
trusted peers; discovery is off.

Observed:

- **Protocol negotiation both ways.** `neox-rs` establishes `beacon/2` and `dbft/0` sessions with
  every Geth peer (`Neo X beacon peer established … version=V2`, `Neo X dbft/0 peer established`).
- **Geth → Reth.** `neox-rs` validates and finalises Geth-produced blocks over the wire
  (`Validated and finalized propagated Neo X block block_number=279`) and follows the chain via
  header sync.
- **Reth → Geth.** When a `neox-rs` node is the round primary it broadcasts a PrepareRequest that
  Geth receives and accepts (`received PrepareRequest {"validator": 5 …}` / `{"validator": 6 …}` in
  the Geth logs — **94** such accepted proposals during the run). Geth also counts `neox-rs`
  PrepareResponses and Commits toward its quorum.
- **Cross-counted quorum.** `neox-rs` reaches preparation and commit quorum counting Geth votes
  (`reached preparation quorum … votes: 5/6/7`, `reached commit quorum … votes: 5/6/7`).
- **Lockstep finality.** All seven nodes (five Geth + two `neox-rs`) report the identical block and
  hash at every checkpoint; e.g. block 328 `0xaa133699…` on all seven. Zero panics and zero recovery
  errors on the `neox-rs` nodes.

## Scope and remaining work

This run is the pre-anti-MEV (ECDSA) regime. It does **not** exercise the ZK-v1 anti-MEV path
(DKG/TPKE decryption during block production), which requires the network-approved ZK ceremony
artifacts (downloadable, ~3.6 GB) and the `zk` privnet layout. The separate fault-injection report
covers crash/view-change, transaction inclusion, restart/backfill, and whole-cluster restart; the
remaining live gates are prover delay, transaction replacement, Anti-MEV decryption, and controlled
reorg, followed by an independent security review. Validator mode remains pre-release until those
are complete, but both the recovery stall and the mixed-client compatibility question are now
resolved.

## Reproduce

1. Build both clients; init seven Geth datadirs with `geth init --state.scheme hash <genesis>` and
   import the seven validator keys; create each node's `antimev-keystore`
   (`geth --datadir <d> antimev init --antimev.password <pw> <addr> 7`).
2. Start a bootnode and seven Geth miners (`--mine --antimev.password <pw> --ipcdisable
   --networkid 47763777 --state.scheme hash`).
3. For the mixed run, stop two Geth miners and start two `neox-rs` validators with those two keys:
   `neox-rs node --chain <genesis> --validator.ecdsa-key <key> --p2p-secret-key-hex <secret>
   --disable-discovery --ipcdisable --trusted-peers <five Geth enodes>`.
4. Compare `eth_getBlockByNumber` across all nodes; confirm identical hashes and, in the Geth logs,
   `received PrepareRequest {"validator": 5|6}` (Reth-produced proposals accepted by Geth).
