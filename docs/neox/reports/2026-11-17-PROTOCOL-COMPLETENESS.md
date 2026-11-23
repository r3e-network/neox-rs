# Neo X protocol completeness and correctness audit — 2026-11-17

Question answered: is the Neo X protocol implementation **complete** (every protocol rule the public
networks use is implemented) and **correct** (it agrees with the reference client)?

Oracle: `bane-labs/go-ethereum@bane-main` `f5d768e8a9` (re-fetched today: still the tip, **0 new
commits** since the v2.8.0 audit). Code under audit: release `neox-v2.8.0` (`3a1870a16c`).

## Verdict

For every protocol feature **activated on MainNet or T4**, the implementation is complete and
matches the oracle, supported by the strongest available evidence: a full fresh-datadir MainNet
replay with zero divergence. The only unimplemented features are gated behind forks that are not
scheduled on any public network. Every known intentional difference from the oracle is documented,
pinned by a test, and one-directional (fail-stop or liveness-only), with one consensus-reachable
exception (PKCS#7) whose resolution is a coordinated geth-side activation.

## Evidence layers (all current)

| Layer | Result |
|---|---|
| Full MainNet replay, genesis → 8,321,108 (fresh datadir) | All 13 stages finished; 0 errors; 32,570/32,570 independent block-hash checkpoints matched; fork-boundary header state roots identical |
| Live dBFT follow after replay | 510 consecutive proposals verified against post-state commitments; 0 errors; 0 reorgs; node resumed today and is following head 8,326,6xx |
| Geth delta since `b51d712adf` | 255 commits classified; all required changes applied; 0 unreviewed |
| Unit + integration tests (all 8 Neo X crates) | 441/441 pass (re-run today) |
| Cross-implementation vectors | `geth_cross_vectors`, `geth_negative_vectors`, `geth_reshare_vectors`, `geth_keystore_vectors` all pass; oracle vector files byte-identical |

## Protocol surface coverage

| Protocol area | Geth oracle source | Implementation | Differential evidence |
|---|---|---|---|
| Genesis, chain spec, fork schedule | `config/genesis_neo_x*.json`, `params` | `crates/neox/chainspec` | Genesis byte-equal; replay |
| dBFT extra-data, seal hash, V0/V1/V2 | `consensus/dbft/header.go` | `neox-consensus/extra.rs`, `validation.rs` | Replay; seal test incl. Amsterdam fields |
| dBFT engine rules (base fee, nonces, root) | `consensus/dbft/engine.go` | `neox-consensus-engine` | Replay; Prague/Cancun/Amsterdam fork gating tests |
| All 7 dBFT message types (0x00/0x20/0x21/0x30/0x31/0x40/0x41) | `consensus/dbft/*_request.go`, `payload.go` | `neox-network/dbft_payload.rs` | Live gossip decode; 10 MiB cap parity |
| dBFT participation, view change, recovery | `consensus/dbft/dbft.go` | `neox-node/sync.rs`, `validator.rs`, `producer.rs` | Mixed-client G8 gate; live follow |
| System contracts (all 12 proxies) and `onPersist`/`onPersistV2` | `core/state_processor.go:ProcessOnPersist` | `neox-evm/system_contracts.rs`, `executor.rs` | Call order and DKG gating identical to geth (KeyManagement first, then Governance, V2 gated on NeoXDKG); storage-slot vectors |
| Policy blacklist incl. EIP-7702 delegation (geth #678) | `core/vm` blacklist path | `neox-evm/factory.rs` | Unit tests + Prague replay (4,720,788+) |
| NeoXDKG MCOPY gate, Cancun/Prague forks | `core/vm` fork gates | `neox-evm/factory.rs` | Replay across both boundaries |
| Anti-MEV Envelope parse/admission | `antimev/` | `neox-antimev/envelope.rs`, `neox-node/pool.rs` | Cross vectors; replay |
| TPKE share verify/aggregate, reconstruction, fallback | `crypto/tpke/`, `consensus/dbft/preblock.go` | `neox-antimev/tpke.rs`, `neox-node/reconstruction.rs` | Cross vectors; fault-injection; mixed DKG epoch 1→2 |
| DKG lifecycle (share/reshare/recover, V0/V1) | `consensus/dbft/dkg.go` | `neox-node/dkg*.rs`, `neox-antimev/dkg*.rs` | G8 gate: 1,402 blocks, zero reorgs |
| Txpool policy admission | `core/txpool` | `neox-node/pool.rs` | Audit + replay |
| RPC (`eth_gasPrice`, `eth_envelopeFee`, `eth_maxEnvelopeGas`, `eth_getCachedTransaction`, Policy) | `internal/ethapi` | `neox-node` RPC modules | RPC differential audit; runtime comparator |
| P2P BEACON/2 + dbft/0 | `eth/protocols`, dbft p2p | `neox-network` | Live peers; BEACON/3 correctly not negotiated |

## Known divergences (complete register)

Deliberate, documented in `docs/neox/README.md`, each pinned by a regression test:

1. **BLS12-381 infinity rejection** — fail-stop only; requires colluding quorum to reach.
2. **DKG receipt re-check after 3 blocks** — liveness-only, never changes chain state.
3. **Strict `ZK_VERSION()` decoding** — fail-stop only.
4. **Policy base-fee check on every imported block** — fail-stop only; replay never hit it.
5. **`--txpool.amevcache` caches RPC submissions only** — relay behavior, not consensus.
6. **Ciphertext admission (`CipherText.Verify`)** — geth never verifies before decrypt; Rust rejects
   at admission. One-directional: proven there is no input geth can decrypt that Rust cannot;
   consequence is geth-side liveness, not a state fork.
7. **PKCS#7 strict unpad** — the only consensus-reachable divergence: geth's lenient unpad accepts
   padding length > 16, so a crafted Envelope could decrypt to an inner transaction in geth while
   Rust falls back to executing the Envelope as-is. **Resolution is geth-side**: the strict-unpad
   patch and height-gated `Pkcs7Strict` activation are prepared
   (`2026-09-09-GETH-PKCS7-HEIGHT-GATE-DESIGN.md`); both implementations must not run mixed
   activation states. Never triggered on MainNet: the full 8.32M-block replay had zero divergence,
   and triggering requires a crafted Envelope no wallet produces.

## Not implemented (correctly out of scope today)

- **Extended `PrepareRequest` format + BEACON/3** (`isNeoXPrepareRequestExtensionEnabled`): fork is
  privnet-only at height 5; no public-network activation exists. MainNet replay crossed 8.32M
  blocks without it. Must be ported before any public activation is scheduled.
- **Amsterdam on public networks**: rules implemented and tested, fork unscheduled (matching geth).
- **Reth evm2 migration**: engineering backlog, not a protocol gap; correctness fixes from the
  evm2 line are backported individually.

## Conclusion

No protocol work is outstanding for the currently deployed Neo X networks. The two activation-gated
items above are tracked in `source-baseline.toml` with `pending_activation_gates`, so any future
geth fork scheduling triggers a port requirement automatically at the next delta audit.

## Update — 2026-11-23

Re-verified after the bane-main delta `f5d768e8a9` → `da96fc385d` (3 commits, see
`2026-11-23-GETH-DELTA.md`) and the Reth backlog re-audit (`c09a02d4e0` → `95b1b67496`, 43
commits, no Neo X protocol impact):

- **Geth #683 applied**: the Prague `requestsHash == EmptyRequestsHash` enforcement was removed
  from `validate_neox_header_fields`; only presence is checked, matching the oracle. Headers
  carrying a real `CalcRequestsHash` value now validate. Pinned by
  `prague_accepts_any_non_nil_requests_hash`.
- All other protocol areas re-checked against the new oracle tip; `antimev/`, `crypto/tpke/`, and
  both genesis files byte-identical between the tips, so every vector suite remains valid.
- Full Neo X test suite re-run green (442/442); nightly rustfmt and clippy clean.
- The verdict, the coverage matrix above, and the divergence register are unchanged by the
delta; the restored replay node was relaunched with the updated binary to re-confirm live
consensus follow under the relaxed requestsHash rule.
