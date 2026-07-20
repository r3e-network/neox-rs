# Neo X feature-specific performance optimizations — 2026-07-20

A targeted pass over the Neo X protocol hot paths (dBFT consensus, BLS12-381 TPKE/DKG, Anti-MEV
block reconstruction, Policy/Governance reads, beacon/dbft wire) for **result-identical** performance
improvements — distinct from the security (safety) and code-quality (style) passes. Every change was
adversarially verified to produce byte-identical output, ordering, error behavior, and determinism;
anything that could alter consensus/crypto output or diverge from the Neo X Geth oracle was rejected.

## Applied

- **TPKE batch decrypt decodes the global public key once** (`antimev/src/tpke.rs`).
  `aggregate_and_decrypt_keys` re-`blst_p1_uncompress`+subgroup-checked the identical DKG global
  public key on every `(combination × ciphertext)` inner call while recovering an Anti-MEV block's
  Envelope keys. It now decodes the key once via a `aggregate_and_decrypt_with_key` inner variant; a
  malformed key still surfaces as `DecryptionAggregationFailed`, preserving observable behavior. The
  public `aggregate_and_decrypt` keeps its exact validate-then-decode order.
- **Threshold-signature aggregation decodes each G2 share once** (`antimev/src/tpke.rs`). The
  combination search in `aggregate_and_verify_signature_shares` re-decoded each selected G2 share on
  every subset it appeared in (up to 21 subsets for 5-of-7); shares are now uncompressed once into
  `interpolate_signature_shares`. Each share's subgroup check already ran at `SignatureShare`
  construction, so no error path changes.
- **Anti-MEV block logs bloom is OR-ed from receipt blooms** (`node/src/reconstruction.rs`). The block
  bloom was recomputed by re-hashing every log; it is now the bitwise-OR of the per-receipt blooms
  already computed for the receipts root. OR is associative/commutative, so the 256-byte bloom is
  bit-identical.
- **Block propagation encodes once, not per peer** (`node/src/sync.rs`). `BeaconCommand::NewBlock`
  deep-cloned and re-RLP-encoded the whole block for each peer in `broadcast`. The block frame body is
  now encoded once and fanned out as an existing `BeaconCommand::Raw` frame (`NewBlock`'s id `0x02` is
  within every negotiated version's range), so the bytes are identical to per-peer encoding without
  the clone+re-encode.
- **Sidecar `contains()` stats instead of decoding** (`network/src/store.rs`). It read and fully
  RLP-decoded the entire (up to ~10 MiB) sidecar file just to return a boolean; since `insert()`
  writes atomically (temp + rename), a present file is complete, so an existence check suffices. Used
  per-block on serving nodes and per blob request.
- **Reconstruction borrows instead of cloning the outer transactions/senders**
  (`node/src/reconstruction.rs`). The full outer transaction and sender vectors were cloned up front;
  they are now borrowed (the borrows end before `proposal.block` is reassigned), removing per-block
  heap copies of the whole transaction list.

## Deliberately deferred

- **Consensus messages are cryptographically verified twice** (network admission in
  `network/src/dbft.rs` + round state in `node/src/validator.rs`) — the single highest-value finding
  (doubles per-message ECDSA recovery and BLS subgroup checks, up to hundreds for a `RecoveryMessage`).
  Skipped here because the fix threads already-verified state through the network→round boundary and
  adds a decode-skipping process path, touching the exact verification flow the security review just
  hardened; a mistake is a consensus-safety hole, not a perf regression. It warrants dedicated design
  plus the live fault-gate harness, not a bundled refactor.
- **Lagrange coefficients per ciphertext, caching decoded points in `TpkeCiphertext`, and
  consensus-message hash caching** — lower-value (scalar work / cheap keccak, once per block) versus
  the restructuring they require in consensus-critical crypto; deferred pending a measured need.

## Validation

All 204 Neo X unit tests pass (including `aggregates_five_of_seven_signature_shares`, the TPKE decrypt
vectors, and the beacon codec/golden-vector tests), `cargo +nightly fmt --all --check` is clean, and
the full strict clippy set produces no warnings.
