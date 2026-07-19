# Neo X ZK-v1 Anti-MEV proving boundary — 2026-07-20

Exercises the zero-knowledge DKG proving path that the Anti-MEV era depends on, using the
network-approved MPC ceremony artifacts, and records a prover bug it surfaced. This covers the
cryptographic boundary (`neox-dkg-prover` ↔ the deployed gnark verifier); the full live
block-production decryption flow on a DKG/Anti-MEV network is scoped but not yet run (see below).

## Artifacts

The production ceremony artifacts were fetched from the network-published source
(`https://zkstorage.blob.core.windows.net/zk-blob/`, per the Neo X Geth `privnet/zk` READMEs) and
pinned by SHA-256:

| message count | R1CS (`.ccs`) | SHA-256 | proving key (`.pk`) | SHA-256 |
|---|---|---|---|---|
| one  | 82 MB  | `08741f3db4a34f98804c33cc3b719cd6842cc2a433382de020a371999f5be3ae` | 698 MB  | `3d470a6e43570f2c8d171e299a384749809b5211bc1af0710f6d45b56ec69373` |
| two  | 152 MB | `53d26dba85f5e8d18af471cfccc9aa86eabe758ed3fae28524d4f7b406d76289` | 815 MB  | `1d92851d68e8d7787656ceaaa1241c3d5aee29ce8396b22b1eaa4cffeeb442cc` |
| seven| 519 MB | `bcad0a7c3c6005e283daf4baa2af3d74dde3a0fb08713df14ae1772e30cfaa2b` | 1.39 GB | `39fbe9b2c54be6a150a05b598875c220894b8580e202a343d7974e133b6eca10` |

These are the SHA-256 values to place in a `dkg-prover-manifest.json` for a node configured against
this ceremony (`docs/neox/dkg-prover-manifest.example.json` ships with zero-digest placeholders by
design).

## Proving boundary verified

`neox-dkg-prover` (the same `bane-labs/zk-dkg` v0.3.0 / gnark v0.13.0 boundary Neo X Geth uses) was
driven with a ZK-v1 request (one recipient, a valid secp256k1 public key, a non-degenerate share
scalar) against the `one_message` R1CS and proving key. It loaded the 976,098-constraint circuit,
solved the witness, and produced a committed Groth16 proof on BN254: a single JSON response with one
ECIES message, eight non-zero proof elements, two commitments, and a commitment proof-of-knowledge,
in ~2.4 minutes.

Degenerate inputs are correctly rejected before proving (a private key of 1 makes the "public key"
the curve generator and the circuit hits `no modular inverse`), and the artifact SHA-256 pins are
enforced, so a wrong or tampered R1CS / proving key is refused.

## Bug found and fixed

gnark's default zerolog logger writes constraint-solver and prover progress to **stdout**. The Rust
node reads the prover's single JSON response from stdout, so on a real ZK-v1 proof the log lines were
interleaved with the JSON and `serde_json` parsing failed — the DKG round would abort in production.
Fixed by routing gnark diagnostics to stderr (`tools/neox-dkg-prover/main.go`), leaving stdout as pure
JSON. This bug is invisible to the Go unit tests because they capture the response through an in-memory
writer rather than the process's real stdout, and only ZK-v1 (real proving) emits the gnark logs.

## Scope and remaining work

Not yet exercised: a live network in the DKG / Anti-MEV era (forks active) running a full round —
DKG key generation with on-chain proof submission, envelope-encrypted transactions, `PreCommit`
decryption-share exchange, and TPKE reconstruction during block building — plus the prover-delay gate
(a slow prover must trigger a view change, not a stall). The TPKE/DKG reconstruction logic carries
strong negative unit coverage already; what remains is the end-to-end network run, which needs the
`zk` privnet layout with the DKG and Anti-MEV forks enabled and per-node DKG keystores. This is the
last major validator-mode gate before an independent security review.
