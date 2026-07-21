# Neo X code-quality audit — 2026-07-21

Scope: the Neo X Rust implementation on the `neox` branch (`crates/neox/*` and
`bin/neox-rs`). This audit focuses on maintainability, explicit invariants, error handling,
ownership, unsafe-code boundaries, concurrency, consistency, and testability. Consensus behavior
and wire compatibility were treated as constraints: a smaller or more stylistically uniform diff
was not accepted if it weakened those properties.

This is an internal code-quality audit. It complements, but does not replace, the protocol,
security, interoperability, fault-injection, and live-validator release gates documented elsewhere
under [`docs/neox/reports`](.).

## Baseline and method

The review started from `aeed475191` (`neox-v2.4.1-rc.5`) with a clean worktree aligned to
`origin/neox`. The audited Rust scope contained 28,144 lines at that point. The method combined:

- module and dependency-boundary review of every Neo X crate and the `neox-rs` binary;
- production `expect`/`unwrap`, typed-error, allocation, clone, and lint-suppression review;
- all `unsafe` operations and their BLST FFI preconditions;
- secret-bearing types and buffer-zeroization review;
- shared-state, lock-order, lock-poisoning, and async task-boundary review;
- public re-export and API-shape review;
- the exact Neo X CI commands, focused regression tests, no-std checking where applicable, and
  build/tooling checks.

The final reviewed scope contains 28,264 Rust lines. The increase is primarily typed contexts,
explicit error variants, two clock regression tests, and a small BLST field-operation module; it is
not generated or duplicated implementation.

## Results summary

| ID | Area | Baseline problem | Resolution | Evidence |
|---|---|---|---|---|
| CQ-01 | Orchestration APIs | Eight large functions suppressed or expected `too_many_arguments`, hiding implicit dependency groups | Replaced positional parameter lists with function-specific contexts and owned result types; no suppression remains | `3ac48bbcd5` |
| CQ-02 | Async errors | Anti-MEV task failures crossed async boundaries as flattened strings | Added typed reconstruction-task errors that retain their source error category | `3ac48bbcd5` |
| CQ-03 | Availability | Present-time validation panicked when the host clock was before the Unix epoch | Added `SystemTimeBeforeUnixEpoch` and returned a typed consensus error; supplied-time logic is independently testable | `5e2ba6228c` |
| CQ-04 | Unsafe/FFI | BLST scalar add/subtract/multiply/from-u64 wrappers were duplicated across DKG and TPKE | Centralized the wrappers in `antimev::field`, reduced BLST unsafe sites from 59 to 56, and enabled `undocumented_unsafe_blocks` as a crate lint | `d4f4b37619` |
| CQ-05 | Type invariants | `DkgTaskMaterial` could represent method/PVSS/recovery-index combinations that production code handled with three `expect` calls | Introduced a method-specific enum, made invalid combinations unrepresentable, consumed the material during encoding, and removed the clones and panics | `5b4a666b97` |

All five changes are narrow in observable behavior. CQ-03 intentionally changes one failure mode
from process panic to a returned typed error. The other changes preserve calldata, cryptographic
output, transaction ordering, consensus decisions, and wire bytes.

## Detailed assessment

### 1. Architecture and module boundaries

The crate-level split is sound: chainspec, consensus validation, consensus-engine integration,
Anti-MEV cryptography, EVM/system contracts, network protocols, and node orchestration have distinct
ownership. The binary is mainly composition and operational lifecycle code. The main structural
weakness is below the crate boundary: several orchestration files contain multiple state machines
and therefore demand unusually broad context.

The context refactor in CQ-01 makes dependency groups explicit without introducing a generic
"god context". Each new context belongs to one operation, borrows only what that operation needs,
and keeps ownership visible at the call site. `ReconstructedSequence` similarly owns its output and
failure bookkeeping, so fallback inclusion no longer passes a wide collection of mutually dependent
arguments.

The largest remaining files are:

| File | Lines | Assessment |
|---|---:|---|
| `crates/neox/node/src/sync.rs` | 3,277 | Highest maintainability risk; combines event driving, dBFT timers/actions, proposal recovery, Anti-MEV reconstruction, and block import coordination |
| `crates/neox/node/src/validator.rs` | 1,608 | Dense but cohesive consensus-round validation; extraction needs explicit state ownership |
| `crates/neox/network/src/dbft_payload.rs` | 1,204 | Codec plus validation and extensive vectors; a codec/types/test split is plausible |
| `bin/neox-rs/src/main.rs` | 1,050 | Composition, CLI lifecycle, and local caches; moderate risk |
| `crates/neox/antimev/src/tpke.rs` | 1,039 | Cryptographic code plus vectors; size alone is not a reason to fragment the reviewed FFI boundary |

`sync.rs` should be decomposed only after defining the state ownership and event ordering of each
candidate driver. Merely moving functions into smaller files would improve line-count metrics while
making consensus ordering harder to inspect.

### 2. Types, invariants, and error handling

The codebase generally uses `thiserror` enums at crate boundaries and converts to operational
strings only at logging/process boundaries. CQ-02 fixes a notable exception where typed Anti-MEV
errors were flattened before the orchestrator could classify them.

CQ-05 applies the same principle to data: a DKG method requiring PVSS now carries PVSS in its enum
variant, while recovery carries its indices. Encoding consumes the material and moves these values
into the ABI call. This removes three production `expect` calls and avoids copying potentially large
PVSS or index buffers.

Remaining `expect` calls were reviewed individually. The cryptographic conversion from a validated
`DkgSecretScalar` to the identical prover-scalar representation and lock-poison fail-fast paths are
documented local invariants, not input validation. They should not be mechanically replaced with
fallback values: doing so could hide corrupted consensus or secret state. New input- or
environment-dependent paths should continue to return typed errors, as CQ-03 now does.

### 3. Unsafe code and cryptographic boundaries

The Anti-MEV crate now has `#![warn(clippy::undocumented_unsafe_blocks)]`. All 56 BLST unsafe sites
have adjacent safety rationale, and deserialization status is checked before subgroup or infinity
inspection. The new private `field` module owns the repeated scalar-field operations rather than
duplicating raw-pointer calls in DKG and TPKE.

This does not make the cryptography "safe by lint": correctness still depends on BLST's API contract,
canonical encoding, subgroup checks, and the Geth-derived vectors. The important improvement is that
the FFI assumptions have one auditable shape and omissions now fail lint review.

The one non-BLST unsafe operation in the audited scope sets `RUST_BACKTRACE` before worker threads
are started. It is isolated at process startup and carries a safety explanation.

### 4. Ownership, allocations, and secrets

Secret scalar, private-share, keystore-state, and prover-share types use `Zeroize`/
`ZeroizeOnDrop`; password and encoded request buffers are held in zeroizing wrappers or explicitly
wiped. Debug implementations expose counts/indices rather than secret values. The earlier raw-key
file fix also wipes the source heap buffer before returning the fixed-size key.

The reviewed refactors preserve this discipline:

- contexts borrow secret-bearing state rather than adding long-lived clones;
- typed task errors do not embed secret material;
- DKG material is consumed at the ABI boundary, eliminating PVSS/index clones;
- `DkgTaskMaterial::Debug` reports only method, sender, recipient indices, counts, and PVSS length.

### 5. Concurrency and lock policy

The dBFT caches use a consistent nested order: `messages` before `senders`. No inverse acquisition
was found. Peer-map locks are held only for short map operations or command fan-out, and async
network work is not awaited while holding them.

Lock-poison behavior is intentionally different across roles but is not documented as a policy:
local caches and signer-share holders recover the poisoned inner value, while event receivers and
network consensus state fail fast. This may be the correct distinction—availability-oriented cache
versus invariant-bearing consensus state—but it should be stated in module documentation and
covered by a small policy note before future contributors normalize it in either direction.

### 6. Style, lints, and API surface

At baseline, five `allow` and three `expect` attributes suppressed `too_many_arguments`. There are
now zero such attributes in the audited scope. Formatting is owned by nightly rustfmt and the exact
CI Clippy set builds every target with `-D warnings` on stable Rust.

The remaining style-level API debt is eight glob re-exports across `reth-neox-antimev` and
`reth-neox-evm`. They are convenient today, but make name ownership and future collision review
less explicit. Replacing them requires a deliberate public-API migration or compatibility aliases;
it was not bundled into behavior-preserving internal refactors without downstream API evidence.

### 7. Tests and documentation

The Neo X packages have strong unit/vector coverage for dBFT state transitions, codecs, EVM rules,
DKG/TPKE, Geth interoperability, block reconstruction, and malformed/adversarial inputs. The clock
fix adds both the pre-epoch error regression and a supplied-time boundary test. DKG type-invariant
tests still assert every deployed selector and deterministic proof-bearing calldata after switching
to owned encoding.

There is no dedicated Neo X fuzz target, and the audited node package currently reports zero
doctests. Existing adversarial loops and golden vectors are valuable but do not replace persistent
fuzz corpora. The highest-return additions are fuzz targets for dBFT RLP envelopes/recovery payloads,
DKG prover JSON, encrypted keystore decoding, and Anti-MEV envelope/sidecar boundaries.

## Deferred work, in priority order

1. **Design the `sync.rs` decomposition.** Define state ownership and ordering invariants for the
   beacon/import driver, dBFT round driver, proposal transaction recovery, and Anti-MEV
   reconstruction before moving code.
2. **Add persistent fuzzing.** Seed corpora from the existing Geth golden vectors and adversarial
   unit cases; run with bounded allocation assertions where parsers accept peer-controlled lengths.
3. **Document lock-poison policy.** Make the fail-fast versus recover-and-continue distinction
   explicit per shared-state class.
4. **Replace glob re-exports with an API migration plan.** First inventory downstream imports, then
   add explicit re-exports without silently breaking external validators or tooling.
5. **Increase executable API documentation.** Add doctests for public construction/validation APIs
   where examples can be deterministic and do not require a live chain.

These are code-quality recommendations, not evidence of a consensus defect. Validator readiness
still depends on the separate live and independent-review gates.

## Verification gates

The final local branch passed the exact repository CI-equivalent commands:

| Gate | Result |
|---|---|
| Nightly rustfmt | pass |
| Stable Rust tests | 219 passed, 0 failed, 0 ignored |
| Stable Clippy, all Neo X targets, `-D warnings` | pass |
| `neox-rs` binary build | pass; macOS linker emitted the existing large `__eh_frame` warning |
| Go DKG prover test and build | pass |
| Python interoperability/tooling suite | 60 passed |
| Anti-MEV and consensus-engine no-default-feature checks | pass; six existing warnings originate in upstream `reth-trie-common` |

Commands:

```text
cargo +nightly fmt --all -- --check
cargo +stable test --locked \
  -p reth-neox-chainspec -p reth-neox-consensus -p reth-neox-consensus-engine \
  -p reth-neox-antimev -p reth-neox-evm -p reth-neox-network -p reth-neox-node \
  -p neox-rs
cargo +stable clippy --locked --all-targets \
  -p reth-neox-chainspec -p reth-neox-consensus -p reth-neox-consensus-engine \
  -p reth-neox-antimev -p reth-neox-evm -p reth-neox-network -p reth-neox-node \
  -p neox-rs -- -D warnings
cargo +stable build --locked -p neox-rs --bins
(cd tools/neox-dkg-prover && go test ./... && go build -trimpath -o /tmp/neox-dkg-prover .)
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Focused checks additionally cover `reth-neox-antimev` without default features and
`reth-neox-consensus-engine` without default features. The local `cargo-nextest` subcommand is not
installed, so the repository's canonical `cargo test` gate is used rather than claiming nextest
coverage.

## Conclusion

The audited code is materially more explicit and easier to review: dependency groups are typed,
task errors retain their categories, an environmental clock fault no longer panics the process,
the BLST boundary is centralized and lint-enforced, and DKG calldata material cannot represent an
invalid method/payload combination. The remaining debt is concentrated and visible rather than
hidden behind lint suppressions. The next quality phase should be measured architectural work on the
sync driver plus fuzzing—not broad cosmetic rewriting of consensus-critical code.
