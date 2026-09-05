# Release Notes - Neo X v2.5.2

## Overview

`neox-v2.5.2` closes all eleven findings from the 2026-09-05 systematic review (four P1), hardens
dBFT consensus against cross-view manipulation, aligns Anti-MEV reconstruction pool admission with
the reference client's parent-state semantics, introduces a versioned activation gate for strict
PKCS#7 unpadding, and adds durable validator signing-duty records. All 418 Neo X Rust tests pass,
with nightly rustfmt and strict (`-D warnings`) clippy clean.

> Note on versions: the `neox-rs` binary reports the workspace version (`2.5.1`), which tracks the
> pinned upstream Reth baseline; the `neox-v2.5.2` tag tracks the Neo X layer, per the versioning
> split documented in `.github/workflows/neox-release.yml`.

---

## Key Highlights & Changes

### 1. dBFT Consensus Hardening
- **Reference-aligned ChangeView tally**: each validator's latest `ChangeView` request is kept and
  superseded (lower-targeted retransmissions are dropped), the candidate view is tallied
  cumulatively over every request whose target meets or exceeds it, and future-view requests are
  processed immediately — so a lagging node catches up in one step, matching nspcc-dbft v0.3.2
  (`onChangeView`/`checkChangeView`).
- **ChangeView removed from seen-map equivocation checks**: duplicate detection keyed by view used
  to poison a round when a future-view request was replayed after the round reached that view.
- **Recovery path restored for future views**: recovered `ChangeView` contributions drive the
  round to the recovered view through the same cumulative rule.

### 2. Anti-MEV Reconstruction Pool Admission (Consensus-Fork Fix)
- **Parent-state per-sender admission**: the scratch pool now tracks each sender's parent-state
  nonce and cumulative maximum cost (`max_fee_per_gas * gas_limit + value`) and refuses nonces
  below the tracked state or costs above the remaining balance — previously a sender whose
  parent-state balance was insufficient could be kept because sequential execution funded them
  earlier in the block, a divergence the reference client's pool does not allow.
- **Check/commit discipline**: admission state advances only after a transaction is actually
  included, so a rejected or failed Envelope replacement never consumes the fallback Envelope's
  budget; nonce gaps follow the pool's queued semantics instead of hard refusal.
- **Proposal gate moved behind the parent state**: proposal verification now opens the resolved
  parent state and applies the same per-sender admission before signing.

### 3. PKCS#7 Strict Unpadding — Versioned Activation
- **`Pkcs7Strict` hardfork**: optional `neoXPkcs7StrictBlock` genesis field gates strict unpadding
  per block height; chains that do not configure it stay byte-compatible with the unpatched
  reference client (MainNet and T4 TestNet default to the legacy behavior until coordinated
  activation).
- **Dual-mode decryption**: `decrypt_message_with_mode` — legacy mode reproduces the reference
  client's original acceptance set for pre-fork replay, strict mode enforces the audited
  `1..=16` rule; `decrypt_message` defaults to strict.
- **Canonical Geth validation**: `outputs/geth-pkcs7-strict.patch` (SHA-256
  `a2cc2fa368152d15007f89f32d8422b22abdfc2bab1d61696c0dc4e07cb4f281`) was applied to a tracked
  checkout of the pinned oracle commit `f0e236838bb334c7c0d29eeca33533ed0cfda254` with a verified
  HEAD — gofmt, the full strict test matrix (26 subtests), and `go vet` are clean
  (`docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md`).
- **Offline Envelope census scanner**: `scripts/neox-scan-history-pkcs7.py` correlates
  plaintext-committed inner hashes against block contents to scope the historical
  replaced-vs-fallback distribution (it cannot decrypt threshold ciphertexts; definitive padding
  verification requires committee key material or a mixed replay).

### 4. Validator Signing Safety
- **Durable duty journal**: the signer records every duty-bearing payload (prepare, pre-commit,
  commit, finalized-header seals) in an fsync-backed journal (`neox-dbft-duties.jsonl` under the
  node's per-chain data directory) before producing the signature, reloads it on startup, refuses
  a different payload for the same recorded duty, and stays idempotent for identical ones —
  closing the restart gap in equivocation protection. A torn crash tail is skipped by hash-shape
  validation; ChangeView and Recovery payloads stay exempt (their legitimate repeats carry fresh
  timestamps or state dumps).

### 5. Reconstruction Resilience
- **Transient-failure retry with backoff**: provider-backed failures during Anti-MEV
  reconstruction are classified separately from share-set failures and retry the identical share
  set up to five times with a doubling backoff (250 ms, capped at 8 s); deterministic failures
  still require new contributions.

### 6. Cross-Platform Build & Release Pipeline Hardening
- **Bindgen flags scoped out of the workspace** (review R04): the global
  `BINDGEN_EXTRA_CLANG_ARGS` Windows-GNU target flags were removed from `.cargo/config.toml`;
  host-specific configuration lives in the host environment (documented in `AGENTS.md`).
- **Release provenance verification** (review R08): the release pipeline now peels the release tag
  and compares every bundle's `SOURCE_COMMIT` against the build commit before the draft release
  becomes visible — a recovery dispatch packaging a build from one commit under a tag pointing at
  another is rejected.
- **PR/merge-queue coverage** (review R09): the `neox` workflow (Rust fmt/tests/clippy, Go prover,
  static ELF and Python compatibility tools) now runs on `pull_request` and `merge_group`.
- **Format baseline restored** (review R10): nightly rustfmt is clean across the workspace.
- **Baseline documentation sync** (review R11): the README baseline table quotes
  `docs/neox/source-baseline.toml` exactly, genesis fingerprints are documented as oracle-byte
  hashes, and a unittest (`scripts/tests/test_baseline_docs.py`) keeps the documents from
  drifting.

---

## Test Verification

- **Neo X Rust suite**: **418 passed; 0 failed** across all eight crates:
  - `reth-neox-node`: 171
  - `reth-neox-antimev`: 47 library + 47 integration vectors (94 total)
  - `reth-neox-network`: 47
  - `neox-rs` CLI: 29
  - `reth-neox-evm`: 28
  - `reth-neox-consensus`: 18
  - `reth-neox-chainspec`: 17
  - `reth-neox-consensus-engine`: 14
- **Nightly rustfmt**: `--check` clean across the workspace.
- **Strict clippy**: `--all-targets -D warnings` clean on all Neo X crates.
- **Go DKG prover**: `go test ./...` pass.
- **Python tooling**: 70 tests (58 executed, 12 platform-skipped on Windows).

---

## Upgrade Notes

- No storage migration; the duty journal is created on first validator start.
- The `Pkcs7Strict` fork is **inactive** unless `neoXPkcs7StrictBlock` is configured in the
  genesis `config`. Activating it must be coordinated with the reference client's strict patch
  (`outputs/geth-pkcs7-strict.patch`): strict and legacy validators must not mix after activation,
  and no ad-hoc rollback is permitted.
- The release pipeline now automatically verifies that the release tag resolves to the built
  commit and that every bundle's recorded `SOURCE_COMMIT` matches, before the draft release is
  created.
