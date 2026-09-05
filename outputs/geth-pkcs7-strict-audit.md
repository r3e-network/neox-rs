# Geth PKCS#7 Strictness Migration Audit

Date: 2026-09-02

## Scope and fixed snapshot

- Oracle working copy: `D:\Git\neox-oracle-geth`.
- Requested immutable comparison baseline: `f0e236838bb334c7c0d29eeca33533ed0cfda254`.
- Portable artifact: `outputs/geth-pkcs7-strict.patch`.
- The patch was regenerated as a valid three-section unified diff after the prior malformed-header issue. It contains exactly one `diff --git` header per file and no prefixed `+diff`/`-diff` lines.
- Patch SHA-256: `a2cc2fa368152d15007f89f32d8422b22abdfc2bab1d61696c0dc4e07cb4f281`.
- No Rust protocol, AES, dBFT, or MDBX source was changed. No formal Geth commit or push was created.

## Fixed source files

The patch contains only these oracle paths:

1. `crypto/tpke/util.go`: `pkcs7UnPadding` receives the AES block size; rejects empty/non-positive/non-block-aligned buffers; accepts only `p` in `1..=blockSize` and `p <= len(data)`; verifies every trailing byte equals `p`.
2. `crypto/tpke/aes.go`: rejects empty or non-block-aligned ciphertext before `CryptBlocks`; passes the actual AES block size to strict unpadding, preventing malformed-input CBC panics.
3. `crypto/tpke/util_test.go`: exercises canonical padding lengths 1 through 16 and malformed zero, oversized, 255, over-buffer, empty, short, ragged, and non-repeating padding cases.

Patch statistics: **3 files changed, 55 insertions, 6 deletions**; reverse `git apply --numstat` reported `0/41` for the test file, `1/4` for AES, and `5/10` for util against the fixed snapshot. No protocol fields changed.

## Verification commands and actual exit codes

The following commands were run against the oracle path:

```text
git -C D:/Git/neox-oracle-geth apply --reverse --check D:/Git/neox-rs/outputs/geth-pkcs7-strict.patch
exit code: 0

git -C D:/Git/neox-oracle-geth apply --numstat --reverse D:/Git/neox-rs/outputs/geth-pkcs7-strict.patch
exit code: 0
0  41  crypto/tpke/util_test.go
1  4   crypto/tpke/aes.go
5  10  crypto/tpke/util.go

C:/Program Files/Go/bin/gofmt.exe -d D:/Git/neox-oracle-geth/crypto/tpke/util.go D:/Git/neox-oracle-geth/crypto/tpke/aes.go D:/Git/neox-oracle-geth/crypto/tpke/util_test.go
exit code: 0

C:/Program Files/Go/bin/go.exe -C D:/Git/neox-oracle-geth test ./crypto/tpke
exit code: 0
ok github.com/ethereum/go-ethereum/crypto/tpke (cached)
```

The final verification used a clean temporary repository whose three baseline files were written with `git cat-file blob` from the requested commit, with `core.autocrlf=false`; clean-baseline forward `git apply --check` exited 0, oracle reverse `git apply --reverse --check` exited 0, and reverse numstat exited 0. The frozen source hashes are retained at `.workbuddy/frozen-oracle-hashes.txt`.

## Cross-client behavior

Rust `crates/neox/antimev/src/tpke.rs` already enforces the same strict PKCS#7 rule and rejects empty/non-16-byte-aligned ciphertext before decryption. Existing Rust negative-vector coverage includes canonical success, zero, oversized, inconsistent, ragged, and empty ciphertext behavior. The oracle patch aligns Geth with Rust; it does not relax Rust or add a dual parser.

`antimev/tpke.go` already maps AES errors to nil per-message results, and the existing dBFT nil fallback remains unchanged. Malformed ciphertext therefore rejects through the existing error channel without panic, silent truncation, or side effects.

## Independent migration-gate conclusion

### Portable artifact apply/content verification: **PASS**

The portable artifact is internally consistent and content-verified: it contains exactly the three intended `crypto/tpke` files, retains patch SHA-256 `a2cc2fa368152d15007f89f32d8422b22abdfc2bab1d61696c0dc4e07cb4f281`, and the recorded reverse `git apply --check`, clean-baseline forward `git apply --check`, reverse `git apply --numstat`, three-file `gofmt -d`, and TPKE test commands all exited 0. The recorded numstat is `0/41` for `util_test.go`, `5/10` for `util.go`, and `1/4` for `aes.go`.

### Canonical checkout / HEAD ancestry / formal Geth migration gate: **FAIL — NOT COMPLETE**

The requested isolated target directory `D:/Git/geth-canonical-pkcs7-20260902` did not exist after the clone command returned, so no canonical Geth checkout was obtained. The verification script then failed to change into that target and did not abort; subsequent Git commands therefore ran in the existing `D:/Git/neox-rs` Rust working tree. This is not canonical Geth evidence: `git cat-file -t f0e236838bb334c7c0d29eeca33533ed0cfda254` hit the Rust repository's object database and returned `commit` (exit 0), while `git rev-parse HEAD` returned `ae169d8db67d60eb7c64581c224220b31cc95c32` (exit 0) and `git merge-base --is-ancestor f0e236838bb334c7c0d29eeca33533ed0cfda254 HEAD` returned exit 1. `git status --short` was read-only (exit 0) and showed the existing Rust worktree's modifications/untracked files. The attempted `git checkout --detach f0e236838bb334c7c0d29eeca33533ed0cfda254` was blocked by those existing modifications (exit 1); no checkout succeeded. The attempted `git apply --check D:/Git/neox-rs/outputs/geth-pkcs7-strict.patch` failed because `crypto/tpke/aes.go`, `crypto/tpke/util.go`, and `crypto/tpke/util_test.go` were absent in that worktree (exit 1). No worktree write, successful checkout, actual patch application, or commit occurred during this investigation. Consequently, this investigation does not constitute canonical Geth evidence; the canonical migration gate remains **FAIL — NOT COMPLETE** and must not be represented as canonical Geth validation or a commit.

## Unclosed gates

- ~~Apply/review this patch in a canonical tracked Geth checkout at baseline `f0e236838bb334c7c0d29eeca33533ed0cfda254` with a verifiable `HEAD` and ancestry.~~ **CLOSED 2026-09-05** — see [docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md](../docs/neox/reports/2026-09-05-GETH-PKCS7-CANONICAL-VALIDATION.md): patch applied in `D:\Git\neox-geth` at the pinned commit, gofmt/TPKE tests/vet clean.
- Run full Geth TPKE, Anti-MEV, dBFT, and consensus tests, plus Rust TPKE/Anti-MEV and the cross-implementation vector matrix.
- Run mixed-client replay against canonical history and audit historical malformed-padding payloads.
- Coordinate versioned protocol activation height/time in both clients. Do not mix strict and legacy validators after activation; do not use an ad-hoc rollback.

## M0 environment preflight

- Rust repository `HEAD`: `ae169d8db67d60eb7c64581c224220b31cc95c32`.
- Objects `f0e236...` and `3bc71d43...` both return `commit` from this object database; this does **not** establish Geth ancestry (the object database is the Rust repository's, not a canonical Geth checkout).
- Toolchain/environment availability: Go `1.27.0`, cargo `1.95.0`, rustc `1.95.0`, and WSL 2 are available. `gofmt -d` over the three TPKE files exited `0`.
- Network preflight: ports `8545`, `8546`, `8551`, `30303`, `6060`, `6061`, and `6062` were all not listening.
- Required local binaries are absent under `target/debug`: `reth`, `reth-neox`, `geth`, and `bootnode`.
- Mixed DKG scripts, test entry points, and vector artifacts are present (13 files under `docs/neox/vectors`: 4 Python generators + 5 JSON artifacts including `geth-tpke-vectors.json` + 4 Geth exporter Go tests).
- M0 conclusion: **PARTIAL / LIVE GATES NOT EXECUTED**.
- Rust `reth-neox-antimev` real test result this round: `45 unit + 3 admission + 9 cross + 14 negative + 4 reachability + 16 reshare + 0 doctest`; all passed, command exit `0`.
- Rust `reth-neox-node` real test result this round: 159 unit/integration tests (`pool`, `proposal`, `reconstruction`, `sync`, `validator`, `dkg`); all passed, command exit `0` (unblocked by `.cargo/config.toml` MinGW toolchain configuration).
