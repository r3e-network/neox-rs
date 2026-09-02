# Geth PKCS#7 Strictness Migration Audit

Date: 2026-09-02

## Scope and fixed snapshot

- Oracle working copy: `D:\Git\neox-oracle-geth`.
- Requested immutable comparison baseline: `f0e236838bb334c7c0d29eeca33533ed0cfda254`.
- Portable artifact: `outputs/geth-pkcs7-strict.patch`.
- The patch was regenerated as a valid three-section unified diff after the prior malformed-header issue. It contains exactly one `diff --git` header per file and no prefixed `+diff`/`-diff` lines.
- Patch SHA-256: `c23bc475d50b1f7ad6fd7626f488bdddd99d371a2f1d03605843d54fb75c1280`.
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

## Unclosed gates

- Apply/review this patch in a canonical tracked Geth checkout at baseline `f0e236838bb334c7c0d29eeca33533ed0cfda254`; the oracle snapshot's Git metadata is not usable for ancestry verification.
- Run full Geth TPKE, Anti-MEV, dBFT, and consensus tests, plus Rust TPKE/Anti-MEV and the cross-implementation vector matrix.
- Run mixed-client replay against canonical history and audit historical malformed-padding payloads.
- Coordinate versioned protocol activation height/time in both clients. Do not mix strict and legacy validators after activation; do not use an ad-hoc rollback.
