# Geth PKCS#7 Strictness Migration Audit

Date: 2026-09-02

## Scope and baseline

- Oracle working copy: `D:\Git\neox-oracle-geth`.
- Requested immutable comparison baseline: `f0e236838bb334c7c0d29eeca33533ed0cfda254`.
- Portable migration artifact: `outputs/geth-pkcs7-strict.patch`.
- No Rust protocol, AES, dBFT, or MDBX source was changed for this artifact.
- No formal Geth commit or push was created.

## Patch contents

The patch contains only the following oracle paths:

1. `crypto/tpke/util.go`: make `pkcs7UnPadding` receive the AES block size; reject empty/non-positive/non-block-aligned buffers; accept only `p` in `1..=blockSize` and `p <= len(data)`; verify every trailing byte equals `p`.
2. `crypto/tpke/aes.go`: reject empty or non-block-aligned ciphertext before `CryptBlocks`; pass the actual AES block size to strict unpadding. This prevents the Go CBC implementation from panicking on malformed ciphertext.
3. `crypto/tpke/util_test.go`: exercise canonical padding lengths 1 through 16 and malformed zero, oversized, 255, over-buffer, empty, short, ragged, and non-repeating padding cases.

Patch statistics: **3 files changed, 55 insertions, 6 deletions** (61 added/deleted lines in unified diff; no protocol fields changed). The patch is generated directly from baseline `f0e236838bb334c7c0d29eeca33533ed0cfda254` to the fixed oracle files, with valid hunk headers.

## Verification executed

Commands were run against the oracle path:

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

The patch now passes both reverse applicability and reverse numstat checks. The complete three-file gofmt check and final TPKE test suite passed.

## Cross-client consistency

Rust `crates/neox/antimev/src/tpke.rs` already enforces the same strict PKCS#7 rule and rejects empty/non-16-byte-aligned ciphertext before decryption. Existing Rust negative-vector coverage includes canonical success, zero, oversized, inconsistent, ragged, and empty ciphertext behavior. The oracle patch aligns Geth with that behavior; it does not relax Rust or add a dual parser.

`antimev/tpke.go` already maps AES errors to nil per-message results, and the existing dBFT nil fallback remains unchanged. Malformed ciphertext therefore rejects through the existing error channel without panic, silent truncation, or side effects.

## Deployment and compatibility gates

This is consensus-critical. Before deployment:

- run full Geth TPKE, Anti-MEV, dBFT, and consensus tests;
- run Rust TPKE/Anti-MEV tests and the cross-implementation vector matrix;
- run mixed-client replay against canonical history;
- coordinate a versioned protocol activation height/time in both implementations;
- audit historical malformed-padding payloads before choosing activation.

Do not mix strict and legacy Geth validators after activation. Do not relax Rust to preserve the old lenient behavior: an encryptor controls the AES plaintext/key and can make malformed padding reach a valid signed inner transaction, causing old/new clients to select different transactions. Do not use an ad-hoc rollback; rollback requires coordinated validator policy or an explicit fork rule.

## Unclosed gates

- Formal Geth commit is intentionally **not created**; this patch must be applied and reviewed in the canonical Geth repository at the specified baseline.
- Full Geth consensus/mixed-client replay and protocol activation rehearsal remain outstanding.
- The oracle checkout's Git metadata is not usable in this environment, so baseline ancestry and tracked-worktree status require confirmation from a normal Geth checkout.
- The temporary command capture files (`.gofmt-real.*`, `.go-test-real.*`) are not part of the patch and must remain excluded from any commit.
- Final SHA-256: `crypto/tpke/util.go` `9191a28f659c14868300cc00ae71c91d0a41a2926f770ec9a14d4ac94f82d461`; `crypto/tpke/aes.go` `f69eef3e2f2250dd6c1bd74099388e74c34a5c17ff43ba6aab2a0acfdd0a623a`; `crypto/tpke/util_test.go` `28771e3f263de853e09d87ad761c38e666d9872959819bb24684829aa0d39c4d`; patch `d004fe59bd5d21d43702d341f57080cb8227cf3be2e4634e081519da7d24fb47`.
