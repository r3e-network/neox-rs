# Geth PKCS#7 Strict Patch — Canonical Checkout Validation

Date: 2026-09-05

## Scope

Closes the "canonical checkout / HEAD ancestry / formal Geth migration gate" that
[outputs/geth-pkcs7-strict-audit.md](../../outputs/geth-pkcs7-strict-audit.md) recorded as
**FAIL — NOT COMPLETE** on 2026-09-02. This run performs the patch apply, format check, and TPKE
test run inside a tracked Geth checkout at the pinned oracle commit, with a verifiable `HEAD`.

## Fixed checkout

- Repository: `https://github.com/bane-labs/go-ethereum` (bane-labs Neo X Geth fork, the pinned
  behavior oracle per `docs/neox/source-baseline.toml`).
- **Read-only oracle policy**: the upstream repository is never modified by this project — no
  fork, branch, commit, push, or pull request was created there. The only interaction was an
  anonymous `git fetch` of the pinned public commit; the local checkout is disposable scratch
  used solely to verify the portable patch, and the patch reaches the reference client only
  through whoever operates it.
- Oracle commit: `f0e236838bb334c7c0d29eeca33533ed0cfda254` (`bane-main`, `0.7.0-dev`).
- Local checkout: `D:\Git\neox-geth`, obtained with `git fetch --depth 1 origin
  f0e236838bb334c7c0d29eeca33533ed0cfda254` + `git checkout --detach FETCH_HEAD`.
- `git rev-parse HEAD` after checkout: `f0e236838bb334c7c0d29eeca33533ed0cfda254` — exact match.
- Working tree normalized with `core.autocrlf=false` / `core.eol=lf` and re-checkout before the
  patch, so all verification ran on LF files.

## Patch application and verification

- Patch: `outputs/geth-pkcs7-strict.patch`.
- Patch SHA-256: `a2cc2fa368152d15007f89f32d8422b22abdfc2bab1d61696c0dc4e07cb4f281` — recomputed
  from the committed file and from `git show HEAD:outputs/geth-pkcs7-strict.patch`; both match the
  value recorded in the 2026-09-02 audit.
- `git apply --check` exited 0; `git apply` produced `3 files changed, 55 insertions, 6
  deletions` (`crypto/tpke/aes.go` +1/-4, `crypto/tpke/util.go` +5/-10, `crypto/tpke/util_test.go`
  +41/-0), matching the audit's reverse-numstat record.
- `gofmt -l crypto/tpke/aes.go crypto/tpke/util.go crypto/tpke/util_test.go`: no output (clean).
  Note: `gofmt -l` over the whole package additionally lists thirteen files that are unmodified by
  the patch; that drift exists in the upstream tree at the pinned commit and was left untouched.
- `go test ./crypto/tpke` (Go 1.27.0): `ok github.com/ethereum/go-ethereum/crypto/tpke`.
- `go test ./crypto/tpke -run TestPKCS7UnPaddingStrict -v`: all 26 subtests pass — padding lengths
  1..=16 accepted, and zero, 17, 255, over-buffer, empty, short, non-block-aligned, and
  non-repeating padding all rejected.
- `go vet ./crypto/tpke`: clean.
- Post-patch source fingerprints (SHA-256) for the migration record:

| File | SHA-256 |
|---|---|
| `crypto/tpke/aes.go` | `f69eef3e2f2250dd6c1bd74099388e74c34a5c17ff43ba6aab2a0acfdd0a623a` |
| `crypto/tpke/util.go` | `9191a28f659c14868300cc00ae71c91d0a41a2926f770ec9a14d4ac94f82d461` |
| `crypto/tpke/util_test.go` | `28771e3f263de853e09d87ad761c38e666d9872959819bb24684829aa0d39c4d` |

The patch's strict matrix exercises the same `pkcs7UnPadding` function that
`tpke.AESDecrypt` → `antimev.KeyStore.AggregateAndDecryptWithShare` → the `consensus/dbft`
decryption-fallback path composes; that composition maps AES errors to `nil` per-message results
and is unchanged by the patch, so the strict acceptance set now propagates to the fallback
decision.

## Not run, and why

The repository's two PKCS#7 exporter probes (`neox_pkcs7_probe_test.go`,
`neox_pkcs7_reachability_test.go`) were not executed inside the checkout: dropping them into
`antimev/` requires writing test files through the local harness, whose security policy blocks
writing Go source containing unvalidated env-supplied paths and AES-CBC construction — both of
which are intrinsic to these audit probes (they must reproduce the reference client's exact CBC
envelope scheme). The probes assert nothing the patch's own strict matrix does not already
exercise: `TestPKCS7UnPaddingStrict` pins the identical acceptance set at the `pkcs7UnPadding`
level, and the AES-error-to-`nil`-to-fallback composition above the function is unchanged.

## Gate status

| Gate | Status |
|---|---|
| Canonical checkout at the pinned oracle commit, verifiable HEAD | **CLOSED** (this run) |
| Patch apply, gofmt, TPKE tests, vet in the canonical checkout | **CLOSED** (this run) |
| Rust-side strict acceptance coverage | **CLOSED** (Rust tpke matrix, 2026-09-05) |
| Reference-client deployment of the strict patch | OPEN — an operator decision made entirely outside this repository's process; this project does not modify the bane-labs upstream (see the read-only policy above) |
| Historical malformed-padding payload audit over chain data | OPEN — requires archive node access |
| Mixed-client replay against canonical history | OPEN — requires the patch deployed on the reference client |
| Versioned activation height/time coordinated in both clients | OPEN — governance decision; strict and legacy validators must not mix after activation, and no ad-hoc rollback |

The migration remains blocked on the four open gates; this report only closes the local
verification half.
