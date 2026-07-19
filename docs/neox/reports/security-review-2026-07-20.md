# Neo X security review — 2026-07-20

An adversarial, fresh-context review of the Neo X (`neox-rs`) consensus, cryptography, wire, key, and
execution surface. Five independent reviewers (dBFT consensus safety, cryptography, DoS / resource
exhaustion, key handling / crash-safe state, EVM / Policy / Governance) each read the actual source
for their dimension; every reported finding was then adversarially verified against the code by a
separate agent instructed to refute it. This is an internal review and does not replace an independent
third-party audit, which remains recommended before any validator/MainNet release claim.

## Confirmed findings (both fixed)

### 1. Pre-authorization CPU DoS via unauthenticated dBFT `RecoveryMessage` — HIGH

Any peer that negotiated the `dbft/0` capability — no validator credentials required — could send a
`Message` frame carrying a `RecoveryMessage` whose `pre_commits` packed on the order of 10^5 valid
compressed-G1 decryption shares (bounded only by the 4 MiB frame size; the attacker reuses one known
in-subgroup point so every share passes). Decoding ran a BLS12-381 `blst_p1_uncompress` +
`blst_p1_affine_in_g1` subgroup check on every share — multiple seconds of single-threaded work —
synchronously inside the connection's `poll_next`, pinning a tokio worker. Crucially the decode ran
**before** `validate_sender`, so an unauthenticated peer was never checked for validator-set
membership before paying the cost, and there was no rate limit. A few connections could stall all
workers and disrupt consensus participation.

**Fix.** The typed-payload decode is split out of `validate_message` into a separate
`validate_payload` step that runs only **after** `validate_sender` authorizes the message against the
active validator set. The header check (`verify_witness` + outer `consensus_data` + height) stays
cheap, so an unauthenticated peer is rejected by the sender check (one ecrecover comparison) before
any BLS work — mirroring Neo X Geth, which only decodes recovery payloads from accountable validators.
Regression test `dbft::tests::recovery_payload_is_not_decoded_before_sender_authorization`. A
compromised *validator* can still send a large frame, but that is a small, accountable set rather than
any peer; a total-share cap tied to the committee size is a reasonable future hardening.

### 2. Raw private-key file leaves key material in freed heap — LOW

`read_private_key` returns early for a raw 32-byte key file via `Vec::try_into`, which moves the bytes
into the returned array and drops the heap `Vec` **without** zeroizing it, leaving the raw ECDSA / DKG
private key in freed heap for the process lifetime. The sibling hex path already wipes its buffer
(`encoded.fill(0)`), and every other key path in the codebase zeroizes. Not self-exploitable (requires
a separate memory-disclosure primitive: core dump, swap, `/proc`, heap over-read), but it defeats the
module's own key-hygiene invariant.

**Fix.** The raw path now copies into a fixed array and wipes the source buffer before returning,
matching the hex path.

## Dimensions with no confirmed defect

The dBFT consensus-safety, cryptography (BLS threshold / TPKE / DKG / ECDSA seal), and
EVM / Policy / Governance reviewers surfaced no finding that survived adversarial verification. Notable
checks that held: quorum arithmetic and witness verification before state mutation; subgroup validation
on deserialized G1/G2 points; the ECDSA parent-reseal path; Governance `currentConsensus` storage-slot
derivation for the runtime validator set; and Policy-aware pool enforcement. This is consistent with
the earlier internal audit (NX-1…NX-8) and the live-block consensus and codec-fuzz coverage.

## Scope note

The review covered the Neo X code under `crates/neox/*` and `bin/neox-rs`, not vanilla Reth internals
except where Neo X calls into them. An independent third-party security audit is still recommended
before validator mode leaves pre-release.
