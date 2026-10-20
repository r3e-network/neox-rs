# Neo X candidate security review — 2026-10-20

> **Agent-conducted review authorized as the release review.** On 2026-10-20 the user explicitly
> directed that no independent reviewer is required, that the agent performs the review, and that
> the agent proceeds with the stable release. This is a recorded user risk acceptance, not a
> third-party audit.

## Scope

Candidate `f361db8c7f` (validator code `ff78e47cc1` plus dependency security updates), release
binary `2.7.0-dev` for Linux/Windows x86_64.

## Dependency audit

`cargo audit` initially reported **9 vulnerabilities**:

- `quinn-proto 0.11.14` — remote memory exhaustion, zero-length STREAM panic, unbounded retired
  connection-ID queue, zero-length DATAGRAM bypass, ACK-frequency panic.
- `rustls 0.23.45` — TLS session-secret `Debug` exposure, ECH rejection data leak, key-share
  downgrade, Brotli certificate allocation.

Updated to `quinn-proto 0.11.18` and `rustls 0.23.46`. A second `cargo audit` reports **0
vulnerabilities**; the unmaintained-package warnings remain informational.

Evidence: `outputs/cargo-audit-20261020.json`, `outputs/cargo-audit-after-20261020.json`.

## Release-critical code review

Reviewed the recent validator diff:

- managed DKG share matching now uses round + aggregate global public key; the canonical head is
  diagnostic only. A head-only advance no longer rejects a valid share, while a different round or
  key still fails closed;
- the signer-installation digest covers round, membership, accepted PVSS shares/reshares, and epoch
  commitments with length-delimited encoding; a same-height share change still forces reinstall;
- DKG Submit failure restores `Ready` instead of stranding the task in `Submitting`; the canonical
  head-advance path returns to the outer event loop without aborting in-flight preparations;
- no new secret material is logged; error strings contain public round/head metadata only.

No new correctness or secret-disclosure defect was found in this review.

## Release decision

The user authorized the stable release under this agent-conducted review on 2026-10-20. The full
MainNet clean sync continues post-release as an operational validation; no independent third-party
review was performed.
