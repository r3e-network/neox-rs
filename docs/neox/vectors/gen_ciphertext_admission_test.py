#!/usr/bin/env python3
"""Generate the Reth half of the Envelope ciphertext-admission divergence proof.

Produces:
  * crates/neox/antimev/tests/geth_ciphertext_admission.rs
  * a `pool_admission_rejects_the_envelope_the_reference_client_admits` test inside
    crates/neox/node/src/pool.rs

Constants come from the exported JSON so the reference-client test and the Reth tests cannot drift.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
VECTORS = HERE / "geth-ciphertext-admission.json"
ANTIMEV_TEST = REPO / "crates/neox/antimev/tests/geth_ciphertext_admission.rs"
POOL = REPO / "crates/neox/node/src/pool.rs"

ANTIMEV_BODY = '''
/// Decodes a vector field.
fn unhex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector field is valid hex")
}

/// Deserialization agrees with the reference client: this crate's [`TpkeCiphertext::decode`] and
/// Geth's `CipherText.FromBytes` both accept all three curve points, because both only check that
/// the points are on-curve and in-subgroup.
///
/// The divergence therefore cannot be a parsing difference. It is a *checking* difference.
#[test]
fn deserialization_agrees_with_the_reference_client() {
    assert!(
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_VALID)).is_ok(),
        "the untampered ciphertext must deserialize"
    );
    assert!(
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_INVALID)).is_ok(),
        "the tampered ciphertext must deserialize too, exactly as Geth's FromBytes accepts it"
    );
}

/// The divergence proper: Geth admits this ciphertext as an Envelope and this crate rejects it.
///
/// Geth never calls `CipherText.Verify`, so a ciphertext whose `R` does not match its G2 commitment
/// is classified as an Envelope by `IsEnvelope` and parsed by `decodeEnvelopeData`. This crate
/// calls [`TpkeCiphertext::verify`] at mempool admission and at proposal discovery, both of which
/// reject it.
#[test]
fn reth_rejects_the_ciphertext_the_reference_client_admits() {
    let valid = TpkeCiphertext::decode(&unhex(CIPHERTEXT_VALID)).expect("valid ciphertext decodes");
    assert_eq!(valid.verify(), Ok(()), "the untampered ciphertext must verify");

    let invalid =
        TpkeCiphertext::decode(&unhex(CIPHERTEXT_INVALID)).expect("tampered ciphertext decodes");
    assert_eq!(
        invalid.verify(),
        Err(TpkeError::InvalidCiphertextCommitment),
        "the tampered ciphertext must fail the pairing check Geth never runs"
    );
}

/// Full Envelope parsing agrees as well: only the pairing check differs.
///
/// Everything outside the ciphertext is byte-identical between the two Envelopes, so the pairing
/// relation is the sole thing separating them. This pins the divergence to one check instead of
/// leaving it ambiguous between "different parse rules" and "different checks".
#[test]
fn envelope_parsing_agrees_and_only_the_pairing_check_diverges() {
    // `EnvelopeData` borrows its input, so the decoded buffers need named bindings.
    let valid_bytes = unhex(ENVELOPE_DATA_VALID);
    let invalid_bytes = unhex(ENVELOPE_DATA_INVALID);
    let valid = EnvelopeData::decode(&valid_bytes).expect("valid Envelope parses");
    let invalid = EnvelopeData::decode(&invalid_bytes).expect("tampered Envelope parses");

    assert_eq!(valid.dkg_round, invalid.dkg_round);
    assert_eq!(valid.dkg_round, DKG_ROUND);
    assert_eq!(valid.encrypted_gas, invalid.encrypted_gas, "gas must be identical");
    assert_eq!(valid.encrypted_hash, invalid.encrypted_hash, "hash must be identical");
    assert_eq!(valid.encrypted_message, invalid.encrypted_message, "payload must be identical");
    assert_ne!(valid.encrypted_key, invalid.encrypted_key, "only the ciphertext may differ");

    assert_eq!(valid.encrypted_key.verify(), Ok(()));
    assert_eq!(
        invalid.encrypted_key.verify(),
        Err(TpkeError::InvalidCiphertextCommitment),
        "Geth parses this Envelope and this crate rejects it: the admission divergence"
    );
}
'''

POOL_TEST = '''
    /// Ciphertext whose three points are individually valid but whose pairing relation is broken.
    ///
    /// Exported by `antimev.TestCiphertextAdmission` in `bane-labs/go-ethereum`
    /// (branch `bane-main`, commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`). Geth's
    /// `CipherText.FromBytes` accepts it and `decodeEnvelopeData` classifies the Envelope as
    /// decryptable, but Geth never calls `CipherText.Verify` and so never notices.
    const ADMISSION_CIPHERTEXT_INVALID: [u8; TPKE_SERIALIZED_LEN] = hex!(
$ciphertext_hex
    );

    /// Mempool admission is where this crate diverges from the reference client.
    ///
    /// Geth's `core/txpool/validation.go` checks only the gas limit, the encrypted gas and the fee
    /// for an Envelope, so a ciphertext with a broken pairing relation enters a Geth mempool. This
    /// crate rejects it permanently. The consequence is liveness rather than a state fork: Geth's
    /// `AggregateAndDecrypt` verifies `e(PK, commitment) * e(rpk, g2)`, which holds exactly when
    /// `Verify` holds, so there is no input Geth decrypts and this crate rejects. A Geth primary
    /// admits the Envelope and then stalls on it, because `dbft.check.go` merely returns and waits
    /// for more PreCommits that can never help; a Reth primary never admits it.
    #[test]
    fn pool_admission_rejects_the_envelope_the_reference_client_admits() {
        let valid = envelope_input(&VALID_CIPHERTEXT);
        assert!(
            validate_envelope_ciphertext(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &valid)
                .is_ok(),
            "the untampered Envelope must be admitted"
        );

        let invalid = envelope_input(&ADMISSION_CIPHERTEXT_INVALID);
        let error =
            validate_envelope_ciphertext(TxType::Legacy as u8, Some(ENVELOPE_TARGET), &invalid)
                .unwrap_err();
        let InvalidPoolTransactionError::Other(error) = error else {
            panic!("TPKE relation failure must use the Neo X pool error")
        };
        let error =
            error.as_any().downcast_ref::<NeoXPoolPolicyError>().expect("Neo X pool error type");
        assert!(
            matches!(
                error,
                NeoXPoolPolicyError::InvalidEnvelopeCiphertext(
                    TpkeError::InvalidCiphertextCommitment
                )
            ),
            "unexpected pool error: {error:?}"
        );
        assert!(error.is_bad_transaction(), "the rejection must be permanent");
    }
'''


def rust_hex_literal(hex_string: str, indent: str = "        ") -> str:
    """Format hex as a Rust `hex!` literal body spanning one string literal.

    A trailing backslash inside a Rust string literal escapes the newline *and* the leading
    whitespace of the next line, so the chunks concatenate into a single literal. Only the first
    chunk opens the quote and only the last one closes it.
    """
    chunks = [hex_string[i : i + 64] for i in range(0, len(hex_string), 64)]
    # Only the first chunk opens the quote and only the last closes it; every line in between
    # ends with a backslash that escapes its own newline and the next line's indentation.
    lines = [f'{indent}"{chunks[0]}\\']
    lines += [f"{indent}{chunk}\\" for chunk in chunks[1:-1]]
    lines.append(f'{indent}{chunks[-1]}"')
    return "\n".join(lines)


def main() -> None:
    vector = json.loads(VECTORS.read_text())

    source = f'''//! Envelope ciphertext admission: this crate verifies a relation the reference client never checks.
//!
//! Neo X Geth defines `CipherText.Verify` in `crypto/tpke/encryption.go`, but no non-test call site
//! in the tree invokes it. Envelope admission instead rests on
//!
//! * `antimev.IsEnvelope` - receiver address, `0xffffffff` prefix, minimum length;
//! * `decodeEnvelopeData` - `CipherText.FromBytes`, which deserializes the three curve points and
//!   checks that they are on-curve and in-subgroup, but not that they agree on one scalar;
//! * `core/txpool/validation.go` - gas limit, encrypted gas and fee only.
//!
//! So a ciphertext whose `R` and G2 commitment encode *different* scalars is admitted as an
//! Envelope. This crate calls [`TpkeCiphertext::verify`] in two places and rejects it in both:
//!
//! * mempool admission, permanently - `NeoXPoolPolicyError::InvalidEnvelopeCiphertext`;
//! * proposal discovery - `AntiMevProposalError::InvalidCiphertext`, which `?`-propagates into
//!   `DbftProposalError::AntiMevProposal` and rejects the whole proposal.
//!
//! The vector here was produced by `antimev.TestCiphertextAdmission` in `bane-labs/go-ethereum`
//! (branch `bane-main`, commit `f0e236838bb334c7c0d29eeca33533ed0cfda254`). That test also shows
//! the reference client can never decrypt the Envelope: `aggregateAndDecrypt` tries all
//! `C(7,5) = 21` quorums and every one fails, so the additional PreCommits that `dbft.check.go`
//! waits for can never arrive in a useful form.
//!
//! This is a **liveness** divergence, not a state fork. `AggregateAndDecrypt` verifies
//! `e(PK, commitment) * e(rpk, g2)` while `Verify` checks `e(R, g2) * e(g1, commitment)`; for
//! honest shares the two hold under the same condition, so no input exists that Geth decrypts and
//! this crate rejects. Both clients fail - Geth by waiting, this crate by refusing to admit.
//!
//! Reference-client side of the same vector: `consensus/dbft.TestEnvelopeDecodeAcceptsUnverifiedCiphertext`
//! proves `decodeEnvelopeData` parses both Envelopes, and `antimev.TestCiphertextAdmission` proves
//! `IsEnvelope` accepts both and that aggregation fails for every quorum.

use alloy_primitives::hex;
use reth_neox_antimev::{{EnvelopeData, TpkeCiphertext, TpkeError}};

/// Envelope calldata carrying a well-formed ciphertext, for contrast.
const ENVELOPE_DATA_VALID: &str = "{vector["envelope_data_valid"]}";

/// Envelope calldata whose ciphertext has a broken pairing relation.
const ENVELOPE_DATA_INVALID: &str = "{vector["envelope_data_invalid"]}";

/// The untampered ciphertext, `M || R || commitment`.
const CIPHERTEXT_VALID: &str = "{vector["ciphertext_valid"]}";

/// The tampered ciphertext: `R` was replaced by `R + G1`, so `e(R, g2) * e(g1, commitment) != 1`.
const CIPHERTEXT_INVALID: &str = "{vector["ciphertext_invalid"]}";

/// DKG round both Envelopes declare.
const DKG_ROUND: u32 = {vector["dkg_round"]};
{Template(ANTIMEV_BODY).substitute()}'''

    ANTIMEV_TEST.write_text(source, encoding="utf-8")
    print(f"wrote {ANTIMEV_TEST} ({len(source)} bytes)")

    # ---- Inject the mempool test into pool.rs, replacing any previous copy of it. ----
    pool = POOL.read_text(encoding="utf-8")
    block = Template(POOL_TEST).substitute(
        ciphertext_hex=rust_hex_literal(vector["ciphertext_invalid"])
    )

    marker = "    fn pool_admission_rejects_the_envelope_the_reference_client_admits() {"
    if marker in pool:
        # Replace the previously generated block: back up to the preceding `    /// Ciphertext whose`
        start = pool.index("    /// Ciphertext whose three points are individually valid")
        end = pool.index(marker)
        # Walk to the end of that function.
        end = pool.index("\n    }\n", end) + len("\n    }\n")
        pool = pool[:start] + block.strip("\n") + "\n" + pool[end:]
        action = "replaced"
    else:
        anchor = "    #[test]\n    fn pool_admission_rejects_only_decoded_envelopes_with_mismatched_tpke_relation() {"
        if anchor not in pool:
            raise SystemExit("pool.rs: anchor test not found")
        # Insert before the existing admission test.
        index = pool.index(anchor)
        pool = pool[:index] + block.lstrip("\n") + "\n" + pool[index:]
        action = "inserted"

    POOL.write_text(pool, encoding="utf-8")
    print(f"{action} mempool admission test in {POOL}")

    # Sanity: the injected constant must be a well-formed 192-byte literal.
    literal = re.search(r"ADMISSION_CIPHERTEXT_INVALID: \[u8; TPKE_SERIALIZED_LEN\] = hex!\((.*?)\);", pool, re.S)
    assert literal, "injected constant not found"
    decoded = "".join(re.findall(r"[0-9a-f]{64}", literal.group(1)))
    assert decoded == vector["ciphertext_invalid"], "injected ciphertext does not match the vector"
    assert len(decoded) == 384, f"expected 384 hex chars, got {len(decoded)}"
    print("verified injected constant matches the exported vector")


if __name__ == "__main__":
    main()
