#!/usr/bin/env python3
"""Generate the consensus/dbft Envelope-decoding test from the exported admission vector.

The constants are transcribed from JSON rather than typed by hand so the reference-client test and
the Rust test can never drift apart.
"""

from __future__ import annotations

import json
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "geth-ciphertext-admission.json"
OUTPUT = Path(r"D:\Git\neox-oracle-geth\consensus\dbft\neox_admission_decode_test.go")

BODY = '''
// TestEnvelopeDecodeAcceptsUnverifiedCiphertext drives the exact parse the reference client runs
// on every transaction in a proposed block (`PreBlock.SetTransactions` -> `decodeEnvelopeData`) and
// shows that it admits an Envelope whose TPKE ciphertext has a broken pairing relation.
//
// `decodeEnvelopeData` validates the prefix, the length and the nonzero DKG round, then calls
// `CipherText.FromBytes`, which only deserializes the three curve points. It never calls
// `CipherText.Verify`, and neither does any other non-test call site in the tree. Reth calls
// `TpkeCiphertext::verify()` at mempool admission and at proposal discovery, so the two clients
// disagree about whether this Envelope exists at all.
//
// The two Envelopes below differ only in the `R` slot of the ciphertext.
func TestEnvelopeDecodeAcceptsUnverifiedCiphertext(t *testing.T) {
    valid, err := hex.DecodeString(admissionEnvelopeDataValid)
    require.NoError(t, err)
    invalid, err := hex.DecodeString(admissionEnvelopeDataInvalid)
    require.NoError(t, err)
    require.Len(t, valid, $valid_len)
    require.Len(t, invalid, $invalid_len)

    parsedValid, err := decodeEnvelopeData(valid)
    require.NoError(t, err, "a well-formed Envelope must parse")
    require.Equal(t, uint32($dkg_round), parsedValid.dkgRound)

    // The assertion that matters: parsing succeeds even though the pairing relation is broken.
    parsedInvalid, err := decodeEnvelopeData(invalid)
    require.NoError(t, err,
        "the reference client must parse an Envelope with a broken TPKE pairing relation")
    require.Equal(t, uint32($dkg_round), parsedInvalid.dkgRound)

    // Only the ciphertext differs, so nothing else can explain the divergence below.
    require.Equal(t, parsedValid.prefix, parsedInvalid.prefix)
    require.Equal(t, parsedValid.encryptedMsg, parsedInvalid.encryptedMsg)
    require.NotEqual(t, parsedValid.encryptedKey.ToBytes(), parsedInvalid.encryptedKey.ToBytes())

    require.NoError(t, parsedValid.encryptedKey.Verify(), "the untampered ciphertext must verify")
    require.ErrorIs(t, parsedInvalid.encryptedKey.Verify(), tpke.ErrTPKECiphertext,
        "the tampered ciphertext is exactly what Reth rejects at proposal discovery")

    t.Logf("ADMISSION DECODE: decodeEnvelopeData accepted both Envelopes; " +
        "Verify rejects only the tampered one, which Reth enforces and Geth never checks")
}

// TestEnvelopeRoundFilterAdmitsEveryEarlierRound drives `PreBlock.SetTransactions`, the filter that
// decides which Envelopes take part in decryption at all.
//
// `preblock.go` declines an Envelope when
//
//	d.dkgRound < min(1, b.dkgRound-1) || b.dkgRound < d.dkgRound
//
// Both operands are `uint32`, so `b.dkgRound-1` wraps at zero, and the builtin `min` - not `max` -
// makes the lower bound 1 for every active round above one. The adjacent comment says
// "current/previous", but the predicate admits Envelopes from *any* earlier round. `SetData` then
// files every non-current one under the previous-round bucket, and because
// `thresholdKeyGroup.aggregateAndDecrypt` verifies a whole batch in a single pairing check, one
// undecryptable stale Envelope defeats every other Envelope in that bucket.
//
// Reth reproduces the same filter: `AntiMevProposal::from_transactions` keeps every round in
// `1..=current_round` and labels anything else `EnvelopeDkgEpoch::Previous`. The Rust test
// `envelope_round_filter_matches_the_reference_client_bound_for_bound` pins the same table from the
// other side, so a fix to either client fails a test instead of desynchronising a network.
func TestEnvelopeRoundFilterAdmitsEveryEarlierRound(t *testing.T) {
	const maxRound = 12
	for active := uint32(0); active <= maxRound; active++ {
		txx := make([]dbft.Transaction[common.Hash], 0, maxRound)
		for round := uint32(1); round <= maxRound; round++ {
			txx = append(txx, &Transaction{Tx: newAdmissionEnvelopeForRound(round)})
		}
		pre := &PreBlock{dkgRound: active}
		pre.SetTransactions(txx)

		admitted := make([]uint32, 0, len(pre.envelopesData))
		for _, d := range pre.envelopesData {
			admitted = append(admitted, d.dkgRound)
		}
		require.Equal(t, gethAdmittedRounds(active), admitted, "active DKG round %d", active)
	}

	// The filter is genuinely wider than "current or immediately previous": at round five an
	// Envelope from round one is admitted and filed under the previous-round key group.
	pre := &PreBlock{dkgRound: 5}
	pre.SetTransactions([]dbft.Transaction[common.Hash]{
		&Transaction{Tx: newAdmissionEnvelopeForRound(1)},
		&Transaction{Tx: newAdmissionEnvelopeForRound(4)},
	})
	require.Len(t, pre.envelopesData, 2, "rounds one and four must both be admitted at round five")
	require.Equal(t, uint32(1), pre.envelopesData[0].dkgRound)
	require.Equal(t, uint32(4), pre.envelopesData[1].dkgRound)

	t.Logf("ADMISSION ROUNDS: at active round 5 the filter admits Envelopes from rounds 1..5, " +
		"not just 4 and 5; all but round 5 are decrypted with the reshared key as one batch")
}

// gethAdmittedRounds restates `preblock.go`'s predicate, including `uint32` wraparound, so the test
// compares the real filter against an independently written expectation rather than a restatement
// of whatever the filter happens to do today.
func gethAdmittedRounds(active uint32) []uint32 {
	lower := uint32(1)
	if wrapped := active - 1; wrapped < lower { // underflows to 2^32-1 when active is zero
		lower = wrapped
	}
	out := make([]uint32, 0, 12)
	for round := uint32(1); round <= 12; round++ {
		if round < lower || active < round {
			continue
		}
		out = append(out, round)
	}
	return out
}

// newAdmissionEnvelopeForRound returns an Envelope transaction declaring `round`, built from the
// exported calldata so the ciphertext stays well-formed and only the round field varies.
func newAdmissionEnvelopeForRound(round uint32) *types.Transaction {
	data, err := hex.DecodeString(admissionEnvelopeDataValid)
	if err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(data[len(antimev.EncryptedDataPrefix):], round)
	to := systemcontracts.GovernanceRewardProxyHash
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(12227332), // Neo X testnet; arbitrary for a filter-only proof
		Nonce:     0,
		GasTipCap: big.NewInt(params.GWei),
		GasFeeCap: big.NewInt(3 * params.GWei),
		Gas:       1_000_000,
		To:        &to,
		Value:     big.NewInt(0),
		Data:      data,
	})
}

// TestEnvelopeDecodeRejectsRoundZero pins the one round check `decodeEnvelopeData` does perform,
// so the proof above cannot be dismissed as "the parser accepts everything".
func TestEnvelopeDecodeRejectsRoundZero(t *testing.T) {
    data, err := hex.DecodeString(admissionEnvelopeDataInvalid)
    require.NoError(t, err)

    // The round occupies the 4 bytes right after the 4-byte prefix.
    copy(data[len(antimev.EncryptedDataPrefix):len(antimev.EncryptedDataPrefix)+4], []byte{0, 0, 0, 0})

    _, err = decodeEnvelopeData(data)
    require.Error(t, err, "DKG round zero must be rejected")
}
'''


def main() -> None:
    vector = json.loads(VECTORS.read_text())

    # Template (not str.format) because the Go body is full of literal braces.
    body = Template(BODY).substitute(
        valid_len=len(vector["envelope_data_valid"]) // 2,
        invalid_len=len(vector["envelope_data_invalid"]) // 2,
        dkg_round=vector["dkg_round"],
    )

    source = f'''package dbft

// Code generated from docs/neox/vectors/geth-ciphertext-admission.json by
// gen_admission_decode_test.py. Do not edit by hand.

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/antimev"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/tpke"
	"github.com/ethereum/go-ethereum/params"
	"github.com/nspcc-dev/dbft"
	"github.com/stretchr/testify/require"
)

// Envelope calldata exported by antimev.TestCiphertextAdmission. Both carry the same inner
// transaction, the same DKG round and the same AES payload; only the ciphertext differs.
const (
	admissionEnvelopeDataValid   = "{vector["envelope_data_valid"]}"
	admissionEnvelopeDataInvalid = "{vector["envelope_data_invalid"]}"
)
{body}'''

    OUTPUT.write_text(source, encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(source)} bytes)")


if __name__ == "__main__":
    main()
