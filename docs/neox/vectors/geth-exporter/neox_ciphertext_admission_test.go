package antimev

// Envelope admission proof for the TPKE ciphertext pairing check.
//
// Neo X Geth NEVER calls `tpke.CipherText.Verify()`. The method exists
// (`crypto/tpke/encryption.go:77`) but grepping `.Verify()` across antimev/, consensus/, core/ and
// crypto/tpke/ yields zero non-test call sites. Envelope admission therefore relies on:
//
//   * `antimev.IsEnvelope`   -> receiver address + `0xffffffff` prefix + minimum length
//   * `decodeEnvelopeData`   -> `CipherText.FromBytes`, which only deserializes the three curve
//                               points (implicitly checking they are on-curve and in-subgroup)
//   * `core/txpool/validation.go:227` -> gas limit, encrypted gas and fee only
//
// None of those establish that `R` and the G2 commitment encode the same scalar `r`, i.e. that
// `e(R, g2) * e(g1, commitment) == 1`. A ciphertext whose points are individually valid but whose
// pairing relation does not hold is admitted as an Envelope all the same.
//
// Reth instead calls `TpkeCiphertext::verify()` in two places:
//
//   * mempool admission  -> `NeoXPoolPolicyError::InvalidEnvelopeCiphertext` (permanent rejection)
//   * proposal discovery -> `AntiMevProposalError::InvalidCiphertext`, which `?`-propagates into
//                           `DbftProposalError::AntiMevProposal` and rejects the whole proposal
//
// This exporter pins the divergence from the reference-client side:
//
//   1. a tampered ciphertext deserializes fine and is classified as an Envelope by Geth
//   2. `Verify()` rejects it, which is exactly what Reth enforces
//   3. Geth's own aggregation path can never decrypt it, no matter how many PreCommits arrive,
//      because `check.go:79` merely returns and waits for more PreCommits on failure
//
// Consequence: a Geth primary admits the Envelope and then stalls on it (liveness), while a Reth
// primary never admits it into the mempool in the first place. This is a liveness divergence, NOT a
// state fork: `AggregateAndDecrypt` (encryption.go:202) verifies `e(PK, commitment)*e(rpk, g2)`,
// which holds iff `Verify()` holds, so there is no input that Geth decrypts and Reth rejects.
//
// Nothing here changes Geth behaviour; the test only drives the existing code paths.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/tpke"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

// admissionVector is everything the Rust side needs to reproduce the divergence.
type admissionVector struct {
	// The receiver every Envelope must target.
	EnvelopeTo string `json:"envelope_to"`
	// Minimum calldata length for the `0xffffffff` Envelope prefix.
	MinEncryptedDataSize int `json:"min_encrypted_data_size"`
	// DKG round declared by the Envelope; any nonzero value at or below the active round passes.
	DkgRound uint32 `json:"dkg_round"`
	// Full Envelope calldata carrying a well-formed ciphertext.
	EnvelopeDataValid string `json:"envelope_data_valid"`
	// Full Envelope calldata carrying a ciphertext with a broken pairing relation.
	EnvelopeDataInvalid string `json:"envelope_data_invalid"`
	// The 192-byte ciphertexts on their own, for direct `decode`/`verify` checks.
	CiphertextValid   string `json:"ciphertext_valid"`
	CiphertextInvalid string `json:"ciphertext_invalid"`
	// AES-CBC ciphertext of the inner transaction.
	EncryptedMessage string `json:"encrypted_message"`
	// The inner transaction the Envelope claims to carry.
	InnerTx     string `json:"inner_tx"`
	InnerTxHash string `json:"inner_tx_hash"`
	// Committee parameters, recorded for completeness.
	GlobalPublicKey string `json:"global_public_key"`
	Scaler          int    `json:"scaler"`
	Threshold       int    `json:"threshold"`
	Note            string `json:"note"`
}

// envelopeData assembles Envelope calldata in the layout `decodeEnvelopeData` expects:
//
//	prefix(4) || round(4) || gas(4) || hash(32) || ciphertext(192) || encrypted message(n)
func envelopeData(round uint32, gas uint32, hash common.Hash, ciphertext []byte, encryptedMsg []byte) []byte {
	data := make([]byte, 0, EncryptedDataPrefixLen+EncryptedDataRoundLen+EncryptedDataGasLen+EncryptedDataHashLen+len(ciphertext)+len(encryptedMsg))
	data = append(data, EncryptedDataPrefix...)
	roundBytes := make([]byte, EncryptedDataRoundLen)
	binary.BigEndian.PutUint32(roundBytes, round)
	data = append(data, roundBytes...)
	gasBytes := make([]byte, EncryptedDataGasLen)
	binary.BigEndian.PutUint32(gasBytes, gas)
	data = append(data, gasBytes...)
	data = append(data, hash.Bytes()...)
	data = append(data, ciphertext...)
	data = append(data, encryptedMsg...)
	return data
}

// tamperRandomCommitment returns a ciphertext whose three points are individually valid but whose
// pairing relation is broken, by adding the G1 generator to the `R` component.
//
// `Verify` checks `e(R, g2) * e(g1, commitment) == 1`. With `R' = R + G1` the product gains a
// factor of `e(G1, g2) != 1`, so the check fails while `FromBytes` still succeeds.
func tamperRandomCommitment(t *testing.T, ciphertext []byte) []byte {
	t.Helper()
	require.Len(t, ciphertext, tpke.CipherTextSize)

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)

	// `R` occupies the second G1 slot: [FPSize, 2*FPSize).
	bigR := new(bls12381.G1Affine)
	_, err := bigR.SetBytes(ciphertext[tpke.FPSize : 2*tpke.FPSize])
	require.NoError(t, err, "the untampered ciphertext must deserialize its R component")

	_, _, g1, _ := bls12381.Generators()
	tamperedR := new(bls12381.G1Affine).Add(bigR, &g1)
	encoded := tamperedR.Bytes()
	copy(tampered[tpke.FPSize:2*tpke.FPSize], encoded[:])

	return tampered
}

// TestCiphertextAdmission proves that the reference client admits an Envelope whose TPKE
// ciphertext has a broken pairing relation, and that it can then never decrypt that Envelope.
func TestCiphertextAdmission(t *testing.T) {
	out := os.Getenv("NEOX_ADMISSION_OUT")
	if out == "" {
		t.Skip("NEOX_ADMISSION_OUT not set; skipping ciphertext admission proof")
	}

	// ---- Standard 7-node / 5-threshold DKG, same fixture the other exporters use. ----
	dir := t.TempDir()
	pubs := make([]*ecies.PublicKey, size)
	kss := make([]*KeyStore, size)
	for i := 0; i < size; i++ {
		key, _ := crypto.HexToECDSA(accounts[i].msgPrivKey)
		pubs[i] = &ecies.ImportECDSA(key).PublicKey
		ks := NewKeyStore(filepath.Join(dir, "antimev-keystore"+fmt.Sprint(i)))
		require.NoError(t, ks.Init(accounts[i].addr, ecies.ImportECDSA(key), size, threshold, accounts[i].pwd))
		kss[i] = ks
	}
	contract := &MockContractStorage{
		shareMsgs:   make([][][]byte, size),
		sharePVSSes: make([][]byte, size),
	}
	for i := 0; i < size; i++ {
		kss[i].OnSharePeriodStart(false)
		ss, pvss, err := kss[i].DKGShare(big.NewInt(1))
		require.NoError(t, err)
		contract.shareMsgs[i], err = encryptShareMessages(pubs, ss)
		require.NoError(t, err)
		contract.sharePVSSes[i] = pvss
	}
	for i := 0; i < size; i++ {
		for j := 0; j < size; j++ {
			require.NoError(t, kss[i].ReceiveSecretShare(i+1, j+1, contract.shareMsgs[j], contract.sharePVSSes[j]))
		}
	}
	cmt := aggregateCommitments(t, contract.sharePVSSes)
	for i := 0; i < size; i++ {
		require.NoError(t, kss[i].OnEpochChange(contract.sharePVSSes[i], cmt, nil, true))
	}

	// ---- An ordinary inner transaction, so the Envelope is indistinguishable at a glance. ----
	senderKey, _ := crypto.HexToECDSA(accounts[0].msgPrivKey)
	chainID := big.NewInt(12227332) // Neo X testnet; arbitrary for an admission-only proof
	signer := types.LatestSignerForChainID(chainID)
	innerTx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(params.GWei),
		GasFeeCap: big.NewInt(3 * params.GWei),
		Gas:       params.TxGas,
		To:        &accounts[1].addr,
		Value:     big.NewInt(1),
	}), signer, senderKey)
	require.NoError(t, err)
	innerTxBytes, err := innerTx.MarshalBinary()
	require.NoError(t, err)

	// ---- Encrypt normally, then break the pairing relation. ----
	validCiphertext, encryptedMsg, err := kss[0].Encrypt(innerTxBytes)
	require.NoError(t, err)
	require.NoError(t, validCiphertext.Verify(), "the freshly produced ciphertext must verify")

	validBytes := validCiphertext.ToBytes()
	invalidBytes := tamperRandomCommitment(t, validBytes)

	invalidCiphertext := new(tpke.CipherText)
	decoded, err := invalidCiphertext.FromBytes(invalidBytes)
	require.NoError(t, err, "the tampered ciphertext must still deserialize: Geth never rejects it here")
	require.NotNil(t, decoded)
	require.ErrorIs(t, invalidCiphertext.Verify(), tpke.ErrTPKECiphertext,
		"the tampered ciphertext must fail the pairing check Reth enforces")

	// ---- Geth classifies both as Envelopes. `IsEnvelopeData` only sees prefix and length. ----
	const dkgRound = uint32(1)
	validData := envelopeData(dkgRound, uint32(innerTx.Gas()), innerTx.Hash(), validBytes, encryptedMsg)
	invalidData := envelopeData(dkgRound, uint32(innerTx.Gas()), innerTx.Hash(), invalidBytes, encryptedMsg)
	require.True(t, IsEnvelopeData(validData), "valid Envelope calldata must be recognized")
	require.True(t, IsEnvelopeData(invalidData),
		"the tampered Envelope must be recognized: admission never checks the pairing relation")

	// A full transaction satisfies `IsEnvelope` too, which is what `SetTransactions` tests first.
	newEnvelope := func(data []byte) *types.Transaction {
		to := systemcontracts.GovernanceRewardProxyHash
		return types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     0,
			GasTipCap: big.NewInt(params.GWei),
			GasFeeCap: big.NewInt(3 * params.GWei),
			Gas:       1_000_000,
			To:        &to,
			Value:     big.NewInt(0),
			Data:      data,
		})
	}
	require.True(t, IsEnvelope(newEnvelope(validData)), "the valid Envelope must be an Envelope")
	require.True(t, IsEnvelope(newEnvelope(invalidData)), "the tampered Envelope must be an Envelope")

	// ---- Geth can never decrypt it, so `check.go:79` waits forever. ----
	//
	// Every committee member contributes a share, so `aggregateAndDecrypt` tries all C(7,5)=21
	// quorum combinations. All of them fail, which is what makes this a liveness stall rather
	// than a transient "wait for more PreCommits".
	shares := make(map[int][]*tpke.DecryptionShare, size)
	for i := 0; i < size; i++ {
		share, err := kss[i].DecryptWithShare([]*tpke.CipherText{invalidCiphertext})
		require.NoError(t, err, "producing a share never validates the ciphertext")
		shares[i+1] = share
	}
	_, err = kss[0].AggregateAndDecryptWithShare(
		[]*tpke.CipherText{invalidCiphertext}, [][]byte{encryptedMsg}, shares)
	require.ErrorIs(t, err, ErrDecryptionFailed,
		"the tampered ciphertext must defeat every quorum, so more PreCommits cannot help")

	// The untampered ciphertext must succeed through the same path, so the failure above is
	// attributable to the pairing relation and to nothing else.
	goodShares := make(map[int][]*tpke.DecryptionShare, size)
	for i := 0; i < size; i++ {
		share, err := kss[i].DecryptWithShare([]*tpke.CipherText{validCiphertext})
		require.NoError(t, err)
		goodShares[i+1] = share
	}
	decrypted, err := kss[0].AggregateAndDecryptWithShare(
		[]*tpke.CipherText{validCiphertext}, [][]byte{encryptedMsg}, goodShares)
	require.NoError(t, err)
	require.Len(t, decrypted, 1)
	require.Equal(t, innerTxBytes, decrypted[0], "the untampered Envelope must decrypt correctly")

	globalPub, err := kss[0].GlobalPublicKey()
	require.NoError(t, err)

	t.Logf("ADMISSION: Geth accepts a ciphertext whose pairing relation is broken "+
		"(IsEnvelope=%v, FromBytes=ok, Verify=ErrTPKECiphertext)", IsEnvelope(newEnvelope(invalidData)))
	t.Logf("ADMISSION: aggregation fails with %v for all C(%d,%d) quorums -> dBFT waits forever",
		ErrDecryptionFailed, size, threshold)
	t.Logf("ADMISSION: Reth rejects the same Envelope at mempool admission and proposal discovery")

	if out != "" {
		blob, err := json.MarshalIndent(admissionVector{
			EnvelopeTo:           systemcontracts.GovernanceRewardProxyHash.Hex(),
			MinEncryptedDataSize: minEncryptedDataSize,
			DkgRound:             dkgRound,
			EnvelopeDataValid:    hex.EncodeToString(validData),
			EnvelopeDataInvalid:  hex.EncodeToString(invalidData),
			CiphertextValid:      hex.EncodeToString(validBytes),
			CiphertextInvalid:    hex.EncodeToString(invalidBytes),
			EncryptedMessage:     hex.EncodeToString(encryptedMsg),
			InnerTx:              hex.EncodeToString(innerTxBytes),
			InnerTxHash:          innerTx.Hash().Hex(),
			GlobalPublicKey:      hex.EncodeToString(globalPub.Bytes()),
			Scaler:               kss[0].scaler,
			Threshold:            threshold,
			Note: "Geth admits both Envelopes; only the second has a broken TPKE pairing relation. " +
				"Reth rejects the second at mempool admission and at proposal discovery. Geth can " +
				"never decrypt it, so dBFT stalls. Not a state fork: AggregateAndDecrypt's check " +
				"holds iff Verify holds.",
		}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(out, append(blob, '\n'), 0o644))
		t.Logf("wrote %s", out)
	}
}

// TestCiphertextAdmissionTamperSanity pins that the tamper is a pure G1 translation of R and
// leaves the other two components untouched, so the only thing that changes is the pairing relation.
func TestCiphertextAdmissionTamperSanity(t *testing.T) {
	// All three slots must be real curve points, otherwise `FromBytes` fails for an unrelated
	// reason and the test would no longer isolate the pairing relation.
	_, _, g1, g2 := bls12381.Generators()
	m := new(bls12381.G1Affine).ScalarMultiplication(&g1, big.NewInt(3))
	r := new(bls12381.G1Affine).ScalarMultiplication(&g1, big.NewInt(7))
	c := new(bls12381.G2Affine).ScalarMultiplication(&g2, big.NewInt(11))

	base := make([]byte, tpke.CipherTextSize)
	mb := m.Bytes()
	copy(base[:tpke.FPSize], mb[:])
	rb := r.Bytes()
	copy(base[tpke.FPSize:2*tpke.FPSize], rb[:])
	cb := c.Bytes()
	copy(base[2*tpke.FPSize:], cb[:])

	tampered := tamperRandomCommitment(t, base)

	// Only the R slot may differ.
	require.Equal(t, base[:tpke.FPSize], tampered[:tpke.FPSize], "the M slot must be untouched")
	require.Equal(t, base[2*tpke.FPSize:], tampered[2*tpke.FPSize:], "the G2 slot must be untouched")
	require.NotEqual(t, base[tpke.FPSize:2*tpke.FPSize], tampered[tpke.FPSize:2*tpke.FPSize],
		"the R slot must change")

	// The result is still a valid G1 point, so `FromBytes` accepts it.
	parsed := new(tpke.CipherText)
	_, err := parsed.FromBytes(tampered)
	require.NoError(t, err, "the tampered R must remain a valid, in-subgroup G1 point")
}
