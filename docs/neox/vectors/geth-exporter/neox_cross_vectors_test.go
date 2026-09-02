package antimev

// Neo X / Reth cross-implementation vector exporter.
//
// This file is ADDED to the reference client (Neo X Geth) for audit purposes only. It does not
// modify any existing Geth source file, protocol logic, or consensus rule. It replays the
// deterministic 7-node / 5-threshold DKG setup already used by TestTPKE and dumps every value the
// Rust implementation needs to be checked against, in one machine-readable JSON document.
//
// Randomised parts of the scheme (the AES message key and the encryption nonce) are NOT treated as
// fixed vectors: the exporter records whatever the reference client produced in this run and also
// records the intermediate values, so the Rust side can be checked for *interoperability* (decode
// the same ciphertext, verify it, aggregate the same shares, recover the same AES key, decrypt to
// the same plaintext) rather than for byte equality with a hard-coded expectation.

import (
	"crypto/sha256"
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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/tpke"
	"github.com/stretchr/testify/require"
)

type vectorParticipant struct {
	Index           int    `json:"index"`
	Address         string `json:"address"`
	PrivateShare    string `json:"private_share"`
	PublicShare     string `json:"public_share"`
	DecryptionShare string `json:"decryption_share"`
}

type vectorLayout struct {
	EncryptedDataPrefix   string `json:"encrypted_data_prefix"`
	PrefixLen             int    `json:"prefix_len"`
	RoundLen              int    `json:"round_len"`
	GasLen                int    `json:"gas_len"`
	HashLen               int    `json:"hash_len"`
	CipherTextLen         int    `json:"ciphertext_len"`
	MinEncryptedDataSize  int    `json:"min_encrypted_data_size"`
	MinEncryptedGasLimit  uint32 `json:"min_encrypted_gas_limit"`
	EnvelopeTarget        string `json:"envelope_target"`
	DecryptionShareLen    int    `json:"decryption_share_len"`
	FPSize                int    `json:"fp_size"`
	AESKeyLen             int    `json:"aes_key_len"`
	AESIVLen              int    `json:"aes_iv_len"`
	AESBlockSize          int    `json:"aes_block_size"`
	G1UncompressedSeedLen int    `json:"g1_uncompressed_seed_len"`
}

type vectorFile struct {
	GeneratedBy   string              `json:"generated_by"`
	Purpose       string              `json:"purpose"`
	Deterministic bool                `json:"deterministic"`
	Participants  int                 `json:"participants"`
	Threshold     int                 `json:"threshold"`
	Scaler        int                 `json:"scaler"`
	Layout        vectorLayout        `json:"layout"`
	Constants     map[string]string   `json:"constants"`
	GlobalPubKey  string              `json:"global_public_key"`
	AggCommitment string              `json:"aggregated_commitment"`
	Ciphertext    string              `json:"ciphertext"`
	RecoveredKey  string              `json:"recovered_aes_key_g1_uncompressed"`
	AESSHA256     string              `json:"aes_seed_sha256"`
	Plaintext     string              `json:"plaintext"`
	EncryptedMsg  string              `json:"encrypted_msg"`
	Shares        []vectorParticipant `json:"shares"`
}

// TestExportCrossImplementationVectors dumps the reference client's TPKE state for the Rust
// implementation to be validated against. It only writes a file when NEOX_VECTOR_OUT is set, so it
// stays a no-op during ordinary `go test` runs.
func TestExportCrossImplementationVectors(t *testing.T) {
	out := os.Getenv("NEOX_VECTOR_OUT")
	if out == "" {
		t.Skip("NEOX_VECTOR_OUT not set; skipping vector export")
	}

	dir := t.TempDir()
	addrs := make([]common.Address, size)
	pubs := make([]*ecies.PublicKey, size)
	kss := make([]*KeyStore, size)
	for i := 0; i < size; i++ {
		addrs[i] = accounts[i].addr
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
	cmt := new(bls12381.G1Affine).ScalarMultiplicationBase(big.NewInt(0))
	for i := 0; i < size; i++ {
		p, err := new(tpke.PVSS).Decode(contract.sharePVSSes[i], size, threshold)
		require.NoError(t, err)
		pg1, err := decodePointG1(p.GetCommitment().Encode()[:128])
		require.NoError(t, err)
		cmt = new(bls12381.G1Affine).Add(cmt, pg1)
	}
	aggregated := encodePointG1(cmt)
	for i := 0; i < size; i++ {
		require.NoError(t, kss[i].OnEpochChange(contract.sharePVSSes[i], aggregated, nil, true))
	}

	// Encrypt; the AES key and the nonce are random per run, so these are recorded as observed
	// values rather than as fixed expectations.
	msg := []byte("some data that is more than 105 bytes in length: pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza pizza")
	encryptedKey, encryptedMsg, err := kss[0].Encrypt(msg)
	require.NoError(t, err)
	require.NoError(t, encryptedKey.Verify())

	// Every participant produces a decryption share for the same ciphertext.
	cts := []*tpke.CipherText{encryptedKey}
	shares := make(map[int][]*tpke.DecryptionShare)
	participants := make([]vectorParticipant, 0, size)
	globalPub, err := kss[0].GlobalPublicKey()
	require.NoError(t, err)

	for i := 0; i < size; i++ {
		share, err := kss[i].DecryptWithShare(cts)
		require.NoError(t, err)
		shares[i+1] = share
		participants = append(participants, vectorParticipant{
			Index:           i + 1,
			Address:         accounts[i].addr.Hex(),
			PrivateShare:    hex.EncodeToString(kss[i].shared.localPrvKey.Bytes()),
			PublicShare:     hex.EncodeToString(kss[i].shared.localPrvKey.GetPublicKey().Bytes()),
			DecryptionShare: hex.EncodeToString(share[0].ToBytes()),
		})
	}

	// Recover the AES key point exactly as the reference client does.
	keys, err := kss[0].shared.aggregateAndDecrypt(cts, shares, threshold, kss[0].scaler)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	seed := keys[0].RawBytes()

	digest := sha256.Sum256(seed[:96])
	decrypted, err := tpke.AESDecrypt(keys[0], encryptedMsg)
	require.NoError(t, err)
	require.Equal(t, msg, decrypted)

	_, _, g1Gen, g2Gen := bls12381.Generators()
	g1Compressed := g1Gen.Bytes()
	g2Compressed := g2Gen.Bytes()
	g1Raw := g1Gen.RawBytes()

	vf := vectorFile{
		GeneratedBy:   "Neo X Geth reference client (bane-labs/go-ethereum, branch bane-main)",
		Purpose:       "cross-implementation TPKE / Envelope vectors for reth-neox-antimev",
		Deterministic: false,
		Participants:  size,
		Threshold:     threshold,
		Scaler:        getScaler(size, threshold),
		Layout: vectorLayout{
			EncryptedDataPrefix:   hex.EncodeToString(EncryptedDataPrefix),
			PrefixLen:             EncryptedDataPrefixLen,
			RoundLen:              EncryptedDataRoundLen,
			GasLen:                EncryptedDataGasLen,
			HashLen:               EncryptedDataHashLen,
			CipherTextLen:         tpke.CipherTextSize,
			MinEncryptedDataSize:  minEncryptedDataSize,
			MinEncryptedGasLimit:  MinEncryptedGasLimit,
			EnvelopeTarget:        systemcontracts.GovernanceRewardProxyHash.Hex(),
			DecryptionShareLen:    tpke.DecryptionShareSize,
			FPSize:                tpke.FPSize,
			AESKeyLen:             32,
			AESIVLen:              16,
			AESBlockSize:          16,
			G1UncompressedSeedLen: 96,
		},
		Constants: map[string]string{
			"g1_generator_compressed":   hex.EncodeToString(g1Compressed[:]),
			"g2_generator_compressed":   hex.EncodeToString(g2Compressed[:]),
			"g1_generator_uncompressed": hex.EncodeToString(g1Raw[:]),
		},
		GlobalPubKey:  hex.EncodeToString(globalPub.Bytes()),
		AggCommitment: hex.EncodeToString(aggregated),
		Ciphertext:    hex.EncodeToString(encryptedKey.ToBytes()),
		RecoveredKey:  hex.EncodeToString(seed[:96]),
		AESSHA256:     hex.EncodeToString(digest[:]),
		Plaintext:     hex.EncodeToString(msg),
		EncryptedMsg:  hex.EncodeToString(encryptedMsg),
		Shares:        participants,
	}

	blob, err := json.MarshalIndent(vf, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(out), 0o755))
	require.NoError(t, os.WriteFile(out, append(blob, '\n'), 0o644))
	t.Logf("wrote %s (%d bytes)", out, len(blob))
}
