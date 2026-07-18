package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/bane-labs/zk-dkg/encryption"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestZKV0EncryptsOneMessageForEachShare(t *testing.T) {
	privateKeys := make([]*ecies.PrivateKey, 7)
	publicKeys := make([]string, len(privateKeys))
	shares := make([]string, len(privateKeys))
	for i := range privateKeys {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[i] = ecies.ImportECDSA(key)
		publicKeys[i] = "0x" + hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
		shares[i] = encodeU256(big.NewInt(int64(i + 1)))
	}
	req := request{
		ProtocolVersion: protocolVersion,
		ZKVersion:       0,
		Sender:          "0x1111111111111111111111111111111111111111",
		PublicKeys:      publicKeys,
		Shares:          shares,
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(bytes.NewReader(encoded), &output); err != nil {
		t.Fatal(err)
	}
	var result response
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Proof != nil {
		t.Fatal("ZK-v0 response unexpectedly included a proof")
	}
	if len(result.Messages) != len(shares) {
		t.Fatalf("got %d messages, want %d", len(result.Messages), len(shares))
	}
	for i, encodedMessage := range result.Messages {
		message, err := hex.DecodeString(strings.TrimPrefix(encodedMessage, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		if len(message) != messageLength {
			t.Fatalf("message %d has length %d", i, len(message))
		}
		bigR := new(secp256k1.G1Affine)
		if _, err := bigR.SetBytes(message[:64]); err != nil {
			t.Fatal(err)
		}
		plaintext, err := encryption.ECIESDecrypt(
			privateKeys[i],
			message[76:],
			message[64:76],
			bigR,
		)
		if err != nil {
			t.Fatal(err)
		}
		if got := new(big.Int).SetBytes(plaintext); got.Cmp(big.NewInt(int64(i+1))) != 0 {
			t.Fatalf("message %d decrypted to %s", i, got)
		}
	}
}

func TestRejectsUnknownOrTrailingRequestData(t *testing.T) {
	if _, err := decodeRequest(strings.NewReader(`{"protocol_version":1,"unknown":true}`)); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if _, err := decodeRequest(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestRejectsNonCanonicalSharesAndRelativeArtifacts(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	base := request{
		ProtocolVersion: protocolVersion,
		ZKVersion:       0,
		Sender:          "0x1111111111111111111111111111111111111111",
		PublicKeys:      []string{"0x" + hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))},
		Shares:          []string{encodeU256(big.NewInt(0))},
	}
	if _, err := validateRequest(base); err == nil {
		t.Fatal("zero scalar was accepted")
	}
	base.Shares[0] = encodeU256(big.NewInt(1))
	base.ZKVersion = 1
	base.R1CSPath = "batch_encryption_1.ccs"
	base.R1CSSHA256 = strings.Repeat("00", 32)
	base.ProvingKeyPath = "/tmp/batch_encryption_1.pk"
	base.ProvingKeySHA256 = strings.Repeat("00", 32)
	if _, err := validateRequest(base); err == nil || !strings.Contains(err.Error(), "R1CS path") {
		t.Fatalf("relative R1CS path error = %v", err)
	}
}
