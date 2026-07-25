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

// The Rust node serializes these names from its own struct and this decoder rejects unknown
// fields, so a tag renamed on either side is a runtime-only failure during a live DKG round. Pin
// the names here against literal JSON; the counterpart pin is `pins_request_wire_format` in
// crates/neox/node/src/dkg_prover.rs.
func TestPinsRequestFieldNames(t *testing.T) {
	const literal = `{
		"protocol_version": 1,
		"zk_version": 1,
		"sender": "0xAbC1111111111111111111111111111111111111",
		"public_keys": ["0x04"],
		"shares": ["0x22"],
		"r1cs_path": "/artifacts/one.r1cs",
		"r1cs_sha256": "0x33",
		"proving_key_path": "/artifacts/one.pk",
		"proving_key_sha256": "0x44"
	}`
	req, err := decodeRequest(strings.NewReader(literal))
	if err != nil {
		t.Fatal(err)
	}
	if req.ProtocolVersion != protocolVersion || req.ZKVersion != 1 {
		t.Fatalf("version fields decoded as %d/%d", req.ProtocolVersion, req.ZKVersion)
	}
	// Mixed case survives decoding; decodeFixedHex trims 0x and hex.DecodeString is case-insensitive.
	if req.Sender != "0xAbC1111111111111111111111111111111111111" {
		t.Fatalf("sender decoded as %q", req.Sender)
	}
	if len(req.PublicKeys) != 1 || req.PublicKeys[0] != "0x04" {
		t.Fatalf("public_keys decoded as %v", req.PublicKeys)
	}
	if len(req.Shares) != 1 || req.Shares[0] != "0x22" {
		t.Fatalf("shares decoded as %v", req.Shares)
	}
	if req.R1CSPath != "/artifacts/one.r1cs" || req.R1CSSHA256 != "0x33" {
		t.Fatalf("R1CS fields decoded as %q/%q", req.R1CSPath, req.R1CSSHA256)
	}
	if req.ProvingKeyPath != "/artifacts/one.pk" || req.ProvingKeySHA256 != "0x44" {
		t.Fatalf("proving key fields decoded as %q/%q", req.ProvingKeyPath, req.ProvingKeySHA256)
	}
}

// A ZK-v0 request omits all four artifact fields, which must leave them empty rather than
// tripping the artifact guard in validateRequest.
func TestZKV0RequestOmitsArtifactFields(t *testing.T) {
	req, err := decodeRequest(strings.NewReader(
		`{"protocol_version":1,"zk_version":0,"sender":"0x11","public_keys":["0x04"],"shares":["0x22"]}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if req.R1CSPath != "" || req.R1CSSHA256 != "" || req.ProvingKeyPath != "" || req.ProvingKeySHA256 != "" {
		t.Fatal("omitted artifact fields did not decode as empty")
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
