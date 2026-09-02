package antimev

// Probe for the PKCS#7 unpadding strictness of the reference client.
//
// `crypto/tpke.AESDecrypt` unwraps padding with `pkcs7UnPadding`, which only rejects a padding
// length larger than the buffer and never checks that the padding length is in `1..=16` nor that
// every padding byte repeats it. The Rust implementation rejects all three cases. This probe
// establishes the reference client's actual behaviour so the divergence can be recorded as an
// audit finding instead of an inference from reading code.
//
// Nothing here changes Geth behaviour; the probe only calls the existing decoder.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/crypto/tpke"
)

type probeVector struct {
	RecoveredKey string `json:"recovered_aes_key_g1_uncompressed"`
}

// loadRecoveredKey reads the AES key point captured by the vector exporter.
func loadRecoveredKey(t *testing.T) *bls12381.G1Affine {
	t.Helper()
	path := os.Getenv("NEOX_VECTOR_IN")
	if path == "" {
		t.Skip("NEOX_VECTOR_IN not set")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v probeVector
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	raw, err := hex.DecodeString(v.RecoveredKey)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	pg1 := new(bls12381.G1Affine)
	if _, err := pg1.SetBytes(raw); err != nil {
		t.Fatalf("decode g1 point: %v", err)
	}
	return pg1
}

// encryptBlocks CBC-encrypts an already-padded buffer with the reference client's key derivation.
func encryptBlocks(pg1 *bls12381.G1Affine, padded []byte) []byte {
	seed := pg1.RawBytes()
	hash := sha256.Sum256(seed[:96])
	block, err := aes.NewCipher(hash[:32])
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, hash[:16]).CryptBlocks(out, padded)
	return out
}

// TestReferenceClientPKCS7Strictness records how the reference client treats malformed padding.
//
// The test deliberately does NOT assert a pass/fail expectation: it prints the observed behaviour
// for each malformed case so the audit can cite it verbatim.
func TestReferenceClientPKCS7Strictness(t *testing.T) {
	pg1 := loadRecoveredKey(t)

	cases := []struct {
		name  string
		build func() []byte
		note  string
	}{
		{
			name: "valid_pkcs7",
			build: func() []byte {
				// 112 bytes of payload + 16 bytes of 0x10 is a canonical full-block pad.
				padded := make([]byte, 128)
				for i := 0; i < 112; i++ {
					padded[i] = 'a'
				}
				for i := 112; i < 128; i++ {
					padded[i] = 0x10
				}
				return padded
			},
			note: "control: canonical padding must succeed",
		},
		{
			name: "zero_padding_byte",
			build: func() []byte {
				padded := make([]byte, 128)
				for i := 0; i < 128; i++ {
					padded[i] = 'a'
				}
				padded[127] = 0x00
				return padded
			},
			note: "last byte 0x00: padding length 0 is outside 1..=16",
		},
		{
			name: "oversized_padding_byte",
			build: func() []byte {
				padded := make([]byte, 128)
				for i := 0; i < 128; i++ {
					padded[i] = 'a'
				}
				padded[127] = 0x14 // 20 > block size
				return padded
			},
			note: "last byte 0x14: padding length 20 exceeds the 16-byte block",
		},
		{
			name: "inconsistent_padding_bytes",
			build: func() []byte {
				padded := make([]byte, 128)
				for i := 0; i < 120; i++ {
					padded[i] = 'a'
				}
				// Declares 8 bytes of padding but the preceding 7 bytes are not 0x08.
				for i := 120; i < 128; i++ {
					padded[i] = byte(i)
				}
				padded[127] = 0x08
				return padded
			},
			note: "declares 8 pad bytes but bytes 1..7 differ from 0x08",
		},
	}

	results := make([]pkcs7Case, 0, len(cases))
	for _, tc := range cases {
		ct := encryptBlocks(pg1, tc.build())
		out, err := tpke.AESDecrypt(pg1, ct)
		accepted := err == nil
		if accepted {
			t.Logf("RESULT %-26s ACCEPTED  len=%d  (%s)", tc.name, len(out), tc.note)
		} else {
			t.Logf("RESULT %-26s REJECTED  err=%v  (%s)", tc.name, err, tc.note)
		}
		results = append(results, pkcs7Case{
			Name:            tc.name,
			Note:            tc.note,
			ReferenceAccept: accepted,
			ReferenceLen:    len(out),
			Ciphertext:      hex.EncodeToString(ct),
		})
	}

	if out := os.Getenv("NEOX_PKCS7_OUT"); out != "" {
		blob, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(out, append(blob, '\n'), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %s", out)
	}
}

type pkcs7Case struct {
	Name            string `json:"name"`
	Note            string `json:"note"`
	ReferenceAccept bool   `json:"reference_accept"`
	ReferenceLen    int    `json:"reference_output_len"`
	Ciphertext      string `json:"ciphertext"`
}
