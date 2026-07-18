// neox-dkg-prover prepares the exact ECIES messages and committed Groth16 proof accepted by the
// deployed Neo X KeyManagement contract. Secret shares are accepted only over stdin and are never
// written to logs or files.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	zkdkg "github.com/bane-labs/zk-dkg"
	"github.com/bane-labs/zk-dkg/circuit"
	"github.com/bane-labs/zk-dkg/helper"
	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

const (
	protocolVersion = 1
	maxRequestBytes = 64 << 10
	messageLength   = 64 + 12 + 32 + 16
)

type request struct {
	ProtocolVersion  int      `json:"protocol_version"`
	ZKVersion        uint64   `json:"zk_version"`
	Sender           string   `json:"sender"`
	PublicKeys       []string `json:"public_keys"`
	Shares           []string `json:"shares"`
	R1CSPath         string   `json:"r1cs_path,omitempty"`
	R1CSSHA256       string   `json:"r1cs_sha256,omitempty"`
	ProvingKeyPath   string   `json:"proving_key_path,omitempty"`
	ProvingKeySHA256 string   `json:"proving_key_sha256,omitempty"`
}

type response struct {
	ProtocolVersion int         `json:"protocol_version"`
	Messages        []string    `json:"messages"`
	Proof           *proofInput `json:"proof,omitempty"`
}

type proofInput struct {
	Proof         [8]string `json:"proof"`
	Commitments   [2]string `json:"commitments"`
	CommitmentPOK [2]string `json:"commitment_pok"`
}

type preparedInput struct {
	sender        [20]byte
	publicKeys    []*ecies.PublicKey
	shares        []*fr.Element
	r1csPath      string
	r1csSHA256    [32]byte
	provingPath   string
	provingSHA256 [32]byte
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	req, err := decodeRequest(input)
	if err != nil {
		return err
	}
	prepared, err := validateRequest(req)
	if err != nil {
		return err
	}

	fisInts, nonces, encryptedFis, rs, err := circuit.PrepareEncryptedKeyShares(
		prepared.publicKeys,
		prepared.shares,
	)
	if err != nil {
		return fmt.Errorf("prepare encrypted key shares: %w", err)
	}
	messages, err := encodeMessages(encryptedFis, rs, nonces)
	if err != nil {
		return err
	}

	result := response{ProtocolVersion: protocolVersion, Messages: messages}
	if req.ZKVersion == 1 {
		r1cs, err := readR1CS(prepared.r1csPath, prepared.r1csSHA256)
		if err != nil {
			return err
		}
		provingKey, err := readProvingKey(prepared.provingPath, prepared.provingSHA256)
		if err != nil {
			return err
		}
		proof, _, err := zkdkg.ProveMultipleKeyShareEncryption(
			r1cs,
			provingKey,
			prepared.sender,
			prepared.publicKeys,
			rs,
			fisInts,
			encryptedFis,
			nonces,
		)
		if err != nil {
			return fmt.Errorf("generate DKG proof: %w", err)
		}
		result.Proof, err = contractProof(proof)
		if err != nil {
			return err
		}
	}

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return nil
}

func decodeRequest(input io.Reader) (request, error) {
	limited := &io.LimitedReader{R: input, N: maxRequestBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return request{}, fmt.Errorf("read request: %w", err)
	}
	if len(data) > maxRequestBytes {
		return request{}, errors.New("request exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		return request{}, fmt.Errorf("decode request: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return request{}, err
	}
	return req, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("request contains multiple JSON values")
	}
	return fmt.Errorf("decode trailing request data: %w", err)
}

func validateRequest(req request) (preparedInput, error) {
	if req.ProtocolVersion != protocolVersion {
		return preparedInput{}, fmt.Errorf("unsupported protocol version %d", req.ProtocolVersion)
	}
	if req.ZKVersion > 1 {
		return preparedInput{}, fmt.Errorf("unsupported ZK version %d", req.ZKVersion)
	}
	if len(req.PublicKeys) != len(req.Shares) {
		return preparedInput{}, errors.New("public key and share counts differ")
	}
	if count := len(req.Shares); count != 1 && count != 2 && count != 7 {
		return preparedInput{}, fmt.Errorf("unsupported message count %d", count)
	}

	var result preparedInput
	sender, err := decodeFixedHex("sender", req.Sender, len(result.sender))
	if err != nil {
		return preparedInput{}, err
	}
	copy(result.sender[:], sender)

	result.publicKeys = make([]*ecies.PublicKey, len(req.PublicKeys))
	result.shares = make([]*fr.Element, len(req.Shares))
	for i := range req.PublicKeys {
		encoded, err := decodeFixedHex(fmt.Sprintf("public key %d", i), req.PublicKeys[i], 65)
		if err != nil {
			return preparedInput{}, err
		}
		if encoded[0] != 4 {
			return preparedInput{}, fmt.Errorf("public key %d is not uncompressed", i)
		}
		publicKey, err := crypto.UnmarshalPubkey(encoded)
		if err != nil {
			return preparedInput{}, fmt.Errorf("invalid public key %d", i)
		}
		result.publicKeys[i] = ecies.ImportECDSAPublic(publicKey)

		shareBytes, err := decodeFixedHex(fmt.Sprintf("share %d", i), req.Shares[i], fr.Bytes)
		if err != nil {
			return preparedInput{}, err
		}
		share := new(big.Int).SetBytes(shareBytes)
		if share.Sign() == 0 || share.Cmp(ecc.BLS12_381.ScalarField()) >= 0 {
			return preparedInput{}, fmt.Errorf("share %d is not a canonical nonzero BLS12-381 scalar", i)
		}
		result.shares[i] = new(fr.Element).SetBigInt(share)
	}

	if req.ZKVersion == 0 {
		if req.R1CSPath != "" || req.R1CSSHA256 != "" || req.ProvingKeyPath != "" || req.ProvingKeySHA256 != "" {
			return preparedInput{}, errors.New("ZK-v0 request unexpectedly includes proof artifacts")
		}
		return result, nil
	}

	result.r1csPath, result.r1csSHA256, err = validateArtifact("R1CS", req.R1CSPath, req.R1CSSHA256)
	if err != nil {
		return preparedInput{}, err
	}
	result.provingPath, result.provingSHA256, err = validateArtifact(
		"proving key",
		req.ProvingKeyPath,
		req.ProvingKeySHA256,
	)
	if err != nil {
		return preparedInput{}, err
	}
	return result, nil
}

func validateArtifact(name, path, digest string) (string, [32]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", [32]byte{}, fmt.Errorf("%s path must be absolute", name)
	}
	decoded, err := decodeFixedHex(name+" SHA-256", digest, sha256.Size)
	if err != nil {
		return "", [32]byte{}, err
	}
	var expected [32]byte
	copy(expected[:], decoded)
	return filepath.Clean(path), expected, nil
}

func decodeFixedHex(name, value string, length int) ([]byte, error) {
	value = strings.TrimPrefix(value, "0x")
	if len(value) != length*2 {
		return nil, fmt.Errorf("%s must be exactly %d bytes", name, length)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hexadecimal", name)
	}
	return decoded, nil
}

func encodeMessages(encryptedFis [][]byte, rs []*big.Int, nonces [][]byte) ([]string, error) {
	if len(encryptedFis) != len(rs) || len(rs) != len(nonces) {
		return nil, errors.New("encrypted DKG message arrays differ")
	}
	result := make([]string, len(encryptedFis))
	for i := range encryptedFis {
		if len(nonces[i]) != 12 || len(encryptedFis[i]) != 48 {
			return nil, fmt.Errorf("invalid encrypted DKG message %d shape", i)
		}
		bigR := new(secp256k1.G1Affine).ScalarMultiplicationBase(rs[i]).RawBytes()
		message := make([]byte, 0, messageLength)
		message = append(message, bigR[:]...)
		message = append(message, nonces[i]...)
		message = append(message, encryptedFis[i]...)
		result[i] = "0x" + hex.EncodeToString(message)
	}
	return result, nil
}

func readR1CS(path string, expected [32]byte) (constraint.ConstraintSystem, error) {
	file, hash, err := openHashedArtifact("R1CS", path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	r1cs := new(cs.R1CS)
	if _, err := r1cs.ReadFrom(io.TeeReader(file, hash)); err != nil {
		return nil, fmt.Errorf("read R1CS: %w", err)
	}
	if err := finishArtifactHash("R1CS", file, hash, expected); err != nil {
		return nil, err
	}
	return r1cs, nil
}

func readProvingKey(path string, expected [32]byte) (*groth16.ProvingKey, error) {
	file, hash, err := openHashedArtifact("proving key", path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	key := new(groth16.ProvingKey)
	if _, err := key.ReadFrom(io.TeeReader(file, hash)); err != nil {
		return nil, fmt.Errorf("read proving key: %w", err)
	}
	if err := finishArtifactHash("proving key", file, hash, expected); err != nil {
		return nil, err
	}
	return key, nil
}

func openHashedArtifact(name, path string) (*os.File, hashWriter, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", name, err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", name)
	}
	return file, sha256.New(), nil
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func finishArtifactHash(name string, file *os.File, hash hashWriter, expected [32]byte) error {
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash %s: %w", name, err)
	}
	if !bytes.Equal(hash.Sum(nil), expected[:]) {
		return fmt.Errorf("%s SHA-256 mismatch", name)
	}
	return nil
}

func contractProof(proof *groth16.Proof) (*proofInput, error) {
	proofData, commitments, commitmentPOK := helper.GetContractInput(proof)
	if len(commitments) != 2 {
		return nil, fmt.Errorf("unexpected Groth16 commitment coordinate count %d", len(commitments))
	}
	result := new(proofInput)
	for i := range result.Proof {
		result.Proof[i] = encodeU256(proofData[i])
	}
	for i := range result.Commitments {
		result.Commitments[i] = encodeU256(commitments[i])
		result.CommitmentPOK[i] = encodeU256(commitmentPOK[i])
	}
	return result, nil
}

func encodeU256(value *big.Int) string {
	return fmt.Sprintf("0x%064x", value)
}
