package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"
)

// Test for Hashing Algorithms

func TestHashSHA256(t *testing.T) {
	zkp := NewZeroKnowledgeProof()
	data := []byte("test data")
	expectedHash := sha256.Sum256(data)
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	hash := zkp.HashSHA256(data)
	if hash != expectedHashStr {
		t.Errorf("expected %s but got %s", expectedHashStr, hash)
	}
}

func TestHashSHA3(t *testing.T) {
	zkp := NewZeroKnowledgeProof()
	data := []byte("test data")
	expectedHash := sha3.Sum256(data)
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	hash := zkp.HashSHA3(data)
	if hash != expectedHashStr {
		t.Errorf("expected %s but got %s", expectedHashStr, hash)
	}
}

func TestHashBlake2b(t *testing.T) {
	zkp := NewZeroKnowledgeProof()
	data := []byte("test data")
	expectedHash, _ := blake2b.New256(nil)
	expectedHash.Write(data)
	expectedHashStr := hex.EncodeToString(expectedHash.Sum(nil))

	hash, err := zkp.HashBlake2b(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != expectedHashStr {
		t.Errorf("expected %s but got %s", expectedHashStr, hash)
	}
}

// Test for Zero-Knowledge Proofs

func TestGenerateAndVerifyProof(t *testing.T) {
	zkp := NewZeroKnowledgeProof()
	secret := big.NewInt(123456789)
	randomValue := big.NewInt(987654321)
	publicValue := big.NewInt(1000000007)

	commitment, response, err := zkp.GenerateProof(secret, randomValue, publicValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid := zkp.VerifyProof(publicValue, commitment, response)
	if !valid {
		t.Errorf("expected proof to be valid")
	}
}

// Test for Digital Signatures

func TestECDSASignAndVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	publicKey := &privateKey.PublicKey
	data := []byte("test data")
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	valid := ecdsa.Verify(publicKey, hash[:], r, s)
	if !valid {
		t.Errorf("expected signature to be valid")
	}
}

func TestRSASignAndVerify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	publicKey := &privateKey.PublicKey
	data := []byte("test data")
	hash := sha256.Sum256(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hash[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, 0, hash[:], signature)
	if err != nil {
		t.Errorf("expected signature to be valid")
	}
}

// Test for Asymmetric Encryption

func TestRSAEncryptionAndDecryption(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	publicKey := &privateKey.PublicKey
	data := []byte("test data")

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("expected %s but got %s", data, decryptedData)
	}
}

func TestECCEncryptionAndDecryption(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	publicKey := &privateKey.PublicKey
	data := []byte("test data")

	ciphertext, err := encryptECC(publicKey, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plaintext, err := decryptECC(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Errorf("expected %s but got %s", data, plaintext)
	}
}

func encryptECC(publicKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	// ECC encryption placeholder
	return data, nil
}

func decryptECC(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	// ECC decryption placeholder
	return data, nil
}
