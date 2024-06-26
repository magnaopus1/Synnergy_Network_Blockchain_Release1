package hash_based

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func generateTestData(n int) [][]byte {
	var data [][]byte
	for i := 0; i < n; i++ {
		hash := sha256.Sum256([]byte(string(i)))
		data = append(data, hash[:])
	}
	return data
}

func TestNewMerkleTree(t *testing.T) {
	data := generateTestData(8)
	tree, err := NewMerkleTree(data)
	if err != nil {
		t.Fatalf("Failed to create Merkle Tree: %v", err)
	}

	if tree.Root == nil {
		t.Fatalf("Merkle Tree root is nil")
	}
}

func TestMerkleSignatureScheme(t *testing.T) {
	secretKeys, err := generateSecretKeys(8)
	if err != nil {
		t.Fatalf("Failed to generate secret keys: %v", err)
	}

	mss, err := NewMerkleSignatureScheme(secretKeys)
	if err != nil {
		t.Fatalf("Failed to create Merkle Signature Scheme: %v", err)
	}

	if mss.GetPublicKey() == "" {
		t.Fatalf("Public key should not be empty")
	}

	message := []byte("test message")
	signature, proof, err := mss.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) == 0 || len(proof) == 0 {
		t.Fatalf("Signature or proof should not be empty")
	}

	valid := mss.Verify(message, signature, proof)
	if !valid {
		t.Fatalf("Failed to verify signature")
	}
}

func TestMerkleProofVerification(t *testing.T) {
	data := generateTestData(8)
	tree, err := NewMerkleTree(data)
	if err != nil {
		t.Fatalf("Failed to create Merkle Tree: %v", err)
	}

	leaf := data[0]
	proof, err := tree.generateProof(leaf)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	valid := tree.verifyProof(leaf, proof)
	if !valid {
		t.Fatalf("Proof verification failed")
	}

	invalidLeaf := []byte("invalid leaf")
	invalidProof := proof
	invalidValid := tree.verifyProof(invalidLeaf, invalidProof)
	if invalidValid {
		t.Fatalf("Invalid proof should not verify")
	}
}

func TestArgon2KeyGeneration(t *testing.T) {
	message := []byte("test message")
	secretKey, err := generateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	signature, err := argon2Key(message, secretKey)
	if err != nil {
		t.Fatalf("Failed to generate Argon2 key: %v", err)
	}

	if len(signature) == 0 {
		t.Fatalf("Generated signature should not be empty")
	}
}

func TestArgon2Hash(t *testing.T) {
	password := "password"
	salt, err := generateRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash, err := Argon2Hash(password, string(salt))
	if err != nil {
		t.Fatalf("Failed to generate Argon2 hash: %v", err)
	}

	if len(hash) == 0 {
		t.Fatalf("Generated hash should not be empty")
	}
}

func BenchmarkMerkleSignatureScheme_Sign(b *testing.B) {
	secretKeys, err := generateSecretKeys(8)
	if err != nil {
		b.Fatalf("Failed to generate secret keys: %v", err)
	}

	mss, err := NewMerkleSignatureScheme(secretKeys)
	if err != nil {
		b.Fatalf("Failed to create Merkle Signature Scheme: %v", err)
	}

	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := mss.Sign(message)
		if err != nil {
			b.Fatalf("Failed to sign message: %v", err)
		}
	}
}

func BenchmarkMerkleSignatureScheme_Verify(b *testing.B) {
	secretKeys, err := generateSecretKeys(8)
	if err != nil {
		b.Fatalf("Failed to generate secret keys: %v", err)
	}

	mss, err := NewMerkleSignatureScheme(secretKeys)
	if err != nil {
		b.Fatalf("Failed to create Merkle Signature Scheme: %v", err)
	}

	message := []byte("benchmark message")
	signature, proof, err := mss.Sign(message)
	if err != nil {
		b.Fatalf("Failed to sign message: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := mss.Verify(message, signature, proof)
		if !valid {
			b.Fatalf("Failed to verify signature")
		}
	}
}

func TestGenerateSecretKeys(t *testing.T) {
	keys, err := generateSecretKeys(8)
	if err != nil {
		t.Fatalf("Failed to generate secret keys: %v", err)
	}

	if len(keys) != 8 {
		t.Fatalf("Expected 8 keys, got %d", len(keys))
	}

	for _, key := range keys {
		if len(key) == 0 {
			t.Fatalf("Generated key should not be empty")
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	bytes, err := generateRandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	if len(bytes) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(bytes))
	}
}
