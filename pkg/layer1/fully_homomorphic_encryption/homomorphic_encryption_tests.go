package fully_homomorphic_encryption

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// TestHomomorphicEncryption ensures that encryption and decryption are functioning correctly.
func TestHomomorphicEncryption(t *testing.T) {
	key := make([]byte, 32) // Use a 256-bit key for AES-256
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate key: %s", err)
	}

	encryptor, err := NewHomomorphicEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to initialize encryptor: %s", err)
	}

	// Test data
	originalData := []byte("The quick brown fox jumps over the lazy dog")

	// Encrypt data
	encryptedData, err := encryptor.Encrypt(originalData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %s", err)
	}

	// Decrypt data
	decryptedData, err := encryptor.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %s", err)
	}

	// Verify the original and decrypted data match
	if !bytes.Equal(originalData, decryptedData) {
		t.Fatalf("Original and decrypted data do not match. Got %s, want %s", decryptedData, originalData)
	}
}

// TestErrorHandling checks that proper errors are returned when expected.
func TestErrorHandling(t *testing.T) {
	key := make([]byte, 32) // Use a 256-bit key for AES-256
	encryptor, _ := NewHomomorphicEncryptor(key)

	// Test decryption of too short data
	_, err := encryptor.Decrypt([]byte{0x00, 0x01}) // Clearly an invalid encrypted block
	if err == nil {
		t.Errorf("Expected an error for short data, but got none")
	}
}

// TestComputations simulates and tests computations on encrypted data.
func TestComputations(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate key: %s", err)
	}

	encryptor, err := NewHomomorphicEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to initialize encryptor: %s", err)
	}

	// Encrypt some data
	data := []byte("Test data for computation")
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %s", err)
	}

	// Perform a simulated computation
	modifiedData, err := encryptor.SimulateComputation(encryptedData)
	if err != nil {
		t.Fatalf("Failed to perform computation: %s", err)
	}

	// Decrypt the modified data to ensure it's still valid
	_, err = encryptor.Decrypt(modifiedData)
	if err != nil {
		t.Fatalf("Failed to decrypt modified data: %s", err)
	}
}

// Additional tests to validate security aspects and performance benchmarks can be added here.
