package quantum_interoperability

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// Utility function to generate random data for tests
func generateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

// Test for KeyManager to ensure quantum keys can be added and retrieved
func TestKeyManager_AddAndGetQuantumKey(t *testing.T) {
	km := NewKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	err := km.AddQuantumKey(chainID, password, true)
	if err != nil {
		t.Fatalf("Failed to add quantum key: %v", err)
	}

	key, err := km.GetQuantumKey(chainID)
	if err != nil {
		t.Fatalf("Failed to get quantum key: %v", err)
	}

	if len(key) != Argon2KeyLen {
		t.Fatalf("Expected key length %d, got %d", Argon2KeyLen, len(key))
	}
}

// Test for KeyManager to ensure classical keys can be added and retrieved
func TestKeyManager_AddAndGetClassicalKey(t *testing.T) {
	km := NewKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	err := km.AddClassicalKey(chainID, password, true)
	if err != nil {
		t.Fatalf("Failed to add classical key: %v", err)
	}

	key, err := km.GetClassicalKey(chainID)
	if err != nil {
		t.Fatalf("Failed to get classical key: %v", err)
	}

	if len(key) != Argon2KeyLen {
		t.Fatalf("Expected key length %d, got %d", Argon2KeyLen, len(key))
	}
}

// Test for SecureCrossChainTransaction creation and validation
func TestSecureCrossChainTransaction(t *testing.T) {
	source := "chainA"
	destination := "chainB"
	data, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	tx, err := NewSecureCrossChainTransaction(source, destination, data)
	if err != nil {
		t.Fatalf("Failed to create transaction: %v", err)
	}

	if !tx.ValidateSignature() {
		t.Fatalf("Failed to validate transaction signature")
	}

	tx.PrintDetails()
}

// Test for CrossChainValidator to validate transactions
func TestCrossChainValidator_ValidateTransaction(t *testing.T) {
	km := NewKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	err := km.AddQuantumKey(chainID, password, true)
	if err != nil {
		t.Fatalf("Failed to add quantum key: %v", err)
	}

	data, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	validator := NewCrossChainValidator(km)
	key, _ := km.GetQuantumKey(chainID)
	signature := generateSignatureWithKey(data, key)

	isValid, err := validator.ValidateTransaction(chainID, data)
	if err != nil {
		t.Fatalf("Failed to validate transaction: %v", err)
	}
	if !isValid {
		t.Fatalf("Transaction validation failed")
	}

	// Test with invalid data
	invalidData, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	isValid, _ = validator.ValidateTransaction(chainID, invalidData)
	if isValid {
		t.Fatalf("Invalid transaction validation passed")
	}
}

// Test for Argon2 key generation
func TestGenerateArgon2Key(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate random salt: %v", err)
	}

	key := GenerateArgon2Key(password, salt)
	if len(key) != Argon2KeyLen {
		t.Fatalf("Expected Argon2 key length %d, got %d", Argon2KeyLen, len(key))
	}
}

// Test for Scrypt key generation
func TestGenerateScryptKey(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate random salt: %v", err)
	}

	key, err := GenerateScryptKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to generate Scrypt key: %v", err)
	}
	if len(key) != ScryptKeyLen {
		t.Fatalf("Expected Scrypt key length %d, got %d", ScryptKeyLen, len(key))
	}
}

// Test for transaction ID generation
func TestGenerateTransactionID(t *testing.T) {
	txID, err := generateTransactionID()
	if err != nil {
		t.Fatalf("Failed to generate transaction ID: %v", err)
	}

	if len(txID) != 32 {
		t.Fatalf("Expected transaction ID length 32, got %d", len(txID))
	}
}

// Test for signature generation
func TestGenerateSignature(t *testing.T) {
	data, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	signature := generateSignature(data)
	if len(signature) != 32 {
		t.Fatalf("Expected signature length 32, got %d", len(signature))
	}
}

// Test for signature generation with key
func TestGenerateSignatureWithKey(t *testing.T) {
	data, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	key, err := generateRandomData(32)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	signature := generateSignatureWithKey(data, key)
	if len(signature) != 32 {
		t.Fatalf("Expected signature length 32, got %d", len(signature))
	}
}

// Helper function to compare slices for equality
func compareSlices(a, b []byte) bool {
	return bytes.Equal(a, b)
}
