package hybrid_cryptography_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"synnergy_network/core/blockchain/quantum_resistance/post_quantum_algorithms/hybrid_cryptography"
)

// Helper function to generate a random byte slice
func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func TestGenerateClassicalKey(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomBytes(16)
	assert.NoError(t, err)

	key, err := hybrid_cryptography.GenerateClassicalKey(password, salt)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Len(t, key, 32)
}

func TestGenerateQuantumResistantKey(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomBytes(16)
	assert.NoError(t, err)

	key := hybrid_cryptography.GenerateQuantumResistantKey(password, salt)
	assert.NotNil(t, key)
	assert.Len(t, key, 32)
}

func TestDualLayerSecurity_EncryptDecrypt(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomBytes(16)
	assert.NoError(t, err)

	classicalKey, err := hybrid_cryptography.GenerateClassicalKey(password, salt)
	assert.NoError(t, err)

	quantumResistantKey := hybrid_cryptography.GenerateQuantumResistantKey(password, salt)

	dls := hybrid_cryptography.NewDualLayerSecurity(classicalKey, quantumResistantKey)

	message := []byte("Hello, Quantum-Resistant World!")
	encryptedMessage, err := dls.Encrypt(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, encryptedMessage)

	decryptedMessage, err := dls.Decrypt(encryptedMessage)
	assert.NoError(t, err)
	assert.Equal(t, message, decryptedMessage)
}

func TestDualLayerSecurity_EncryptDecrypt_InvalidCiphertext(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomBytes(16)
	assert.NoError(t, err)

	classicalKey, err := hybrid_cryptography.GenerateClassicalKey(password, salt)
	assert.NoError(t, err)

	quantumResistantKey := hybrid_cryptography.GenerateQuantumResistantKey(password, salt)

	dls := hybrid_cryptography.NewDualLayerSecurity(classicalKey, quantumResistantKey)

	// Generate a valid encrypted message
	message := []byte("Hello, Quantum-Resistant World!")
	encryptedMessage, err := dls.Encrypt(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, encryptedMessage)

	// Corrupt the encrypted message
	corruptedEncryptedMessage := encryptedMessage[:len(encryptedMessage)-1] + "x"

	_, err = dls.Decrypt(corruptedEncryptedMessage)
	assert.Error(t, err)
}

func TestDualLayerSecurity_EncryptDecrypt_HashMismatch(t *testing.T) {
	password := []byte("securepassword")
	salt, err := generateRandomBytes(16)
	assert.NoError(t, err)

	classicalKey, err := hybrid_cryptography.GenerateClassicalKey(password, salt)
	assert.NoError(t, err)

	quantumResistantKey := hybrid_cryptography.GenerateQuantumResistantKey(password, salt)

	dls := hybrid_cryptography.NewDualLayerSecurity(classicalKey, quantumResistantKey)

	message := []byte("Hello, Quantum-Resistant World!")
	encryptedMessage, err := dls.Encrypt(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, encryptedMessage)

	// Decode the encrypted message
	finalCiphertext, err := hex.DecodeString(encryptedMessage)
	assert.NoError(t, err)

	// Tamper with the hash to simulate a hash mismatch
	finalCiphertext[len(finalCiphertext)-1] ^= 0xFF

	// Re-encode the tampered ciphertext
	tamperedEncryptedMessage := hex.EncodeToString(finalCiphertext)

	_, err = dls.Decrypt(tamperedEncryptedMessage)
	assert.Error(t, err)
}

func TestNewDualLayerSecurity(t *testing.T) {
	classicalKey, err := generateRandomBytes(32)
	assert.NoError(t, err)

	quantumResistantKey, err := generateRandomBytes(32)
	assert.NoError(t, err)

	dls := hybrid_cryptography.NewDualLayerSecurity(classicalKey, quantumResistantKey)

	assert.NotNil(t, dls)
	assert.Equal(t, classicalKey, dls.ClassicalKey)
	assert.Equal(t, quantumResistantKey, dls.QuantumResistantKey)
}
