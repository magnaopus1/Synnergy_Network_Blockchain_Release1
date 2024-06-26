package quantum_key_distribution

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGenerateRandomBytes tests the GenerateRandomBytes function
func TestGenerateRandomBytes(t *testing.T) {
	length := 32
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}

	if len(bytes) != length {
		t.Fatalf("Expected %d bytes, got %d", length, len(bytes))
	}
}

// TestGenerateArgon2Key tests the GenerateArgon2Key function
func TestGenerateArgon2Key(t *testing.T) {
	password := []byte("password")
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key := GenerateArgon2Key(password, salt)
	if len(key) != Argon2KeyLen {
		t.Fatalf("Expected key length %d, got %d", Argon2KeyLen, len(key))
	}
}

// TestGenerateScryptKey tests the GenerateScryptKey function
func TestGenerateScryptKey(t *testing.T) {
	password := []byte("password")
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := GenerateScryptKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to generate Scrypt key: %v", err)
	}

	if len(key) != ScryptKeyLen {
		t.Fatalf("Expected key length %d, got %d", ScryptKeyLen, len(key))
	}
}

// TestEncryptDecrypt tests the Encrypt and Decrypt functions
func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateRandomBytes(AESKeyLen)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := []byte("Test data for encryption")
	ciphertext, err := Encrypt(data, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Fatalf("Decrypted data does not match original data")
	}
}

// TestGenerateHMAC tests the GenerateHMAC function
func TestGenerateHMAC(t *testing.T) {
	key, err := GenerateRandomBytes(HMACKeyLen)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := []byte("Test data for HMAC")
	hmac := GenerateHMAC(data, key)

	if len(hmac) != sha256.Size {
		t.Fatalf("Expected HMAC length %d, got %d", sha256.Size, len(hmac))
	}
}

// TestVerifyHMAC tests the VerifyHMAC function
func TestVerifyHMAC(t *testing.T) {
	key, err := GenerateRandomBytes(HMACKeyLen)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := []byte("Test data for HMAC")
	hmac := GenerateHMAC(data, key)

	valid := VerifyHMAC(data, key, hmac)
	if !valid {
		t.Fatalf("Expected HMAC to be valid")
	}

	invalidHMAC := GenerateHMAC([]byte("Different data"), key)
	invalid := VerifyHMAC(data, key, invalidHMAC)
	if invalid {
		t.Fatalf("Expected HMAC to be invalid")
	}
}

// TestSecureKeyManager tests the SecureKeyManager's key management functions
func TestSecureKeyManager(t *testing.T) {
	skm := NewSecureKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := skm.AddKey(chainID, password)
	if err != nil {
		t.Fatalf("Failed to add key: %v", err)
	}

	// Retrieve the quantum key
	key, err := skm.GetKey(chainID)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}
	if len(key) != Argon2KeyLen {
		t.Fatalf("Expected key length %d, got %d", Argon2KeyLen, len(key))
	}

	// Update the quantum key
	newPassword := []byte("newsecurepassword")
	err = skm.UpdateKey(chainID, newPassword)
	if err != nil {
		t.Fatalf("Failed to update key: %v", err)
	}

	newKey, err := skm.GetKey(chainID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated key: %v", err)
	}
	if bytes.Equal(key, newKey) {
		t.Fatalf("Expected updated key to be different")
	}

	// Delete the quantum key
	skm.DeleteKey(chainID)
	_, err = skm.GetKey(chainID)
	if err == nil {
		t.Fatalf("Expected error when retrieving deleted key")
	}
}

// TestEncryptionDecryptionWithChainID tests encryption and decryption with chain ID
func TestEncryptionDecryptionWithChainID(t *testing.T) {
	skm := NewSecureKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := skm.AddKey(chainID, password)
	if err != nil {
		t.Fatalf("Failed to add key: %v", err)
	}

	// Encrypt data
	data := []byte("Sensitive blockchain data")
	ciphertext, err := skm.EncryptWithChainID(chainID, data)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt data
	plaintext, err := skm.DecryptWithChainID(chainID, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(data, plaintext) {
		t.Fatalf("Decrypted data does not match original data")
	}
}

// TestMain demonstrates the key management and encryption/decryption process
func TestMain(t *testing.T) {
	skm := NewSecureKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := skm.AddKey(chainID, password)
	if err != nil {
		t.Fatalf("Error adding key: %v", err)
	}

	// Retrieve the quantum key
	key, err := skm.GetKey(chainID)
	if err != nil {
		t.Fatalf("Error retrieving key: %v", err)
	}
	t.Logf("Retrieved key: %s", hex.EncodeToString(key))

	// Encrypt data
	data := []byte("Sensitive blockchain data")
	ciphertext, err := skm.EncryptWithChainID(chainID, data)
	if err != nil {
		t.Fatalf("Error encrypting data: %v", err)
	}
	t.Logf("Encrypted data: %s", hex.EncodeToString(ciphertext))

	// Decrypt data
	plaintext, err := skm.DecryptWithChainID(chainID, ciphertext)
	if err != nil {
		t.Fatalf("Error decrypting data: %v", err)
	}
	t.Logf("Decrypted data: %s", plaintext)

	if !bytes.Equal(data, plaintext) {
		t.Fatalf("Decrypted data does not match original data")
	}
}
