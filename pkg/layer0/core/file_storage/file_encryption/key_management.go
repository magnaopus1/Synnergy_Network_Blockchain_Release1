// Package file_encryption handles the encryption and decryption of files within the Synnergy Network blockchain.
package file_encryption

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// KeyManager manages the encryption keys used for file encryption.
type KeyManager struct {
	// Salt is used with PBKDF2 to generate deterministic keys from passwords.
	Salt []byte
	// Iterations define the complexity of the hashing process to make brute-force attacks more difficult.
	Iterations int
}

// NewKeyManager creates a new KeyManager with a random salt.
func NewKeyManager() (*KeyManager, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &KeyManager{
		Salt:       salt,
		Iterations: 10000, // Recommended number of iterations for PBKDF2
	}, nil
}

// GenerateKey generates a 32-byte key using PBKDF2 with the provided password.
func (km *KeyManager) GenerateKey(password string) []byte {
	return pbkdf2.Key([]byte(password), km.Salt, km.Iterations, 32, sha256.New)
}

// EncryptData encrypts data using AES-256-GCM.
func EncryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES-256-GCM.
func DecryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:aesgcm.NonceSize()], data[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example usage of KeyManager and encryption functions.
func main() {
	manager, err := NewKeyManager()
	if err != nil {
		panic(err)
	}

	password := "strong_password123"
	key := manager.GenerateKey(password)

	// Example data to encrypt
	data := []byte("Sensitive data for encryption")
	encryptedData, err := EncryptData(data, key)
	if err != nil {
		panic(err)
	}

	decryptedData, err := DecryptData(encryptedData, key)
	if err != nil {
		panic(err)
	}

	println("Decrypted data:", string(decryptedData))
}
