package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// SecureStorageManager manages secure storage operations.
type SecureStorageManager struct {
	mu    sync.RWMutex
	store map[string]string // map to store encrypted data
}

// NewSecureStorageManager initializes a new SecureStorageManager instance.
func NewSecureStorageManager() *SecureStorageManager {
	return &SecureStorageManager{
		store: make(map[string]string),
	}
}

// StoreData securely stores data with a key.
func (ssm *SecureStorageManager) StoreData(key, data, passphrase string) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	ssm.store[key] = encryptedData
	return nil
}

// RetrieveData securely retrieves data with a key.
func (ssm *SecureStorageManager) RetrieveData(key, passphrase string) (string, error) {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()

	encryptedData, exists := ssm.store[key]
	if !exists {
		return "", errors.New("data not found")
	}

	decryptedData, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

// EncryptData encrypts plaintext using AES-GCM with a passphrase.
func EncryptData(plaintext, passphrase string) (string, error) {
	key, salt, err := deriveKey(passphrase)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts ciphertext using AES-GCM with a passphrase.
func DecryptData(ciphertext, passphrase string) (string, error) {
	parts := split(ciphertext, ':')
	if len(parts) != 2 {
		return "", errors.New("invalid ciphertext format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	key, _, err := deriveKeyWithSalt(passphrase, salt)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// deriveKey derives a key from a passphrase using Argon2.
func deriveKey(passphrase string) ([]byte, []byte, error) {
	salt := generateSalt()
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, salt, nil
}

// deriveKeyWithSalt derives a key from a passphrase and salt using Argon2.
func deriveKeyWithSalt(passphrase string, salt []byte) ([]byte, []byte, error) {
	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, salt, nil
}

// generateSalt generates a random salt for key derivation.
func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// HashData hashes data using SHA-256.
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ScryptKeyDerivation derives a key using Scrypt.
func ScryptKeyDerivation(passphrase string) ([]byte, error) {
	salt := generateSalt()
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}

// split splits a string by a separator.
func split(s, sep string) []string {
	return strings.Split(s, sep)
}
