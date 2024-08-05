package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/scrypt"
	"io"
)

// SecureStorage defines the structure for managing secure storage of sensitive data
type SecureStorage struct {
	Key     []byte
	Nonce   []byte
	Storage map[string]string
}

// NewSecureStorage initializes a new SecureStorage instance
func NewSecureStorage(password string, salt []byte) (*SecureStorage, error) {
	key, err := generateKey(password, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &SecureStorage{
		Key:     key,
		Nonce:   nonce,
		Storage: make(map[string]string),
	}, nil
}

// generateKey generates a key from the password and salt using scrypt
func generateKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

// Encrypt encrypts data using AES-GCM
func (ss *SecureStorage) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(ss.Key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, ss.Nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-GCM
func (ss *SecureStorage) Decrypt(ciphertext string) (string, error) {
	block, err := aes.NewCipher(ss.Key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, ss.Nonce, data, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Store securely stores the data
func (ss *SecureStorage) Store(key, value string) error {
	encryptedValue, err := ss.Encrypt(value)
	if err != nil {
		return err
	}
	ss.Storage[key] = encryptedValue
	return nil
}

// Retrieve securely retrieves the data
func (ss *SecureStorage) Retrieve(key string) (string, error) {
	encryptedValue, exists := ss.Storage[key]
	if !exists {
		return "", errors.New("key does not exist")
	}
	return ss.Decrypt(encryptedValue)
}

// Delete securely deletes the data
func (ss *SecureStorage) Delete(key string) {
	delete(ss.Storage, key)
}

// HashPassword securely hashes a password using SHA-256
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}
