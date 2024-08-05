package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// SecureStorage provides secure storage for sensitive data
type SecureStorage struct {
	data  map[string]string
	mutex sync.Mutex
	key   []byte
}

// NewSecureStorage initializes a new SecureStorage with a password
func NewSecureStorage(password string) (*SecureStorage, error) {
	key, err := generateKeyFromPassword(password)
	if err != nil {
		return nil, err
	}

	return &SecureStorage{
		data: make(map[string]string),
		key:  key,
	}, nil
}

// Store securely stores data with a given key
func (ss *SecureStorage) Store(key, value string) error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	encryptedValue, err := encrypt([]byte(value), ss.key)
	if err != nil {
		return err
	}

	ss.data[key] = encryptedValue
	return nil
}

// Retrieve retrieves securely stored data by key
func (ss *SecureStorage) Retrieve(key string) (string, error) {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	encryptedValue, exists := ss.data[key]
	if !exists {
		return "", fmt.Errorf("no value found for key %s", key)
	}

	decryptedValue, err := decrypt(encryptedValue, ss.key)
	if err != nil {
		return "", err
	}

	return string(decryptedValue), nil
}

// Delete removes securely stored data by key
func (ss *SecureStorage) Delete(key string) error {
	ss.mutex.Lock()
	defer ss.mutex.Unlock()

	delete(ss.data, key)
	return nil
}

// generateKeyFromPassword generates a key from a password using scrypt
func generateKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// encrypt encrypts data using AES
func encrypt(data, key []byte) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES
func decrypt(encryptedData string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashData hashes data using SHA-256
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
