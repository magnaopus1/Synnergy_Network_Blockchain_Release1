package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
)

// SecureStorage provides secure storage for sensitive data
type SecureStorage struct {
	mu        sync.Mutex
	storage   map[string]string
	key       []byte
	salt      []byte
	iteration uint32
	memory    uint32
	threads   uint8
}

// NewSecureStorage initializes a new SecureStorage instance
func NewSecureStorage(password string) (*SecureStorage, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := argon2.Key([]byte(password), salt, 1, 64*1024, 4, 32)

	return &SecureStorage{
		storage:   make(map[string]string),
		key:       key,
		salt:      salt,
		iteration: 1,
		memory:    64 * 1024,
		threads:   4,
	}, nil
}

// Encrypt encrypts data using AES-GCM
func (ss *SecureStorage) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-GCM
func (ss *SecureStorage) Decrypt(ciphertext string) (string, error) {
	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Store securely stores data
func (ss *SecureStorage) Store(key, value string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	encryptedValue, err := ss.Encrypt(value)
	if err != nil {
		return err
	}

	ss.storage[key] = encryptedValue
	return nil
}

// Retrieve securely retrieves data
func (ss *SecureStorage) Retrieve(key string) (string, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	encryptedValue, ok := ss.storage[key]
	if !ok {
		return "", errors.New("key not found")
	}

	return ss.Decrypt(encryptedValue)
}

// Delete removes data from secure storage
func (ss *SecureStorage) Delete(key string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	delete(ss.storage, key)
	return nil
}

// ChangePassword allows changing the password used for encryption
func (ss *SecureStorage) ChangePassword(newPassword string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	newKey := argon2.Key([]byte(newPassword), ss.salt, ss.iteration, ss.memory, ss.threads, 32)
	ss.key = newKey
	return nil
}

// SecureStorageData provides a singleton instance for secure storage
var SecureStorageData *SecureStorage

// InitSecureStorage initializes the secure storage with a given password
func InitSecureStorage(password string) error {
	var err error
	SecureStorageData, err = NewSecureStorage(password)
	return err
}

