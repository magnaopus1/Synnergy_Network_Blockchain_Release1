package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

// SecureStorage manages the encryption and decryption of sensitive data
type SecureStorage struct {
	mu       sync.Mutex
	password []byte
	salt     []byte
}

// NewSecureStorage creates a new instance of SecureStorage
func NewSecureStorage(password, salt []byte) *SecureStorage {
	return &SecureStorage{
		password: password,
		salt:     salt,
	}
}

// Encrypt encrypts the given data using AES encryption with the stored password and salt
func (ss *SecureStorage) Encrypt(data []byte) (string, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	block, err := aes.NewCipher(ss.deriveKey())
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
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given data using AES decryption with the stored password and salt
func (ss *SecureStorage) Decrypt(encryptedData string) ([]byte, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ss.deriveKey())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// deriveKey derives a key from the password and salt using Scrypt
func (ss *SecureStorage) deriveKey() []byte {
	key, err := scrypt.Key(ss.password, ss.salt, 32768, 8, 1, 32)
	if err != nil {
		panic("failed to derive key: " + err.Error())
	}
	return key
}
