package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// SecureStorage handles secure storage of sensitive information
type SecureStorage struct {
	key []byte
}

// NewSecureStorage initializes and returns a new SecureStorage instance
func NewSecureStorage(key []byte) (*SecureStorage, error) {
	if len(key) != 32 {
		return nil, errors.New("key length must be 32 bytes")
	}
	return &SecureStorage{key: key}, nil
}

// Encrypt encrypts the given plaintext using AES-GCM
func (s *SecureStorage) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES-GCM
func (s *SecureStorage) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
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

// SecurelyStoreData securely stores data by encrypting it
func (s *SecureStorage) SecurelyStoreData(data string) (string, error) {
	encryptedData, err := s.Encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// RetrieveSecureData retrieves and decrypts the securely stored data
func (s *SecureStorage) RetrieveSecureData(encryptedData string) (string, error) {
	decryptedData, err := s.Decrypt(encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}

// EnsureIntegrity checks if the stored data is unaltered by comparing hashes (placeholder)
func (s *SecureStorage) EnsureIntegrity(originalData, encryptedData string) (bool, error) {
	decryptedData, err := s.Decrypt(encryptedData)
	if err != nil {
		return false, err
	}
	return originalData == decryptedData, nil
}

// BackupData securely backs up data to a secondary location (placeholder)
func (s *SecureStorage) BackupData(data string) (string, error) {
	encryptedData, err := s.Encrypt(data)
	if err != nil {
		return "", err
	}
	// Placeholder for actual backup logic
	return encryptedData, nil
}

// RestoreData restores data from a backup location (placeholder)
func (s *SecureStorage) RestoreData(encryptedBackupData string) (string, error) {
	decryptedData, err := s.Decrypt(encryptedBackupData)
	if err != nil {
		return "", err
	}
	// Placeholder for actual restore logic
	return decryptedData, nil
}

// PurgeData securely deletes data (placeholder)
func (s *SecureStorage) PurgeData(dataID string) error {
	// Placeholder for actual data deletion logic
	return nil
}
