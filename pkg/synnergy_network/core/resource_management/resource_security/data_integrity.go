package resource_security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"time"
)

// DataIntegrityManager handles the encryption, decryption, and integrity verification of data
type DataIntegrityManager struct {
	encryptionKey []byte
}

// NewDataIntegrityManager initializes a new DataIntegrityManager with the provided encryption key
func NewDataIntegrityManager(key string) (*DataIntegrityManager, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes long")
	}
	return &DataIntegrityManager{encryptionKey: []byte(key)}, nil
}

// EncryptData encrypts the given data using AES-GCM and returns the encrypted data as a base64 string
func (dim *DataIntegrityManager) EncryptData(data string) (string, error) {
	block, err := aes.NewCipher(dim.encryptionKey)
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

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given base64-encoded encrypted data using AES-GCM
func (dim *DataIntegrityManager) DecryptData(encryptedData string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dim.encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// VerifyDataIntegrity checks the integrity of the data by comparing the hash with the original
func (dim *DataIntegrityManager) VerifyDataIntegrity(data, hash string) bool {
	computedHash := computeHash(data)
	return computedHash == hash
}

// computeHash generates a hash of the given data (placeholder function)
func computeHash(data string) string {
	// Implement hash computation logic (e.g., using SHA-256)
	return fmt.Sprintf("%x", data) // Placeholder
}

// LogAuditTrail logs data access events for auditing purposes
func LogAuditTrail(action, data string) {
	log.Printf("Action: %s, Data: %s, Timestamp: %s\n", action, data, time.Now().Format(time.RFC3339))
}

// Ensure compliance with data protection regulations by encrypting sensitive data
func (dim *DataIntegrityManager) EnsureCompliance(data string) (string, error) {
	encryptedData, err := dim.EncryptData(data)
	if err != nil {
		return "", err
	}
	LogAuditTrail("EncryptData", encryptedData)
	return encryptedData, nil
}

// DecryptAndAudit decrypts the data and logs the action for auditing
func (dim *DataIntegrityManager) DecryptAndAudit(encryptedData string) (string, error) {
	decryptedData, err := dim.DecryptData(encryptedData)
	if err != nil {
		return "", err
	}
	LogAuditTrail("DecryptData", encryptedData)
	return decryptedData, nil
}
