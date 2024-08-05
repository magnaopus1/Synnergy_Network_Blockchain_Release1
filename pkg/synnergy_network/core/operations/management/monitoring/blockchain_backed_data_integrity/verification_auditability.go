package blockchain_backed_data_integrity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// VerificationAuditability ensures that the data integrity can be verified and audited in a secure manner

type VerificationAuditability struct {
	encryptionKey []byte
	hashSalt      []byte
}

// NewVerificationAuditability creates a new instance of VerificationAuditability
func NewVerificationAuditability(password, salt string) (*VerificationAuditability, error) {
	key, err := generateKey(password, salt)
	if err != nil {
		return nil, err
	}
	return &VerificationAuditability{
		encryptionKey: key,
		hashSalt:      []byte(salt),
	}, nil
}

// generateKey generates a secure encryption key using Argon2
func generateKey(password, salt string) ([]byte, error) {
	saltBytes := []byte(salt)
	key := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	if len(key) == 0 {
		return nil, errors.New("failed to generate key")
	}
	return key, nil
}

// EncryptData encrypts the given data using AES-GCM
func (va *VerificationAuditability) EncryptData(plainText string) (string, error) {
	block, err := aes.NewCipher(va.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(os.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(cipherText), nil
}

// DecryptData decrypts the given encrypted data using AES-GCM
func (va *VerificationAuditability) DecryptData(encryptedText string) (string, error) {
	cipherText, err := hex.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(va.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", errors.New("cipherText too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// GenerateDataHash generates a SHA-256 hash of the data with salt
func (va *VerificationAuditability) GenerateDataHash(data string) string {
	hash := sha256.New()
	hash.Write(va.hashSalt)
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyDataHash verifies the SHA-256 hash of the data with salt
func (va *VerificationAuditability) VerifyDataHash(data, hash string) bool {
	expectedHash := va.GenerateDataHash(data)
	return expectedHash == hash
}

// LogVerification logs the verification details securely
func (va *VerificationAuditability) LogVerification(data, hash string, success bool) {
	status := "FAIL"
	if success {
		status = "PASS"
	}

	logEntry := fmt.Sprintf("Data: %s, Hash: %s, Status: %s\n", data, hash, status)
	logToFile(logEntry)
}

// logToFile logs the entry to a secure file
func logToFile(logEntry string) {
	file, err := os.OpenFile("verification_audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteString(logEntry); err != nil {
		log.Fatal(err)
	}
}

