package compliance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// UserInfo represents the basic information required for KYC.
type UserInfo struct {
	ID            string // Unique identifier for the user
	Name          string // User's full name
	DateOfBirth   string // Date of birth
	Address       string // Residential address
	DocumentID    string // ID of the document used for verification
	DocumentType  string // Type of document (e.g., Passport, Driver's License)
	VerificationStatus string // Status of KYC verification
}

// AMLCompliance represents the AML compliance information for a transaction.
type AMLCompliance struct {
	TransactionID string  // Unique identifier for the transaction
	UserID        string  // ID of the user involved in the transaction
	TransactionAmount float64 // Amount involved in the transaction
	Flagged       bool    // Indicates if the transaction is flagged for review
	Reason        string  // Reason for flagging (if applicable)
	Reviewed      bool    // Indicates if the transaction has been reviewed
	ReviewOutcome string  // Outcome of the review
}

// Encrypt encrypts data using AES encryption.
func Encrypt(data, passphrase string) (string, error) {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES encryption.
func Decrypt(data, passphrase string) (string, error) {
	dataBytes, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := dataBytes[:nonceSize], dataBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// createHash creates a hash using SHA-256.
func createHash(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// VerifyUser verifies the KYC information of a user.
func VerifyUser(user *UserInfo) error {
	// In a real-world scenario, this function would involve checking the provided documents and information.
	// For this implementation, we'll assume the verification is based on some external process and return a success status.
	if user.Name == "" || user.DocumentID == "" {
		return errors.New("missing essential KYC information")
	}
	user.VerificationStatus = "Verified"
	return nil
}

// FlagTransaction flags a transaction for AML compliance review.
func FlagTransaction(aml *AMLCompliance, reason string) {
	aml.Flagged = true
	aml.Reason = reason
	aml.Reviewed = false
}

// ReviewTransaction reviews a flagged transaction.
func ReviewTransaction(aml *AMLCompliance, outcome string) {
	aml.Reviewed = true
	aml.ReviewOutcome = outcome
}

// CheckAMLCompliance checks a transaction against AML rules.
func CheckAMLCompliance(aml *AMLCompliance) error {
	// Example rule: transactions above a certain amount should be flagged
	const threshold = 10000.0
	if aml.TransactionAmount > threshold {
		FlagTransaction(aml, "Transaction amount exceeds threshold")
	}
	if aml.Flagged && !aml.Reviewed {
		return errors.New("transaction requires AML review")
	}
	return nil
}

// StoreUserInfo securely stores user information after encryption.
func StoreUserInfo(user *UserInfo, encryptionKey string) (string, error) {
	// Simulate data serialization and encryption
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s", user.ID, user.Name, user.DateOfBirth, user.Address, user.DocumentID, user.DocumentType)
	encryptedData, err := Encrypt(data, encryptionKey)
	if err != nil {
		return "", err
	}
	// Store encrypted data in the database (simulated here with a return)
	return encryptedData, nil
}

// RetrieveUserInfo retrieves and decrypts stored user information.
func RetrieveUserInfo(encryptedData, encryptionKey string) (*UserInfo, error) {
	// Decrypt data
	decryptedData, err := Decrypt(encryptedData, encryptionKey)
	if err != nil {
		return nil, err
	}

	// Simulate data deserialization
	var user UserInfo
	_, err = fmt.Sscanf(decryptedData, "%s|%s|%s|%s|%s|%s", &user.ID, &user.Name, &user.DateOfBirth, &user.Address, &user.DocumentID, &user.DocumentType)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
