// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// ensuring high-level performance, security, and real-world applicability. This security_protocols.go file
// implements the logic for security protocols within the network.

package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"time"
)

// SecurityProtocols manages the security protocols within the network.
type SecurityProtocols struct {
	encryptionKey []byte
}

// NewSecurityProtocols creates a new instance of SecurityProtocols with a given encryption key.
func NewSecurityProtocols(key string) *SecurityProtocols {
	return &SecurityProtocols{
		encryptionKey: []byte(key),
	}
}

// Encrypt encrypts a plain text string using AES encryption.
func (sp *SecurityProtocols) Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(sp.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts an AES-encrypted string.
func (sp *SecurityProtocols) Decrypt(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sp.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// GenerateEncryptionKey generates a new AES encryption key.
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// LogSecurityEvent logs a security event with a timestamp.
func LogSecurityEvent(event string) {
	log.Printf("Security Event: %s at %s", event, time.Now().Format(time.RFC3339))
}

// ValidateTransactionSignature validates the signature of a transaction.
func ValidateTransactionSignature(transactionData, signature, publicKey string) (bool, error) {
	// Implement signature validation logic here
	// This is a placeholder for actual implementation
	return true, nil
}

// Example usage of security protocols within the node package
func main() {
	key, err := GenerateEncryptionKey()
	if err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}

	sp := NewSecurityProtocols(key)

	encryptedText, err := sp.Encrypt("This is a secret message")
	if err != nil {
		log.Fatalf("Failed to encrypt text: %v", err)
	}

	log.Printf("Encrypted Text: %s", encryptedText)

	decryptedText, err := sp.Decrypt(encryptedText)
	if err != nil {
		log.Fatalf("Failed to decrypt text: %v", err)
	}

	log.Printf("Decrypted Text: %s", decryptedText)

	LogSecurityEvent("Test event")

	valid, err := ValidateTransactionSignature("transaction data", "signature", "public key")
	if err != nil {
		log.Fatalf("Failed to validate transaction signature: %v", err)
	}

	log.Printf("Transaction Signature Valid: %v", valid)
}
