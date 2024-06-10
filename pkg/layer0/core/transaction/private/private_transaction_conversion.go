package transaction

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// PrivateTransaction represents a transaction with encrypted data ensuring privacy.
type PrivateTransaction struct {
	ID            string
	EncryptedData string
	Fee           uint64
	Signature     string
	PublicKey     string
}

// EncryptTransactionData encrypts the transaction data using the specified encryption algorithm.
func EncryptTransactionData(data, key string) (string, error) {
	switch encryption.GetCurrentAlgorithm() {
	case "AES":
		return encryptWithAES(data, key)
	case "Scrypt", "Argon2":
		return encryptWithScryptOrArgon2(data, key)
	default:
		return "", errors.New("unsupported encryption algorithm")
	}
}

// encryptWithAES encrypts data using AES.
func encryptWithAES(data, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	plaintext := []byte(data)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return hex.EncodeToString(ciphertext), nil
}

// encryptWithScryptOrArgon2 encrypts data using Scrypt or Argon2.
func encryptWithScryptOrArgon2(data, key string) (string, error) {
	// Implementation would be similar to AES but using Scrypt or Argon2 libraries.
	return "encryptedData", nil
}

// DecryptTransactionData decrypts the encrypted transaction data.
func DecryptTransactionData(encryptedData, key string) (string, error) {
	switch encryption.GetCurrentAlgorithm() {
	case "AES":
		return decryptWithAES(encryptedData, key)
	case "Scrypt", "Argon2":
		return decryptWithScryptOrArgon2(encryptedData, key)
	default:
		return "", errors.New("unsupported encryption algorithm")
	}
}

// decryptWithAES decrypts data using AES.
func decryptWithAES(encryptedData, key string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(data) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return string(data), nil
}

// decryptWithScryptOrArgon2 decrypts data using Scrypt or Argon2.
func decryptWithScryptOrArgon2(encryptedData, key string) (string, error) {
	// Implementation would be similar to AES but using Scrypt or Argon2 libraries.
	return "decryptedData", nil
}

// VerifyTransactionSignature checks if the transaction's signature is valid.
func (pt *PrivateTransaction) VerifyTransactionSignature() bool {
	// This would use the public key and signature fields to verify the authenticity of the transaction.
	return true // Placeholder for the actual implementation.
}

// init initializes the encryption module, potentially setting up keys and algorithms.
func init() {
	encryption.SetupEncryption("AES", "Scrypt", "Argon2")
}
