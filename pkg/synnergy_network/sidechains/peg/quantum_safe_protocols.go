package peg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
)

// QuantumSafeProtocolService manages quantum-safe encryption and decryption processes.
type QuantumSafeProtocolService struct {
	mutex       sync.Mutex
	encryptionKey []byte
}

// NewQuantumSafeProtocolService creates a new instance of QuantumSafeProtocolService.
func NewQuantumSafeProtocolService(encryptionKey []byte) *QuantumSafeProtocolService {
	return &QuantumSafeProtocolService{
		encryptionKey: encryptionKey,
	}
}

// EncryptAES encrypts data using AES encryption with the provided key.
func (qsps *QuantumSafeProtocolService) EncryptAES(data []byte) (string, error) {
	block, err := aes.NewCipher(qsps.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES encryption with the provided key.
func (qsps *QuantumSafeProtocolService) DecryptAES(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 ciphertext: %v", err)
	}

	block, err := aes.NewCipher(qsps.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES: %v", err)
	}

	return plaintext, nil
}

// GenerateKey generates a new AES encryption key.
func (qsps *QuantumSafeProtocolService) GenerateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// EncryptWithArgon2 encrypts data using Argon2 and AES encryption.
func (qsps *QuantumSafeProtocolService) EncryptWithArgon2(data []byte, passphrase string) (string, error) {
	key := crypto.GenerateArgon2Key([]byte(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithArgon2 decrypts data using Argon2 and AES encryption.
func (qsps *QuantumSafeProtocolService) DecryptWithArgon2(ciphertext string, passphrase string) ([]byte, error) {
	key := crypto.GenerateArgon2Key([]byte(passphrase))
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 ciphertext: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES: %v", err)
	}

	return plaintext, nil
}
