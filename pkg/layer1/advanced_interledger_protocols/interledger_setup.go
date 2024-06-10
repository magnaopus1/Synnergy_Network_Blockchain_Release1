package interledger

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

// InterledgerConfig holds the configuration settings for the interledger protocol
type InterledgerConfig struct {
	Passphrase string
	Salt       []byte
}

// NewInterledgerConfig creates a new configuration for the interledger setup with a secure passphrase
func NewInterledgerConfig(passphrase string) (*InterledgerConfig, error) {
	salt, err := generateSalt(16) // Generate a 16-byte salt
	if err != nil {
		return nil, err
	}

	return &InterledgerConfig{
		Passphrase: passphrase,
		Salt:       salt,
	}, nil
}

// SetupCipher sets up the AES cipher for encryption and decryption operations using Argon2 for key derivation
func (ic *InterledgerConfig) SetupCipher() (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(ic.Passphrase), ic.Salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead, nil
}

// generateSalt generates a secure random salt
func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptData uses the AEAD cipher to encrypt data
func (ic *InterledgerConfig) EncryptData(data []byte) (string, error) {
	aead, err := ic.SetupCipher()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encrypted := aead.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts data using the AEAD cipher
func (ic *InterledgerConfig) DecryptData(encData string) ([]byte, error) {
	data, err := hex.DecodeString(encData)
	if err != nil {
		return nil, err
	}

	aead, err := ic.SetupCipher()
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}
