package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
)

const (
	saltSize   = 16
	keySize    = 32
	nonceSize  = 12
)

// DataEncryption provides methods to encrypt and decrypt data using AES-GCM
type DataEncryption struct {
	salt []byte
}

// NewDataEncryption initializes and returns a new DataEncryption instance with a generated salt
func NewDataEncryption() *DataEncryption {
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate salt: %v", err))
	}
	return &DataEncryption{salt: salt}
}

// Encrypt encrypts plaintext using AES-GCM with a given passphrase
func (de *DataEncryption) Encrypt(plaintext, passphrase string) (string, error) {
	key, err := deriveKey(passphrase, de.salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	return encodedCiphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM with a given passphrase
func (de *DataEncryption) Decrypt(ciphertext, passphrase string) (string, error) {
	key, err := deriveKey(passphrase, de.salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(decodedCiphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedCiphertext[:nonceSize], decodedCiphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// deriveKey derives a key from the given passphrase and salt using scrypt
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keySize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SetSalt allows setting a custom salt for key derivation
func (de *DataEncryption) SetSalt(salt []byte) error {
	if len(salt) != saltSize {
		return errors.New("invalid salt size")
	}
	de.salt = salt
	return nil
}

// GetSalt returns the current salt used for key derivation
func (de *DataEncryption) GetSalt() []byte {
	return de.salt
}
