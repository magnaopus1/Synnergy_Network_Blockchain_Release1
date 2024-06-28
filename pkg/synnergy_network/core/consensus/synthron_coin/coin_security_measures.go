package synthron_coin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// SecurityConfig stores the configuration for various security mechanisms.
type SecurityConfig struct {
	SaltLength       int
	KeyLength        int
	ArgonIterations  int
	ArgonMemory      uint32
	ArgonParallelism uint8
	ArgonSaltLength  uint32
	ArgonKeyLength   uint32
	ArgonTime        uint32
}

// DefaultSecurityConfig returns a default configuration for security parameters.
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		SaltLength:       16,
		KeyLength:        32,
		ArgonIterations:  4,
		ArgonMemory:      64 * 1024,
		ArgonParallelism: 4,
		ArgonSaltLength:  16,
		ArgonKeyLength:   32,
		ArgonTime:        1,
	}
}

// GenerateSalt generates a random salt of the given length.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashPassword hashes a password using Argon2.
func HashPassword(password string, config *SecurityConfig) (string, error) {
	salt, err := GenerateSalt(int(config.ArgonSaltLength))
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, config.ArgonTime, config.ArgonMemory, config.ArgonParallelism, config.ArgonKeyLength)
	return hex.EncodeToString(hash), nil
}

// EncryptData encrypts data using AES-256-GCM.
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES-256-GCM.
func DecryptData(ciphertext []byte, passphrase string) ([]byte, error) {
	key := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ValidateHash compares a hash with a password to see if they match.
func ValidateHash(password, hash string, config *SecurityConfig) (bool, error) {
	// Extract the salt from the hash
	salt, err := hex.DecodeString(hash[:config.SaltLength*2]) // Salt length in bytes, hex encoded
	if err != nil {
		return false, err
	}

	// Compute the hash of the password using the same salt
	computedHash, err := HashPassword(password, config)
	if err != nil {
		return false, err
	}

	// Compare the hashes
	return hash == computedHash, nil
}

// SetupSecurity measures setup the security parameters on startup.
func SetupSecurity(config *SecurityConfig) {
	// This would be run on initialization to configure the security settings.
}

