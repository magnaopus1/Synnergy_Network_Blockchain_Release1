package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
)

// EncryptData encrypts plaintext using AES-GCM with a passphrase.
func EncryptData(plaintext, passphrase string) (string, error) {
	key := deriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts ciphertext using AES-GCM with a passphrase.
func DecryptData(ciphertext, passphrase string) (string, error) {
	key := deriveKey(passphrase)
	data, err := hex.DecodeString(ciphertext)
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

	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// deriveKey derives a key from a passphrase using Argon2.
func deriveKey(passphrase string) []byte {
	salt := generateSalt()
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// generateSalt generates a random salt for key derivation.
func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// HashPassword hashes a password using Argon2.
func HashPassword(password string) (string, error) {
	salt := generateSalt()
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

// VerifyPassword verifies a password against a hashed value.
func VerifyPassword(password, hashed string) (bool, error) {
	parts := split(hashed, ':')
	if len(parts) != 2 {
		return false, errors.New("invalid hashed password format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	hash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	passwordHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(passwordHash, hash) == 1, nil
}

// HashData hashes data using SHA-256.
func HashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ScryptKeyDerivation derives a key using Scrypt.
func ScryptKeyDerivation(passphrase string) ([]byte, error) {
	salt := generateSalt()
	return scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
}

// split splits a string by a separator.
func split(s, sep string) []string {
	return strings.Split(s, sep)
}
