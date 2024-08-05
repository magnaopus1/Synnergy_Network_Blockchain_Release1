package liquidity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// Constants for scrypt
const (
	ScryptN  = 1 << 15
	ScryptR  = 8
	ScryptP  = 1
	ScryptKeyLen = 32
)

// Constants for Argon2
const (
	Argon2Time = 1
	Argon2Memory = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen = 32
)

// QuantumSafeEncrypt encrypts the given plaintext using a password and returns the ciphertext.
func QuantumSafeEncrypt(plaintext, password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Generate the key using scrypt
	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext using AES-GCM
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
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// QuantumSafeDecrypt decrypts the given ciphertext using a password and returns the plaintext.
func QuantumSafeDecrypt(ciphertext, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Extract the salt and ciphertext
	salt := data[:16]
	ciphertext = string(data[16:])

	// Generate the key using scrypt
	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := []byte(ciphertext[:nonceSize]), []byte(ciphertext[nonceSize:])
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Argon2Encrypt encrypts the given plaintext using a password and Argon2 for key derivation.
func Argon2Encrypt(plaintext, password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Generate the key using Argon2
	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Encrypt the plaintext using AES-GCM
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
	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// Argon2Decrypt decrypts the given ciphertext using a password and Argon2 for key derivation.
func Argon2Decrypt(ciphertext, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Extract the salt and ciphertext
	salt := data[:16]
	ciphertext = string(data[16:])

	// Generate the key using Argon2
	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Decrypt the ciphertext using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := []byte(ciphertext[:nonceSize]), []byte(ciphertext[nonceSize:])
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// QuantumSafeHash hashes the given data using SHA-256
func QuantumSafeHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ValidateDataIntegrity validates the integrity of the data using a given hash
func ValidateDataIntegrity(data, hash string) bool {
	computedHash := QuantumSafeHash(data)
	return computedHash == hash
}

// KeyDerivationFunction chooses the best KDF based on the situation
func KeyDerivationFunction(password, salt string, useArgon2 bool) ([]byte, error) {
	if useArgon2 {
		return argon2.IDKey([]byte(password), []byte(salt), Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen), nil
	}
	return scrypt.Key([]byte(password), []byte(salt), ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}
