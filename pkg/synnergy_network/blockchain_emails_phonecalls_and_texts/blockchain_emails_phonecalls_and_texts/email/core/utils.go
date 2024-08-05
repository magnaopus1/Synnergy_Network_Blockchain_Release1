package core


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"golang.org/x/crypto/scrypt"
)

// HashPassword hashes the given password with a random salt and returns the salt and the hashed password
func HashPassword(password string, saltSize int) (string, string, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", "", err
	}

	hash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash), nil
}

// VerifyPassword verifies the given password against the stored salt and hashed password
func VerifyPassword(password, storedSalt, storedHash string) (bool, error) {
	salt, err := base64.StdEncoding.DecodeString(storedSalt)
	if err != nil {
		return false, err
	}

	hash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return false, err
	}

	return base64.StdEncoding.EncodeToString(hash) == storedHash, nil
}

// Encrypt encrypts the given plaintext using AES with the provided key
func Encrypt(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(key)))
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES with the provided key
func Decrypt(ciphertext, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(createHash(key)))
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

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// createHash creates a SHA-256 hash of the given input
func createHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return base64.StdEncoding.EncodeToString(hash[:])
}
