package encryption_util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// GenerateKey generates a secure encryption key using Scrypt.
func GenerateKey(password, salt []byte, keyLen int) ([]byte, error) {
	const N = 1 << 15
	const r = 8
	const p = 1

	key, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateArgon2Key generates a secure encryption key using Argon2.
func GenerateArgon2Key(password, salt []byte, keyLen uint32) []byte {
	const time = 1
	const memory = 64 * 1024
	const threads = 4

	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// Encrypt encrypts plaintext using AES-GCM.
func Encrypt(plaintext, key []byte) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM.
func Decrypt(ciphertextHex string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
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
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateSalt generates a new random salt.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// Hash generates a SHA-256 hash of the given input.
func Hash(input []byte) string {
	hash := sha256.Sum256(input)
	return hex.EncodeToString(hash[:])
}
