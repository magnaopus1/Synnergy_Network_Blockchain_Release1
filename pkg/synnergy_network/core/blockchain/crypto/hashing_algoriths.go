package crypto

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Hashing provides various hashing functionalities
type Hashing struct{}

// NewHashing creates a new Hashing instance
func NewHashing() *Hashing {
	return &Hashing{}
}

// SHA256Hash hashes data using SHA-256
func (h *Hashing) SHA256Hash(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// ScryptHash hashes data using Scrypt with given parameters
func (h *Hashing) ScryptHash(data, salt []byte, N, r, p, keyLen int) (string, error) {
	hash, err := scrypt.Key(data, salt, N, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// Argon2Hash hashes data using Argon2 with given parameters
func (h *Hashing) Argon2Hash(data, salt []byte, time, memory uint32, threads uint8, keyLen uint32) string {
	hash := argon2.IDKey(data, salt, time, memory, threads, keyLen)
	return hex.EncodeToString(hash)
}

// VerifySHA256Hash verifies data against a given SHA-256 hash
func (h *Hashing) VerifySHA256Hash(data []byte, expectedHash string) bool {
	return h.SHA256Hash(data) == expectedHash
}

// VerifyScryptHash verifies data against a given Scrypt hash
func (h *Hashing) VerifyScryptHash(data, salt []byte, N, r, p, keyLen int, expectedHash string) (bool, error) {
	hash, err := h.ScryptHash(data, salt, N, r, p, keyLen)
	if err != nil {
		return false, err
	}
	return hash == expectedHash, nil
}

// VerifyArgon2Hash verifies data against a given Argon2 hash
func (h *Hashing) VerifyArgon2Hash(data, salt []byte, time, memory uint32, threads uint8, keyLen uint32, expectedHash string) bool {
	return h.Argon2Hash(data, salt, time, memory, threads, keyLen) == expectedHash
}

// GenerateSalt generates a random salt of specified length
func (h *Hashing) GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
