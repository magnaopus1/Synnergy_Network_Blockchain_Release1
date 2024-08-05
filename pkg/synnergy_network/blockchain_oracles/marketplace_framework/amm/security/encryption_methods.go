package encryption_methods

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// EncryptionMethod defines the encryption method to be used
type EncryptionMethod string

const (
	AES_Scrypt EncryptionMethod = "AES_Scrypt"
	AES_Argon2 EncryptionMethod = "AES_Argon2"
)

// Encryptor defines the interface for encryption and decryption methods
type Encryptor interface {
	Encrypt(plainText string, secretKey string) (string, error)
	Decrypt(cipherText string, secretKey string) (string, error)
}

// AESEncryptorScrypt represents an AES encryptor using Scrypt for key derivation
type AESEncryptorScrypt struct{}

// Encrypt encrypts the plaintext using AES with a key derived from Scrypt
func (a *AESEncryptorScrypt) Encrypt(plainText string, secretKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the ciphertext using AES with a key derived from Scrypt
func (a *AESEncryptorScrypt) Decrypt(cipherText string, secretKey string) (string, error) {
	parts := split(cipherText, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted message format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(secretKey), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// AESEncryptorArgon2 represents an AES encryptor using Argon2 for key derivation
type AESEncryptorArgon2 struct{}

// Encrypt encrypts the plaintext using AES with a key derived from Argon2
func (a *AESEncryptorArgon2) Encrypt(plainText string, secretKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(secretKey), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the ciphertext using AES with a key derived from Argon2
func (a *AESEncryptorArgon2) Decrypt(cipherText string, secretKey string) (string, error) {
	parts := split(cipherText, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted message format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(secretKey), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// HMACSHA256 generates an HMAC using SHA-256
func HMACSHA256(message, secretKey string) string {
	key := []byte(secretKey)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// Utility functions
func split(s string, sep string) []string {
	var parts []string
	var buf []rune
	for _, r := range s {
		if string(r) == sep {
			parts = append(parts, string(buf))
			buf = []rune{}
		} else {
			buf = append(buf, r)
		}
	}
	parts = append(parts, string(buf))
	return parts
}

// GenerateRandomBytes generates random bytes of the given length
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// HashPassword hashes a password using Argon2
func HashPassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash using Argon2
func VerifyPassword(password, salt, hash string) bool {
	return HashPassword(password, salt) == hash
}

// LogEncryptionMethod logs the encryption method being used
func LogEncryptionMethod(method EncryptionMethod) {
	log.Printf("Using encryption method: %s", method)
}
