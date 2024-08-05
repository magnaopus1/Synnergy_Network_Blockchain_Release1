package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// GenerateSalt generates a new random salt
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// HashPassword hashes a password using Argon2
func HashPassword(password string, salt []byte) string {
	hash := argon2.Key([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLength)
	return base64.StdEncoding.EncodeToString(hash)
}

// Encrypt encrypts plain text using AES with Scrypt key derivation
func Encrypt(plainText, password string) (string, error) {
	salt, err := GenerateSalt(SaltSize)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, AESKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plainText))

	return base64.StdEncoding.EncodeToString(append(salt, ciphertext...)), nil
}

// Decrypt decrypts cipher text using AES with Scrypt key derivation
func Decrypt(cipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("failed to decode cipher text: %v", err)
	}

	salt := data[:SaltSize]
	ciphertext := data[SaltSize:]

	key, err := scrypt.Key([]byte(password), salt, ScryptN, ScryptR, ScryptP, AESKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// HashSHA256 generates a SHA-256 hash of the input
func HashSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// GenerateUUID generates a random UUID
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %v", err)
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// LogAndPanic logs the error and panics
func LogAndPanic(err error) {
	if err != nil {
		log.Panicf("Critical error: %v", err)
	}
}
