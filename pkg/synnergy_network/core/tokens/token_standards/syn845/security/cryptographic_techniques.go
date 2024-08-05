package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
)

// Argon2Parameters holds the parameters for Argon2 key derivation
type Argon2Parameters struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Salt    []byte
}

// ScryptParameters holds the parameters for Scrypt key derivation
type ScryptParameters struct {
	N       int
	R       int
	P       int
	Salt    []byte
	KeyLen  int
}

// GenerateSalt generates a random salt of given length
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKeyArgon2 derives a key using Argon2
func DeriveKeyArgon2(password string, params Argon2Parameters) ([]byte, error) {
	key := argon2.IDKey([]byte(password), params.Salt, params.Time, params.Memory, params.Threads, 32)
	return key, nil
}

// DeriveKeyScrypt derives a key using Scrypt
func DeriveKeyScrypt(password string, params ScryptParameters) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), params.Salt, params.N, params.R, params.P, params.KeyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts data using AES-GCM
func Encrypt(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts AES-GCM encrypted data
func Decrypt(encryptedData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:aesGCM.NonceSize()], data[aesGCM.NonceSize():]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
