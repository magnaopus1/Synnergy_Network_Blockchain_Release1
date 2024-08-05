package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// EncryptData encrypts the given data using AES-GCM with a specified key.
func EncryptData(data, key []byte) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the given base64-encoded ciphertext using AES-GCM with a specified key.
func DecryptData(ciphertext string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
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
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// HashData hashes the given data using SHA-256.
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// GenerateKey generates a key using Argon2 with the given password and salt.
func GenerateKey(password, salt []byte) []byte {
	return argon2.Key(password, salt, 3, 32*1024, 4, 32)
}

// GenerateScryptKey generates a key using scrypt with the given password and salt.
func GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 1<<15, 8, 1, 32)
}

// EncryptMetadata encrypts the metadata using the specified key.
func EncryptMetadata(metadata map[string]string, key []byte) (string, error) {
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	return EncryptData(data, key)
}

// DecryptMetadata decrypts the encrypted metadata using the specified key.
func DecryptMetadata(encryptedData string, key []byte) (map[string]string, error) {
	data, err := DecryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// EncryptTokenData encrypts the token data using the specified key.
func EncryptTokenData(tokenData interface{}, key []byte) (string, error) {
	data, err := json.Marshal(tokenData)
	if err != nil {
		return "", err
	}
	return EncryptData(data, key)
}

// DecryptTokenData decrypts the encrypted token data using the specified key.
func DecryptTokenData(encryptedData string, key []byte) (interface{}, error) {
	data, err := DecryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	var tokenData interface{}
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return nil, err
	}
	return tokenData, nil
}

// EncryptOwnershipRecord encrypts the ownership record using the specified key.
func EncryptOwnershipRecord(record interface{}, key []byte) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return EncryptData(data, key)
}

// DecryptOwnershipRecord decrypts the encrypted ownership record using the specified key.
func DecryptOwnershipRecord(encryptedData string, key []byte) (interface{}, error) {
	data, err := DecryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}

	var record interface{}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return record, nil
}
