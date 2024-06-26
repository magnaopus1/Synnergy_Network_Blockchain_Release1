package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Salt            = "select-a-unique-salt"
	ScryptN         = 16384
	ScryptR         = 8
	ScryptP         = 1
	ScryptKeyLength = 32
	Argon2Time      = 1
	Argon2Memory    = 64 * 1024
	Argon2Threads   = 4
	Argon2KeyLength = 32
)

// EncryptDataWithArgon2 encrypts data using AES-256-GCM with a key derived from Argon2.
func EncryptDataWithArgon2(data []byte) (string, error) {
	salt := []byte(Salt)
	key := argon2.IDKey(data, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLength)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := aesGCM.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(encrypted), nil
}

// DecryptDataWithArgon2 decrypts data encrypted by EncryptDataWithArgon2.
func DecryptDataWithArgon2(encryptedData string) ([]byte, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	salt := []byte(Salt)
	key := argon2.IDKey(data, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLength)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("encrypted data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptDataWithScrypt uses Scrypt for key derivation and AES-256-GCM for encryption.
func EncryptDataWithScrypt(data []byte) (string, error) {
	salt := []byte(Salt)
	key, err := scrypt.Key(data, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLength)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := aesGCM.Seal(nonce, nonce, data, nil)
	return hex.EncodeToString(encrypted), nil
}

// DecryptDataWithScrypt decrypts data encrypted by EncryptDataWithScrypt.
func DecryptDataWithScrypt(encryptedData string) ([]byte, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	salt := []byte(Salt)
	key, err := scrypt.Key(data, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLength)
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

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("encrypted data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	// Example usage of encryption and decryption
	testData := []byte("secret data for encryption")
	encrypted, err := EncryptDataWithArgon2(testData)
	if err != nil {
		log.Fatalf("Encryption failed: %s", err)
	}

	decrypted, err := DecryptDataWithArgon2(encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %s", err)
	}

	fmt.Println("Original:", string(testData))
	fmt.Println("Decrypted:", string(decrypted))
}
