package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// EncryptData encrypts data using Scrypt for key derivation and AES for encryption.
func EncryptData(data, passphrase string) (string, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	ciphertext, err := encryptAES([]byte(data), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %v", err)
	}

	encryptedData := append(salt, ciphertext...)
	return hex.EncodeToString(encryptedData), nil
}

// DecryptData decrypts data using Scrypt for key derivation and AES for decryption.
func DecryptData(data, passphrase string) (string, error) {
	encryptedData, err := hex.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	if len(encryptedData) < 32 {
		return "", errors.New("invalid encrypted data")
	}

	salt := encryptedData[:32]
	ciphertext := encryptedData[32:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive key: %v", err)
	}

	plaintext, err := decryptAES(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return string(plaintext), nil
}

// EncryptMnemonic encrypts the mnemonic phrase with a passphrase.
func EncryptMnemonic(mnemonic, passphrase string) (string, error) {
	return EncryptData(mnemonic, passphrase)
}

// DecryptMnemonic decrypts the mnemonic phrase with a passphrase.
func DecryptMnemonic(encryptedMnemonic, passphrase string) (string, error) {
	return DecryptData(encryptedMnemonic, passphrase)
}

// HashPassword hashes a password using Argon2.
func HashPassword(password string, salt []byte) (string, error) {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	hashWithSalt := append(salt, hash...)
	return hex.EncodeToString(hashWithSalt), nil
}

// VerifyPassword verifies a hashed password using Argon2.
func VerifyPassword(hashedPassword, password string) (bool, error) {
	hashWithSalt, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false, fmt.Errorf("failed to decode hashed password: %v", err)
	}

	salt := hashWithSalt[:32]
	hash := hashWithSalt[32:]
	computedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return sha256.Sum256(computedHash) == sha256.Sum256(hash), nil
}

// encryptAES encrypts data using AES-GCM.
func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAES decrypts data using AES-GCM.
func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}
