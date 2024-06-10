package backups

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// BackupService handles wallet backup and recovery
type BackupService struct {
	Passphrase string
}

// NewBackupService creates a new instance of BackupService
func NewBackupService(passphrase string) *BackupService {
	return &BackupService{
		Passphrase: passphrase,
	}
}

// GenerateMnemonic generates a 12-word mnemonic phrase
func (bs *BackupService) GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// EncryptMnemonic encrypts the mnemonic phrase using AES with Argon2 key derivation
func (bs *BackupService) EncryptMnemonic(mnemonic string) (string, error) {
	salt := generateSalt()

	key := argon2.IDKey([]byte(bs.Passphrase), salt, 1, 64*1024, 4, 32)

	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(mnemonic), nil)
	return fmt.Sprintf("%x:%x", salt, ciphertext), nil
}

// DecryptMnemonic decrypts the encrypted mnemonic phrase
func (bs *BackupService) DecryptMnemonic(encryptedMnemonic string) (string, error) {
	parts := splitString(encryptedMnemonic, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted mnemonic format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(bs.Passphrase), salt, 1, 64*1024, 4, 32)

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

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// StoreBackup stores the encrypted mnemonic in a secure location
func (bs *BackupService) StoreBackup(filename, encryptedMnemonic string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(encryptedMnemonic)
	return err
}

// RecoverFromBackup recovers the mnemonic from the stored backup
func (bs *BackupService) RecoverFromBackup(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	encryptedMnemonic, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return bs.DecryptMnemonic(string(encryptedMnemonic))
}

// generateSalt generates a new random salt
func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt
}

// splitString splits a string by a separator
func splitString(str, sep string) []string {
	var result []string
	part := ""
	for _, char := range str {
		if string(char) == sep {
			result = append(result, part)
			part = ""
		} else {
			part += string(char)
		}
	}
	result = append(result, part)
	return result
}
