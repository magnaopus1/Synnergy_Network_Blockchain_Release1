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
	"golang.org/x/crypto/scrypt"
)

// BackupManager handles wallet backup and recovery
type BackupManager struct {
	Passphrase string
}

// NewBackupManager creates a new instance of BackupManager
func NewBackupManager(passphrase string) *BackupManager {
	return &BackupManager{
		Passphrase: passphrase,
	}
}

// GenerateMnemonic generates a 12-word mnemonic phrase
func (bm *BackupManager) GenerateMnemonic() (string, error) {
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

// EncryptMnemonic encrypts the mnemonic phrase using AES
func (bm *BackupManager) EncryptMnemonic(mnemonic string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(bm.Passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

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
func (bm *BackupManager) DecryptMnemonic(encryptedMnemonic string) (string, error) {
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

	key, err := scrypt.Key([]byte(bm.Passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

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
func (bm *BackupManager) StoreBackup(filename, encryptedMnemonic string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(encryptedMnemonic)
	return err
}

// RecoverFromBackup recovers the mnemonic from the stored backup
func (bm *BackupManager) RecoverFromBackup(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	encryptedMnemonic, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return bm.DecryptMnemonic(string(encryptedMnemonic))
}

// generateSalt generates a new random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// splitString splits a string by a separator
func splitString(str, sep string) []string {
	var result []string
	for _, part := range []byte(str) {
		result = append(result, string(part))
	}
	return result
}
