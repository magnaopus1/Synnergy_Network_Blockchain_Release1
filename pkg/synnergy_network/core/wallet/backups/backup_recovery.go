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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/scrypt"
)

// BackupManager handles wallet backup and recovery
type BackupManager struct {
	Passphrase string
	BackupDir  string
}

// NewBackupManager creates a new instance of BackupManager
func NewBackupManager(passphrase, backupDir string) *BackupManager {
	return &BackupManager{
		Passphrase: passphrase,
		BackupDir:  backupDir,
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
	file, err := os.Create(filepath.Join(bm.BackupDir, filename))
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(encryptedMnemonic)
	return err
}

// RecoverFromBackup recovers the mnemonic from the stored backup
func (bm *BackupManager) RecoverFromBackup(filename string) (string, error) {
	file, err := os.Open(filepath.Join(bm.BackupDir, filename))
	if err != nil {
		return "", err
	}
	defer file.Close()

	encryptedMnemonic, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return bm.DecryptMnemonic(string(encryptedMnemonic))
}

// BackupFile creates a backup of the specified file
func (bm *BackupManager) BackupFile(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	encryptedData, err := bm.encryptData(data)
	if err != nil {
		return "", err
	}

	backupFilePath := filepath.Join(bm.BackupDir, filepath.Base(filePath)+".bak")
	err = ioutil.WriteFile(backupFilePath, encryptedData, 0644)
	if err != nil {
		return "", err
	}

	return backupFilePath, nil
}

// RestoreFile restores a backup to the specified file path
func (bm *BackupManager) RestoreFile(backupFilePath, restoreFilePath string) error {
	data, err := ioutil.ReadFile(backupFilePath)
	if err != nil {
		return err
	}

	decryptedData, err := bm.decryptData(data)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(restoreFilePath, decryptedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// encryptData encrypts the given data using AES encryption with the derived passphrase key
func (bm *BackupManager) encryptData(data []byte) ([]byte, error) {
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(bm.Passphrase), salt, 32768, 8, 1, 32)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// decryptData decrypts the given data using AES decryption with the derived passphrase key
func (bm *BackupManager) decryptData(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid data format")
	}

	salt, ciphertext := data[:16], data[16:]

	key, err := scrypt.Key([]byte(bm.Passphrase), salt, 32768, 8, 1, 32)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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
	return []string{str[:64], str[65:]}
}
