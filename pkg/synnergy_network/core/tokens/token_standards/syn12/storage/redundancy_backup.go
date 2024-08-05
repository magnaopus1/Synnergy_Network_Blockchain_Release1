package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
)

// RedundancyBackupManager handles data backup and redundancy operations.
type RedundancyBackupManager struct {
	backupDir string
}

// NewRedundancyBackupManager creates a new instance of RedundancyBackupManager.
func NewRedundancyBackupManager(backupDir string) (*RedundancyBackupManager, error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %v", err)
	}
	return &RedundancyBackupManager{backupDir: backupDir}, nil
}

// BackupDatabase creates a backup of the database file.
func (rbm *RedundancyBackupManager) BackupDatabase(dbFilePath string) error {
	backupFilePath := filepath.Join(rbm.backupDir, fmt.Sprintf("backup_%v.sql", time.Now().Unix()))
	if err := copyFile(dbFilePath, backupFilePath); err != nil {
		return fmt.Errorf("failed to backup database: %v", err)
	}
	log.Printf("Database backed up to %s", backupFilePath)
	return nil
}

// EncryptAndBackupFile encrypts a file and then stores it as a backup.
func (rbm *RedundancyBackupManager) EncryptAndBackupFile(filePath, key string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	encryptedData, err := encryptData(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	backupFilePath := filepath.Join(rbm.backupDir, fmt.Sprintf("encrypted_backup_%v", time.Now().Unix()))
	if err := ioutil.WriteFile(backupFilePath, encryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted backup: %v", err)
	}
	log.Printf("Encrypted backup created at %s", backupFilePath)
	return nil
}

// RestoreFromBackup restores the database from the latest backup.
func (rbm *RedundancyBackupManager) RestoreFromBackup() error {
	backupFiles, err := ioutil.ReadDir(rbm.backupDir)
	if err != nil {
		return fmt.Errorf("failed to list backup files: %v", err)
	}

	if len(backupFiles) == 0 {
		return errors.New("no backup files available")
	}

	// Assuming the backup files are named in such a way that sorting by name orders them chronologically
	latestBackup := backupFiles[len(backupFiles)-1]
	backupFilePath := filepath.Join(rbm.backupDir, latestBackup.Name())

	// The destination path where the backup will be restored
	destFilePath := "path_to_restore" // Set the actual path to restore
	if err := copyFile(backupFilePath, destFilePath); err != nil {
		return fmt.Errorf("failed to restore from backup: %v", err)
	}
	log.Printf("Database restored from %s", backupFilePath)
	return nil
}

// copyFile copies a file from source to destination.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	return nil
}

// encryptData encrypts data using AES.
func encryptData(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES.
func decryptData(ciphertext []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CleanupOldBackups removes backups older than the specified duration.
func (rbm *RedundancyBackupManager) CleanupOldBackups(olderThan time.Duration) error {
	files, err := ioutil.ReadDir(rbm.backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %v", err)
	}

	cutoff := time.Now().Add(-olderThan)
	for _, file := range files {
		if file.ModTime().Before(cutoff) {
			err := os.Remove(filepath.Join(rbm.backupDir, file.Name()))
			if err != nil {
				log.Printf("Failed to remove old backup file %s: %v", file.Name(), err)
			}
		}
	}
	return nil
}
