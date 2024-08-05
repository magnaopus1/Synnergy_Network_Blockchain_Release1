package storage

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"io/ioutil"
)

// BackupManager manages the backup and redundancy of the database
type BackupManager struct {
	primaryDBPath  string
	backupDBPath   string
	security       *security.SecurityManager
	encryptionKey  []byte
}

// NewBackupManager initializes a new BackupManager instance
func NewBackupManager(primaryDBPath, backupDBPath string, security *security.SecurityManager, encryptionKey []byte) (*BackupManager, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	manager := &BackupManager{
		primaryDBPath: primaryDBPath,
		backupDBPath:  backupDBPath,
		security:      security,
		encryptionKey: encryptionKey,
	}

	return manager, nil
}

// CreateBackup creates a backup of the primary database
func (bm *BackupManager) CreateBackup() error {
	// Read the primary database
	data, err := ioutil.ReadFile(bm.primaryDBPath)
	if err != nil {
		return fmt.Errorf("failed to read primary database: %w", err)
	}

	// Encrypt the data
	encryptedData, err := bm.security.Encrypt(data, bm.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt database: %w", err)
	}

	// Write the encrypted data to the backup path
	err = ioutil.WriteFile(bm.backupDBPath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write backup database: %w", err)
	}

	return nil
}

// RestoreBackup restores the primary database from the backup
func (bm *BackupManager) RestoreBackup() error {
	// Read the backup database
	encryptedData, err := ioutil.ReadFile(bm.backupDBPath)
	if err != nil {
		return fmt.Errorf("failed to read backup database: %w", err)
	}

	// Decrypt the data
	data, err := bm.security.Decrypt(encryptedData, bm.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt database: %w", err)
	}

	// Write the decrypted data to the primary path
	err = ioutil.WriteFile(bm.primaryDBPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write primary database: %w", err)
	}

	return nil
}

// ScheduleBackup schedules regular backups at the specified interval
func (bm *BackupManager) ScheduleBackup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := bm.CreateBackup()
			if err != nil {
				fmt.Printf("Error creating backup: %v\n", err)
			} else {
				fmt.Println("Backup created successfully")
			}
		}
	}
}

// CleanupOldBackups cleans up backups older than the specified retention period
func (bm *BackupManager) CleanupOldBackups(retentionPeriod time.Duration) error {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	cutoff := time.Now().Add(-retentionPeriod)
	for _, file := range files {
		if file.ModTime().Before(cutoff) && file.Name() != bm.primaryDBPath && file.Name() != bm.backupDBPath {
			err := os.Remove(file.Name())
			if err != nil {
				return fmt.Errorf("failed to remove old backup: %w", err)
			}
		}
	}

	return nil
}
