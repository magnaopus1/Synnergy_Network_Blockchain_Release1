package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
)

// StorageManager manages the storage solutions for SYN3100 tokens
type StorageManager struct {
	databasePath string
	backupPath   string
	security     *security.SecurityManager
	encryptionKey []byte
	ledger       *ledger.TransactionLedger
}

// NewStorageManager initializes a new StorageManager instance
func NewStorageManager(databasePath, backupPath string, security *security.SecurityManager, encryptionKey []byte, ledger *ledger.TransactionLedger) (*StorageManager, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	manager := &StorageManager{
		databasePath: databasePath,
		backupPath:   backupPath,
		security:     security,
		encryptionKey: encryptionKey,
		ledger:       ledger,
	}

	return manager, nil
}

// SaveRecord saves a record to the database
func (sm *StorageManager) SaveRecord(record interface{}) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	encryptedData, err := sm.security.Encrypt(data, sm.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	err = os.WriteFile(sm.databasePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data to database: %w", err)
	}

	return nil
}

// LoadRecord loads a record from the database
func (sm *StorageManager) LoadRecord(record interface{}) error {
	encryptedData, err := os.ReadFile(sm.databasePath)
	if err != nil {
		return fmt.Errorf("failed to read data from database: %w", err)
	}

	data, err := sm.security.Decrypt(encryptedData, sm.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	err = json.Unmarshal(data, record)
	if err != nil {
		return fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return nil
}

// CreateBackup creates a backup of the current database
func (sm *StorageManager) CreateBackup() error {
	data, err := os.ReadFile(sm.databasePath)
	if err != nil {
		return fmt.Errorf("failed to read database: %w", err)
	}

	err = os.WriteFile(sm.backupPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	return nil
}

// RestoreBackup restores the database from the backup
func (sm *StorageManager) RestoreBackup() error {
	data, err := os.ReadFile(sm.backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	err = os.WriteFile(sm.databasePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	return nil
}

// ScheduleBackup schedules regular backups at the specified interval
func (sm *StorageManager) ScheduleBackup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := sm.CreateBackup()
			if err != nil {
				fmt.Printf("Error creating backup: %v\n", err)
			} else {
				fmt.Println("Backup created successfully")
			}
		}
	}
}

// CleanupOldBackups cleans up backups older than the specified retention period
func (sm *StorageManager) CleanupOldBackups(retentionPeriod time.Duration) error {
	files, err := os.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	cutoff := time.Now().Add(-retentionPeriod)
	for _, file := range files {
		if file.Type().IsRegular() && file.ModTime().Before(cutoff) {
			err := os.Remove(file.Name())
			if err != nil {
				return fmt.Errorf("failed to remove old backup: %w", err)
			}
		}
	}

	return nil
}
