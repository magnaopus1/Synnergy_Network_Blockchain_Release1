package storage

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/you/yourproject/pkg/cryptography"
)

// StorageManager handles the storage operations for bill tokens
type StorageManager struct {
	storagePath string
	mu          sync.Mutex
}

// NewStorageManager initializes a new storage manager
func NewStorageManager(storagePath string) (*StorageManager, error) {
	err := os.MkdirAll(storagePath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &StorageManager{storagePath: storagePath}, nil
}

// StoreRecord stores a data record securely
func (sm *StorageManager) StoreRecord(record DataRecord) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := cryptography.EncryptData([]byte(record.Data), generateKey(record.ID))
	if err != nil {
		return err
	}

	record.Data = string(encryptedData)
	record.Timestamp = time.Now()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	filename := filepath.Join(sm.storagePath, record.ID+".json")
	return ioutil.WriteFile(filename, data, os.ModePerm)
}

// RetrieveRecord retrieves a data record securely
func (sm *StorageManager) RetrieveRecord(recordID string) (*DataRecord, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	filename := filepath.Join(sm.storagePath, recordID+".json")
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var record DataRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}

	decryptedData, err := cryptography.DecryptData([]byte(record.Data), generateKey(record.ID))
	if err != nil {
		return nil, err
	}

	record.Data = string(decryptedData)
	return &record, nil
}

// ListRecords lists all stored data records
func (sm *StorageManager) ListRecords() ([]DataRecord, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var records []DataRecord
	files, err := ioutil.ReadDir(sm.storagePath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(sm.storagePath, file.Name()))
		if err != nil {
			return nil, err
		}

		var record DataRecord
		err = json.Unmarshal(data, &record)
		if err != nil {
			return nil, err
		}
		decryptedData, err := cryptography.DecryptData([]byte(record.Data), generateKey(record.ID))
		if err != nil {
			return nil, err
		}
		record.Data = string(decryptedData)
		records = append(records, record)
	}
	return records, nil
}

// DeleteRecord deletes a data record by its ID
func (sm *StorageManager) DeleteRecord(recordID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	filename := filepath.Join(sm.storagePath, recordID+".json")
	return os.Remove(filename)
}

// generateKey generates a key for encryption and decryption
func generateKey(recordID string) []byte {
	key, _ := scrypt.Key([]byte(recordID), []byte("somesalt"), 32768, 8, 1, 32)
	return key
}

// DataRecord represents a data record to be stored
type DataRecord struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// RedundancyBackupManager manages backup operations
type RedundancyBackupManager struct {
	backupPath string
	mu         sync.Mutex
}

// NewRedundancyBackupManager initializes a new redundancy backup manager
func NewRedundancyBackupManager(backupPath string) (*RedundancyBackupManager, error) {
	err := os.MkdirAll(backupPath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &RedundancyBackupManager{backupPath: backupPath}, nil
}

// BackupRecord creates a backup of the given data record
func (rbm *RedundancyBackupManager) BackupRecord(record DataRecord) error {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	record.Timestamp = time.Now()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	filename := filepath.Join(rbm.backupPath, "backup_"+record.ID+".json")
	return ioutil.WriteFile(filename, data, os.ModePerm)
}

// RestoreRecord restores a backup record by its ID
func (rbm *RedundancyBackupManager) RestoreRecord(recordID string) (*DataRecord, error) {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	filename := filepath.Join(rbm.backupPath, "backup_"+recordID+".json")
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var record DataRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// ListBackups lists all backup records
func (rbm *RedundancyBackupManager) ListBackups() ([]DataRecord, error) {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	var backups []DataRecord
	files, err := ioutil.ReadDir(rbm.backupPath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(rbm.backupPath, file.Name()))
		if err != nil {
			return nil, err
		}

		var record DataRecord
		err = json.Unmarshal(data, &record)
		if err != nil {
			return nil, err
		}
		backups = append(backups, record)
	}
	return backups, nil
}

// DeleteBackup deletes a backup record by its ID
func (rbm *RedundancyBackupManager) DeleteBackup(recordID string) error {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	filename := filepath.Join(rbm.backupPath, "backup_"+recordID+".json")
	return os.Remove(filename)
}
