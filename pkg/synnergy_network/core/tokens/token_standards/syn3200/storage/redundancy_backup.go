package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BackupRecord represents a record for backup
type BackupRecord struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// RedundancyBackup manages backup operations
type RedundancyBackup struct {
	backupPath string
	mu         sync.Mutex
}

// NewRedundancyBackup initializes a new redundancy backup manager
func NewRedundancyBackup(backupPath string) (*RedundancyBackup, error) {
	err := os.MkdirAll(backupPath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &RedundancyBackup{backupPath: backupPath}, nil
}

// BackupRecord creates a backup of the given data record
func (rb *RedundancyBackup) BackupRecord(record BackupRecord) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	record.Timestamp = time.Now()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	filename := filepath.Join(rb.backupPath, fmt.Sprintf("backup_%s.json", record.ID))
	return ioutil.WriteFile(filename, data, os.ModePerm)
}

// RestoreRecord restores a backup record by its ID
func (rb *RedundancyBackup) RestoreRecord(recordID string) (*BackupRecord, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	filename := filepath.Join(rb.backupPath, fmt.Sprintf("backup_%s.json", recordID))
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var record BackupRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// ListBackups lists all backup records
func (rb *RedundancyBackup) ListBackups() ([]BackupRecord, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	var backups []BackupRecord
	files, err := ioutil.ReadDir(rb.backupPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(rb.backupPath, file.Name()))
		if err != nil {
			return nil, err
		}
		var record BackupRecord
		err = json.Unmarshal(data, &record)
		if err != nil {
			return nil, err
		}
		backups = append(backups, record)
	}
	return backups, nil
}

// DeleteBackup deletes a backup record by its ID
func (rb *RedundancyBackup) DeleteBackup(recordID string) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	filename := filepath.Join(rb.backupPath, fmt.Sprintf("backup_%s.json", recordID))
	return os.Remove(filename)
}

// BackupAllRecords backs up all records from the database
func (rb *RedundancyBackup) BackupAllRecords(dm *DatabaseManager) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	records, err := dm.ListRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		backupRecord := BackupRecord{
			ID:        record.ID,
			Data:      record.Data,
			Timestamp: record.Timestamp,
		}
		err = rb.BackupRecord(backupRecord)
		if err != nil {
			return err
		}
	}
	return nil
}

// RestoreAllRecords restores all backup records to the database
func (rb *RedundancyBackup) RestoreAllRecords(dm *DatabaseManager) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	backups, err := rb.ListBackups()
	if err != nil {
		return err
	}
	for _, backup := range backups {
		dataRecord := DataRecord{
			ID:        backup.ID,
			Data:      backup.Data,
			Timestamp: backup.Timestamp,
		}
		err = dm.AddRecord(dataRecord)
		if err != nil {
			return err
		}
	}
	return nil
}
