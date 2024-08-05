package storage

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
)

// RedundancyManager manages the redundancy and backup operations for the SYN3400 token standard.
type RedundancyManager struct {
	mu             sync.Mutex
	primaryPath    string
	backupPaths    []string
	syncInterval   time.Duration
	lastSyncTime   time.Time
	syncInProgress bool
}

// NewRedundancyManager initializes a new RedundancyManager.
func NewRedundancyManager(primaryPath string, backupPaths []string, syncInterval time.Duration) *RedundancyManager {
	return &RedundancyManager{
		primaryPath:  primaryPath,
		backupPaths:  backupPaths,
		syncInterval: syncInterval,
	}
}

// StartAutoSync starts the automatic synchronization process at the specified interval.
func (rm *RedundancyManager) StartAutoSync() {
	ticker := time.NewTicker(rm.syncInterval)
	go func() {
		for range ticker.C {
			rm.SyncBackups()
		}
	}()
}

// SyncBackups synchronizes the primary database with all backup locations.
func (rm *RedundancyManager) SyncBackups() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.syncInProgress {
		return errors.New("sync already in progress")
	}

	rm.syncInProgress = true
	defer func() { rm.syncInProgress = false }()

	data, err := rm.readPrimaryData()
	if err != nil {
		return err
	}

	for _, backupPath := range rm.backupPaths {
		if err := rm.writeBackupData(backupPath, data); err != nil {
			event := events.NewEventLogging()
			event.LogEvent("BackupSyncFailed", err.Error())
		} else {
			event := events.NewEventLogging()
			event.LogEvent("BackupSynced", "Backup synchronized successfully at "+backupPath)
		}
	}

	rm.lastSyncTime = time.Now()
	return nil
}

// readPrimaryData reads the data from the primary database.
func (rm *RedundancyManager) readPrimaryData() ([]byte, error) {
	file, err := os.Open(rm.primaryPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := os.ReadFile(rm.primaryPath)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// writeBackupData writes the data to a backup location.
func (rm *RedundancyManager) writeBackupData(backupPath string, data []byte) error {
	file, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// GetLastSyncTime returns the last synchronization time.
func (rm *RedundancyManager) GetLastSyncTime() time.Time {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.lastSyncTime
}

// ManualBackup triggers a manual backup operation.
func (rm *RedundancyManager) ManualBackup() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := rm.readPrimaryData()
	if err != nil {
		return err
	}

	for _, backupPath := range rm.backupPaths {
		if err := rm.writeBackupData(backupPath, data); err != nil {
			event := events.NewEventLogging()
			event.LogEvent("ManualBackupFailed", err.Error())
			return err
		} else {
			event := events.NewEventLogging()
			event.LogEvent("ManualBackupSuccess", "Manual backup completed successfully at "+backupPath)
		}
	}

	rm.lastSyncTime = time.Now()
	return nil
}

// RestoreFromBackup restores the database from a specified backup file.
func (rm *RedundancyManager) RestoreFromBackup(backupPath string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}

	file, err := os.Create(rm.primaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	event := events.NewEventLogging()
	event.LogEvent("RestoreFromBackup", "Database restored from backup at "+backupPath)
	return nil
}
