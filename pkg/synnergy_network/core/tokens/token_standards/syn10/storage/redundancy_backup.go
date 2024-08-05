package storage

import (
	"errors"
	"log"
	"sync"
	"time"
)

// RedundancyBackupManager manages data redundancy and backup processes for ensuring data availability and integrity.
type RedundancyBackupManager struct {
	mu             sync.RWMutex
	dataStorage    map[string][]byte
	backupStorage  map[string][]byte
	replicationMap map[string]bool
	backupInterval time.Duration
}

// NewRedundancyBackupManager initializes a new RedundancyBackupManager with default configurations.
func NewRedundancyBackupManager(backupInterval time.Duration) *RedundancyBackupManager {
	return &RedundancyBackupManager{
		dataStorage:    make(map[string][]byte),
		backupStorage:  make(map[string][]byte),
		replicationMap: make(map[string]bool),
		backupInterval: backupInterval,
	}
}

// StoreData securely stores data with redundancy and backup processes.
func (rbm *RedundancyBackupManager) StoreData(key string, data []byte) error {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	// Store data in primary storage
	rbm.dataStorage[key] = data

	// Mark data for replication
	rbm.replicationMap[key] = true

	return nil
}

// RetrieveData retrieves data from primary storage.
func (rbm *RedundancyBackupManager) RetrieveData(key string) ([]byte, error) {
	rbm.mu.RLock()
	defer rbm.mu.RUnlock()

	data, exists := rbm.dataStorage[key]
	if !exists {
		return nil, errors.New("data not found for key: " + key)
	}
	return data, nil
}

// ReplicateData ensures data redundancy by replicating data to backup storage.
func (rbm *RedundancyBackupManager) ReplicateData() {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	for key, needsReplication := range rbm.replicationMap {
		if needsReplication {
			data, exists := rbm.dataStorage[key]
			if exists {
				rbm.backupStorage[key] = data
				rbm.replicationMap[key] = false
				log.Printf("Data for key %s replicated to backup storage.\n", key)
			}
		}
	}
}

// RestoreData restores data from backup storage to primary storage.
func (rbm *RedundancyBackupManager) RestoreData(key string) error {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	data, exists := rbm.backupStorage[key]
	if !exists {
		return errors.New("backup not found for key: " + key)
	}

	rbm.dataStorage[key] = data
	log.Printf("Data for key %s restored from backup storage.\n", key)
	return nil
}

// RunBackupScheduler starts a scheduler to perform regular data replication.
func (rbm *RedundancyBackupManager) RunBackupScheduler() {
	ticker := time.NewTicker(rbm.backupInterval)
	go func() {
		for range ticker.C {
			rbm.ReplicateData()
		}
	}()
}

// ListBackupKeys lists all keys currently stored in backup storage.
func (rbm *RedundancyBackupManager) ListBackupKeys() []string {
	rbm.mu.RLock()
	defer rbm.mu.RUnlock()

	keys := make([]string, 0, len(rbm.backupStorage))
	for key := range rbm.backupStorage {
		keys = append(keys, key)
	}
	return keys
}

// RemoveBackupData removes specified data from the backup storage.
func (rbm *RedundancyBackupManager) RemoveBackupData(key string) error {
	rbm.mu.Lock()
	defer rbm.mu.Unlock()

	if _, exists := rbm.backupStorage[key]; exists {
		delete(rbm.backupStorage, key)
		log.Printf("Backup data for key %s removed.\n", key)
		return nil
	}

	return errors.New("no backup data found for key: " + key)
}

// BackupService manages data backup operations including periodic backups and disaster recovery.
type BackupService struct {
	RedundancyBackupManager *RedundancyBackupManager
	backupFrequency         time.Duration
}

// NewBackupService creates a new instance of BackupService.
func NewBackupService(manager *RedundancyBackupManager, frequency time.Duration) *BackupService {
	return &BackupService{
		RedundancyBackupManager: manager,
		backupFrequency:         frequency,
	}
}

// StartBackupProcess begins the periodic backup process.
func (bs *BackupService) StartBackupProcess() {
	ticker := time.NewTicker(bs.backupFrequency)
	go func() {
		for range ticker.C {
			bs.RedundancyBackupManager.ReplicateData()
		}
	}()
}

// ManualBackup allows manual initiation of the backup process.
func (bs *BackupService) ManualBackup() {
	bs.RedundancyBackupManager.ReplicateData()
}
