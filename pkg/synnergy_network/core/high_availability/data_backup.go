package data_backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"synnergy_network/cryptography/keys"
	"synnergy_network/file_storage/data_replication"
	"synnergy_network/file_storage/storage_allocation"
	"synnergy_network/high_availability/utils"
	"synnergy_network/ledger"
	"synnergy_network/network/p2p"
	"synnergy_network/utils/logging"
)

// NewAsynchronousBackupManager initializes a new AsynchronousBackupManager
func NewAsynchronousBackupManager(ledger *ledger.Ledger, p2pNetwork *p2p.Network, keyPair *keys.KeyPair) *AsynchronousBackupManager {
	return &AsynchronousBackupManager{
		dataReplicator: data_replication.NewDataReplicator(),
		storageManager: storage_allocation.NewStorageManager(),
		p2pNetwork:     p2pNetwork,
		ledger:         ledger,
		keyPair:        keyPair,
	}
}

// EncryptData encrypts the data using AES
func (abm *AsynchronousBackupManager) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(abm.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (abm *AsynchronousBackupManager) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(abm.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// PerformBackup performs an asynchronous backup of the blockchain data
func (abm *AsynchronousBackupManager) PerformBackup() error {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	data, err := abm.ledger.GetData()
	if err != nil {
		return err
	}

	// Encrypt data before replication
	encryptedData, err := abm.EncryptData(data)
	if err != nil {
		return err
	}

	// Perform asynchronous data replication
	go func() {
		err := abm.dataReplicator.ReplicateAsynchronously(encryptedData)
		if err != nil {
			logging.LogError("Replication failed: %v", err)
		} else {
			logging.LogInfo("Replication completed successfully")
		}
	}()

	return nil
}

// VerifyBackupIntegrity verifies the integrity of backups
func (abm *AsynchronousBackupManager) VerifyBackupIntegrity(data []byte) (bool, error) {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	// Generate hash of the original data
	hash := sha256.Sum256(data)
	originalHash := hex.EncodeToString(hash[:])

	// Retrieve replicated data and generate its hash
	replicatedData, err := abm.dataReplicator.Retrieve(data)
	if err != nil {
		return false, err
	}

	replicatedHash := sha256.Sum256(replicatedData)
	if originalHash != hex.EncodeToString(replicatedHash[:]) {
		return false, errors.New("data integrity check failed")
	}

	return true, nil
}

// AdjustBackupStrategy adjusts the backup strategy based on network conditions
func (abm *AsynchronousBackupManager) AdjustBackupStrategy(strategy string) error {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	// Adjust storage allocation based on the backup strategy
	err := abm.storageManager.AdjustAllocation(strategy)
	if err != nil {
		return err
	}

	return nil
}

// ScheduleBackups schedules regular data backups
func (abm *AsynchronousBackupManager) ScheduleBackups(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := abm.PerformBackup()
				if err != nil {
					logging.LogError("Backup failed: %v", err)
				} else {
					logging.LogInfo("Backup completed successfully")
				}
			}
		}
	}()
}

// RecoverData recovers data from backups
func (abm *AsynchronousBackupManager) RecoverData() ([]byte, error) {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	data, err := abm.dataReplicator.RetrieveBackup()
	if err != nil {
		return nil, err
	}

	// Decrypt data after retrieval
	decryptedData, err := abm.DecryptData(data)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// HandleNodeFailure manages node failure scenarios
func (abm *AsynchronousBackupManager) HandleNodeFailure(nodeID string) {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	// Log node failure event
	logging.LogWarning("Node %s failed, initiating failover", nodeID)

	// Redistribute responsibilities to healthy nodes
	abm.p2pNetwork.ReassignNodeTasks(nodeID)

	// Adjust backup strategy if needed
	err := abm.AdjustBackupStrategy(abm.storageManager.GetOptimalBackupStrategy())
	if err != nil {
		logging.LogError("Failed to adjust backup strategy: %v", err)
	}
}

// PerformMaintenance performs regular maintenance tasks for backups
func (abm *AsynchronousBackupManager) PerformMaintenance() {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	// Run maintenance tasks
	err := abm.storageManager.CleanUp()
	if err != nil {
		logging.LogError("Maintenance cleanup failed: %v", err)
	}

	// Verify backup integrity periodically
	data, err := abm.ledger.GetData()
	if err != nil {
		logging.LogError("Failed to retrieve ledger data: %v", err)
		return
	}

	valid, err := abm.VerifyBackupIntegrity(data)
	if err != nil || !valid {
		logging.LogError("Backup integrity verification failed: %v", err)
	}
}

// EnsureNodeSynchronization ensures all nodes are synchronized
func (abm *AsynchronousBackupManager) EnsureNodeSynchronization() {
	abm.mu.Lock()
	defer abm.mu.Unlock()

	err := abm.p2pNetwork.SynchronizeNodes()
	if err != nil {
		logging.LogError("Node synchronization failed: %v", err)
	}
}

// NewBackupScheduler initializes a new BackupScheduler
func NewBackupScheduler(ledger *ledger.Ledger, p2pNetwork *p2p.Network, keyPair *keys.KeyPair) *BackupScheduler {
	return &BackupScheduler{
		dataReplicator: data_replication.NewDataReplicator(),
		storageManager: storage_allocation.NewStorageManager(),
		p2pNetwork:     p2pNetwork,
		ledger:         ledger,
		keyPair:        keyPair,
	}
}

// EncryptData encrypts the data using AES
func (bs *BackupScheduler) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(bs.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (bs *BackupScheduler) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(bs.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ScheduleBackup schedules regular data backups
func (bs *BackupScheduler) ScheduleBackup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := bs.PerformBackup()
				if err != nil {
					logging.LogError("Backup failed: %v", err)
				} else {
					logging.LogInfo("Backup completed successfully")
				}
			}
		}
	}()
}

// PerformBackup performs a backup of the blockchain data
func (bs *BackupScheduler) PerformBackup() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	data, err := bs.ledger.GetData()
	if err != nil {
		return err
	}

	// Encrypt data before replication
	encryptedData, err := bs.EncryptData(data)
	if err != nil {
		return err
	}

	// Perform asynchronous data replication
	go func() {
		err := bs.dataReplicator.ReplicateAsynchronously(encryptedData)
		if err != nil {
			logging.LogError("Replication failed: %v", err)
		} else {
			logging.LogInfo("Replication completed successfully")
		}
	}()

	return nil
}

// VerifyBackupIntegrity verifies the integrity of backups
func (bs *BackupScheduler) VerifyBackupIntegrity(data []byte) (bool, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Generate hash of the original data
	hash := sha256.Sum256(data)
	originalHash := hex.EncodeToString(hash[:])

	// Retrieve replicated data and generate its hash
	replicatedData, err := bs.dataReplicator.Retrieve(data)
	if err != nil {
		return false, err
	}

	replicatedHash := sha256.Sum256(replicatedData)
	if originalHash != hex.EncodeToString(replicatedHash[:]) {
		return false, errors.New("data integrity check failed")
	}

	return true, nil
}

// RecoverData recovers data from backups
func (bs *BackupScheduler) RecoverData() ([]byte, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	data, err := bs.dataReplicator.RetrieveBackup()
	if err != nil {
		return nil, err
	}

	// Decrypt data after retrieval
	decryptedData, err := bs.DecryptData(data)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// HandleNodeFailure manages node failure scenarios
func (bs *BackupScheduler) HandleNodeFailure(nodeID string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Log node failure event
	logging.LogWarning("Node %s failed, initiating failover", nodeID)

	// Redistribute responsibilities to healthy nodes
	bs.p2pNetwork.ReassignNodeTasks(nodeID)

	// Adjust backup strategy if needed
	err := bs.AdjustBackupStrategy(bs.storageManager.GetOptimalBackupStrategy())
	if err != nil {
		logging.LogError("Failed to adjust backup strategy: %v", err)
	}
}

// AdjustBackupStrategy adjusts the backup strategy based on network conditions
func (bs *BackupScheduler) AdjustBackupStrategy(strategy string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Adjust storage allocation based on the backup strategy
	err := bs.storageManager.AdjustAllocation(strategy)
	if err != nil {
		return err
	}

	return nil
}

// PerformMaintenance performs regular maintenance tasks for backups
func (bs *BackupScheduler) PerformMaintenance() {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Run maintenance tasks
	err := bs.storageManager.CleanUp()
	if err != nil {
		logging.LogError("Maintenance cleanup failed: %v", err)
	}

	// Verify backup integrity periodically
	data, err := bs.ledger.GetData()
	if err != nil {
		logging.LogError("Failed to retrieve ledger data: %v", err)
		return
	}

	valid, err := bs.VerifyBackupIntegrity(data)
	if err != nil || !valid {
		logging.LogError("Backup integrity verification failed: %v", err)
	}
}

// EnsureNodeSynchronization ensures all nodes are synchronized
func (bs *BackupScheduler) EnsureNodeSynchronization() {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	err := bs.p2pNetwork.SynchronizeNodes()
	if err != nil {
		logging.LogError("Node synchronization failed: %v", err)
	}
}

// NewSnapshotManager initializes a new SnapshotManager
func NewSnapshotManager(ledger *ledger.Ledger, p2pNetwork *p2p.Network, keyPair *keys.KeyPair, snapshotDir string) *SnapshotManager {
	return &SnapshotManager{
		dataReplicator: data_replication.NewDataReplicator(),
		storageManager: storage_allocation.NewStorageManager(),
		p2pNetwork:     p2pNetwork,
		ledger:         ledger,
		keyPair:        keyPair,
		snapshotDir:    snapshotDir,
	}
}

// EncryptData encrypts the data using AES
func (sm *SnapshotManager) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (sm *SnapshotManager) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CreateSnapshot creates a snapshot of the current ledger state
func (sm *SnapshotManager) CreateSnapshot() (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := sm.ledger.GetData()
	if err != nil {
		return "", err
	}

	// Encrypt data before saving snapshot
	encryptedData, err := sm.EncryptData(data)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102150405")
	snapshotPath := filepath.Join(sm.snapshotDir, "snapshot_"+timestamp+".dat")

	err = os.WriteFile(snapshotPath, encryptedData, 0644)
	if err != nil {
		return "", err
	}

	logging.LogInfo("Snapshot created: %s", snapshotPath)
	return snapshotPath, nil
}

// LoadSnapshot loads a snapshot from the given file path
func (sm *SnapshotManager) LoadSnapshot(snapshotPath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}

	data, err := sm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return sm.ledger.SetData(data)
}

// ScheduleSnapshots schedules regular snapshot creation
func (sm *SnapshotManager) ScheduleSnapshots(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				_, err := sm.CreateSnapshot()
				if err != nil {
					logging.LogError("Failed to create snapshot: %v", err)
				}
			}
		}
	}()
}

// VerifySnapshotIntegrity verifies the integrity of a snapshot
func (sm *SnapshotManager) VerifySnapshotIntegrity(snapshotPath string) (bool, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := os.ReadFile(snapshotPath)
	if err != nil {
		return false, err
	}

	data, err := sm.DecryptData(encryptedData)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(data)
	originalHash := hex.EncodeToString(hash[:])

	// Retrieve replicated data and generate its hash
	replicatedData, err := sm.dataReplicator.Retrieve(data)
	if err != nil {
		return false, err
	}

	replicatedHash := sha256.Sum256(replicatedData)
	if originalHash != hex.EncodeToString(replicatedHash[:]) {
		return false, errors.New("data integrity check failed")
	}

	return true, nil
}

// PerformMaintenance performs regular maintenance tasks for snapshots
func (sm *SnapshotManager) PerformMaintenance() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Run maintenance tasks
	err := sm.storageManager.CleanUp()
	if err != nil {
		logging.LogError("Maintenance cleanup failed: %v", err)
	}

	// Verify snapshot integrity periodically
	snapshots, err := filepath.Glob(filepath.Join(sm.snapshotDir, "snapshot_*.dat"))
	if err != nil {
		logging.LogError("Failed to list snapshots: %v", err)
		return
	}

	for _, snapshot := range snapshots {
		valid, err := sm.VerifySnapshotIntegrity(snapshot)
		if err != nil || !valid {
			logging.LogError("Snapshot integrity verification failed: %v", err)
		}
	}
}

// RecoverFromSnapshot recovers the ledger from a snapshot
func (sm *SnapshotManager) RecoverFromSnapshot(snapshotPath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := os.ReadFile(snapshotPath)
	if err != nil {
		return err
	}

	data, err := sm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return sm.ledger.SetData(data)
}

// NewBackupVerifier initializes a new BackupVerifier
func NewBackupVerifier(ledger *ledger.Ledger, keyPair *keys.KeyPair, snapshotDir string) *BackupVerifier {
	return &BackupVerifier{
		ledger:      ledger,
		keyPair:     keyPair,
		snapshotDir: snapshotDir,
	}
}

// ComputeHash computes the SHA-256 hash of the given data
func (bv *BackupVerifier) ComputeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyBackupFile verifies the integrity of a backup file by comparing its hash
func (bv *BackupVerifier) VerifyBackupFile(filePath string) (bool, error) {
	bv.mu.Lock()
	defer bv.mu.Unlock()

	// Read the backup file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	// Decrypt the data
	decryptedData, err := bv.DecryptData(data)
	if err != nil {
		return false, err
	}

	// Compute the hash of the decrypted data
	hash := bv.ComputeHash(decryptedData)

	// Retrieve the original ledger data
	ledgerData, err := bv.ledger.GetData()
	if err != nil {
		return false, err
	}

	// Compute the hash of the ledger data
	originalHash := bv.ComputeHash(ledgerData)

	// Compare the hashes
	if hash != originalHash {
		return false, errors.New("backup verification failed: hashes do not match")
	}

	return true, nil
}

// VerifyAllBackups verifies the integrity of all backup files in the snapshot directory
func (bv *BackupVerifier) VerifyAllBackups() error {
	bv.mu.Lock()
	defer bv.mu.Unlock()

	files, err := ioutil.ReadDir(bv.snapshotDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".dat" {
			filePath := filepath.Join(bv.snapshotDir, file.Name())
			valid, err := bv.VerifyBackupFile(filePath)
			if err != nil || !valid {
				return errors.New("backup verification failed for file: " + filePath)
			}
		}
	}

	logging.LogInfo("All backups verified successfully")
	return nil
}

// ScheduleBackupVerification schedules regular verification of backups
func (bv *BackupVerifier) ScheduleBackupVerification(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				err := bv.VerifyAllBackups()
				if err != nil {
					logging.LogError("Backup verification failed: %v", err)
				} else {
					logging.LogInfo("Backup verification completed successfully")
				}
			}
		}
	}()
}

// DecryptData decrypts the data using AES
func (bv *BackupVerifier) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(bv.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// TestBackupRestoration tests the restoration process from a backup file
func (bv *BackupVerifier) TestBackupRestoration(filePath string) error {
	bv.mu.Lock()
	defer bv.mu.Unlock()

	// Read the backup file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Decrypt the data
	decryptedData, err := bv.DecryptData(data)
	if err != nil {
		return err
	}

	// Set the ledger data
	err = bv.ledger.SetData(decryptedData)
	if err != nil {
		return err
	}

	logging.LogInfo("Backup restoration test successful for file: %s", filePath)
	return nil
}

// TestAllBackupRestorations tests the restoration process for all backup files in the snapshot directory
func (bv *BackupVerifier) TestAllBackupRestorations() error {
	bv.mu.Lock()
	defer bv.mu.Unlock()

	files, err := ioutil.ReadDir(bv.snapshotDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".dat" {
			filePath := filepath.Join(bv.snapshotDir, file.Name())
			err := bv.TestBackupRestoration(filePath)
			if err != nil {
				return errors.New("backup restoration test failed for file: " + filePath)
			}
		}
	}

	logging.LogInfo("All backup restoration tests completed successfully")
	return nil
}

// NewGeoDistributedBackupManager initializes a new GeoDistributedBackupManager
func NewGeoDistributedBackupManager(ledger *ledger.Ledger, p2pNetwork *p2p.Network, keyPair *keys.KeyPair, backupDirs []string) *GeoDistributedBackupManager {
	return &GeoDistributedBackupManager{
		dataReplicator: data_replication.NewDataReplicator(),
		storageManager: storage_allocation.NewStorageManager(),
		p2pNetwork:     p2pNetwork,
		ledger:         ledger,
		keyPair:        keyPair,
		backupDirs:     backupDirs,
	}
}

// EncryptData encrypts the data using AES
func (gm *GeoDistributedBackupManager) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(gm.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (gm *GeoDistributedBackupManager) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(gm.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CreateGeoBackup creates a geographically distributed backup of the blockchain data
func (gm *GeoDistributedBackupManager) CreateGeoBackup() ([]string, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	data, err := gm.ledger.GetData()
	if err != nil {
		return nil, err
	}

	// Encrypt data before creating backups
	encryptedData, err := gm.EncryptData(data)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Format("20060102150405")
	var backupPaths []string
	for _, dir := range gm.backupDirs {
		backupPath := filepath.Join(dir, "geo_backup_"+timestamp+".dat")
		err := ioutil.WriteFile(backupPath, encryptedData, 0644)
		if err != nil {
			logging.LogError("Failed to create backup in %s: %v", dir, err)
			continue
		}
		backupPaths = append(backupPaths, backupPath)
		logging.LogInfo("Backup created: %s", backupPath)
	}

	if len(backupPaths) == 0 {
		return nil, errors.New("failed to create any backup")
	}

	return backupPaths, nil
}

// VerifyGeoBackupIntegrity verifies the integrity of a geographically distributed backup
func (gm *GeoDistributedBackupManager) VerifyGeoBackupIntegrity(backupPaths []string) (bool, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for _, path := range backupPaths {
		encryptedData, err := ioutil.ReadFile(path)
		if err != nil {
			return false, err
		}

		data, err := gm.DecryptData(encryptedData)
		if err != nil {
			return false, err
		}

		// Compute the hash of the decrypted data
		hash := sha256.Sum256(data)
		dataHash := hex.EncodeToString(hash[:])

		// Retrieve the original ledger data and compute its hash
		originalData, err := gm.ledger.GetData()
		if err != nil {
			return false, err
		}

		originalHash := sha256.Sum256(originalData)
		if dataHash != hex.EncodeToString(originalHash[:]) {
			return false, errors.New("data integrity check failed for backup: " + path)
		}
	}

	return true, nil
}

// ScheduleGeoBackups schedules regular geographically distributed backups
func (gm *GeoDistributedBackupManager) ScheduleGeoBackups(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				_, err := gm.CreateGeoBackup()
				if err != nil {
					logging.LogError("Failed to create geographically distributed backup: %v", err)
				}
			}
		}
	}()
}

// RecoverFromGeoBackup recovers the ledger from a geographically distributed backup
func (gm *GeoDistributedBackupManager) RecoverFromGeoBackup(backupPath string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	encryptedData, err := ioutil.ReadFile(backupPath)
	if err != nil {
		return err
	}

	data, err := gm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return gm.ledger.SetData(data)
}

// PerformGeoBackupMaintenance performs regular maintenance tasks for geographically distributed backups
func (gm *GeoDistributedBackupManager) PerformGeoBackupMaintenance() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Clean up old backups
	for _, dir := range gm.backupDirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			logging.LogError("Failed to list directory %s: %v", dir, err)
			continue
		}

		for _, file := range files {
			if time.Since(file.ModTime()) > 30*24*time.Hour { // Keeping backups for 30 days
				filePath := filepath.Join(dir, file.Name())
				err := os.Remove(filePath)
				if err != nil {
					logging.LogError("Failed to remove old backup %s: %v", filePath, err)
				} else {
					logging.LogInfo("Old backup removed: %s", filePath)
				}
			}
		}
	}

	// Verify backup integrity
	for _, dir := range gm.backupDirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			logging.LogError("Failed to list directory %s: %v", dir, err)
			continue
		}

		var backupPaths []string
		for _, file := range files {
			if filepath.Ext(file.Name()) == ".dat" {
				backupPaths = append(backupPaths, filepath.Join(dir, file.Name()))
			}
		}

		valid, err := gm.VerifyGeoBackupIntegrity(backupPaths)
		if err != nil || !valid {
			logging.LogError("Backup integrity verification failed in directory %s: %v", dir, err)
		}
	}
}

// NewIncrementalBackupManager initializes a new IncrementalBackupManager
func NewIncrementalBackupManager(ledger *ledger.Ledger, keyPair *keys.KeyPair, snapshotDir string) *IncrementalBackupManager {
	return &IncrementalBackupManager{
		ledger:        ledger,
		keyPair:       keyPair,
		snapshotDir:   snapshotDir,
		changeTracker: make(map[string]string),
	}
}

// ComputeHash computes the SHA-256 hash of the given data
func (ib *IncrementalBackupManager) ComputeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// EncryptData encrypts the data using AES
func (ib *IncrementalBackupManager) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ib.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (ib *IncrementalBackupManager) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ib.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CreateIncrementalBackup creates an incremental backup of the blockchain data
func (ib *IncrementalBackupManager) CreateIncrementalBackup() (string, error) {
	ib.mu.Lock()
	defer ib.mu.Unlock()

	data, err := ib.ledger.GetData()
	if err != nil {
		return "", err
	}

	// Compute the hash of the current data
	currentHash := ib.ComputeHash(data)

	// Check if there are changes since the last backup
	if lastHash, exists := ib.changeTracker["latest"]; exists && lastHash == currentHash {
		logging.LogInfo("No changes detected since the last backup")
		return "", nil
	}

	// Encrypt the data before creating the backup
	encryptedData, err := ib.EncryptData(data)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102150405")
	backupPath := filepath.Join(ib.snapshotDir, "incremental_backup_"+timestamp+".dat")
	err = ioutil.WriteFile(backupPath, encryptedData, 0644)
	if err != nil {
		return "", err
	}

	// Update the change tracker
	ib.changeTracker["latest"] = currentHash
	logging.LogInfo("Incremental backup created: %s", backupPath)

	return backupPath, nil
}

// VerifyIncrementalBackup verifies the integrity of an incremental backup file
func (ib *IncrementalBackupManager) VerifyIncrementalBackup(filePath string) (bool, error) {
	ib.mu.Lock()
	defer ib.mu.Unlock()

	// Read the backup file
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	// Decrypt the data
	data, err := ib.DecryptData(encryptedData)
	if err != nil {
		return false, err
	}

	// Compute the hash of the decrypted data
	hash := ib.ComputeHash(data)

	// Retrieve the original ledger data
	originalData, err := ib.ledger.GetData()
	if err != nil {
		return false, err
	}

	// Compute the hash of the original data
	originalHash := ib.ComputeHash(originalData)

	// Compare the hashes
	if hash != originalHash {
		return false, errors.New("backup verification failed: hashes do not match")
	}

	return true, nil
}

// ScheduleIncrementalBackups schedules regular incremental backups
func (ib *IncrementalBackupManager) ScheduleIncrementalBackups(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				_, err := ib.CreateIncrementalBackup()
				if err != nil {
					logging.LogError("Failed to create incremental backup: %v", err)
				}
			}
		}
	}()
}

// RecoverFromIncrementalBackup recovers the ledger from an incremental backup
func (ib *IncrementalBackupManager) RecoverFromIncrementalBackup(filePath string) error {
	ib.mu.Lock()
	defer ib.mu.Unlock()

	// Read the backup file
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Decrypt the data
	data, err := ib.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	// Set the ledger data
	return ib.ledger.SetData(data)
}

// PerformIncrementalBackupMaintenance performs regular maintenance tasks for incremental backups
func (ib *IncrementalBackupManager) PerformIncrementalBackupMaintenance() {
	ib.mu.Lock()
	defer ib.mu.Unlock()

	// Clean up old backups
	files, err := ioutil.ReadDir(ib.snapshotDir)
	if err != nil {
		logging.LogError("Failed to list directory %s: %v", ib.snapshotDir, err)
		return
	}

	for _, file := range files {
		if time.Since(file.ModTime()) > 30*24*time.Hour { // Keeping backups for 30 days
			filePath := filepath.Join(ib.snapshotDir, file.Name())
			err := os.Remove(filePath)
			if err != nil {
				logging.LogError("Failed to remove old backup %s: %v", filePath, err)
			} else {
				logging.LogInfo("Old backup removed: %s", filePath)
			}
		}
	}

	// Verify backup integrity
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".dat" {
			filePath := filepath.Join(ib.snapshotDir, file.Name())
			valid, err := ib.VerifyIncrementalBackup(filePath)
			if err != nil || !valid {
				logging.LogError("Backup integrity verification failed for file %s: %v", filePath, err)
			}
		}
	}
}

// NewSnapshotManager initializes a new SnapshotManager
func NewSnapshotManager(ledger *ledger.Ledger, keyPair *keys.KeyPair, snapshotDir string) *SnapshotManager {
	return &SnapshotManager{
		ledger:      ledger,
		keyPair:     keyPair,
		snapshotDir: snapshotDir,
	}
}

// ComputeHash computes the SHA-256 hash of the given data
func (sm *SnapshotManager) ComputeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// EncryptData encrypts the data using AES
func (sm *SnapshotManager) EncryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.keyPair.PublicKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts the data using AES
func (sm *SnapshotManager) DecryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.keyPair.PrivateKey[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// CreateSnapshot creates a new snapshot of the blockchain
func (sm *SnapshotManager) CreateSnapshot() (string, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := sm.ledger.GetData()
	if err != nil {
		return "", err
	}

	encryptedData, err := sm.EncryptData(data)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102150405")
	snapshotPath := filepath.Join(sm.snapshotDir, "snapshot_"+timestamp+".dat")
	err = ioutil.WriteFile(snapshotPath, encryptedData, 0644)
	if err != nil {
		return "", err
	}

	logging.LogInfo("Snapshot created: %s", snapshotPath)
	return snapshotPath, nil
}

// VerifySnapshot verifies the integrity of a snapshot
func (sm *SnapshotManager) VerifySnapshot(filePath string) (bool, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	data, err := sm.DecryptData(encryptedData)
	if err != nil {
		return false, err
	}

	hash := sm.ComputeHash(data)

	originalData, err := sm.ledger.GetData()
	if err != nil {
		return false, err
	}

	originalHash := sm.ComputeHash(originalData)

	if hash != originalHash {
		return false, errors.New("snapshot verification failed: hashes do not match")
	}

	return true, nil
}

// RestoreSnapshot restores the ledger from a snapshot
func (sm *SnapshotManager) RestoreSnapshot(filePath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	data, err := sm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return sm.ledger.SetData(data)
}

// ScheduleSnapshots schedules regular snapshots
func (sm *SnapshotManager) ScheduleSnapshots(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				_, err := sm.CreateSnapshot()
				if err != nil {
					logging.LogError("Failed to create snapshot: %v", err)
				}
			}
		}
	}()
}

// PerformSnapshotMaintenance performs regular maintenance on snapshots
func (sm *SnapshotManager) PerformSnapshotMaintenance() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	files, err := ioutil.ReadDir(sm.snapshotDir)
	if err != nil {
		logging.LogError("Failed to list directory %s: %v", sm.snapshotDir, err)
		return
	}

	for _, file := range files {
		if time.Since(file.ModTime()) > 30*24*time.Hour { // Keeping snapshots for 30 days
			filePath := filepath.Join(sm.snapshotDir, file.Name())
			err := os.Remove(filePath)
			if err != nil {
				logging.LogError("Failed to remove old snapshot %s: %v", filePath, err)
			} else {
				logging.LogInfo("Old snapshot removed: %s", filePath)
			}
		}
	}

	// Verify snapshot integrity
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".dat" {
			filePath := filepath.Join(sm.snapshotDir, file.Name())
			valid, err := sm.VerifySnapshot(filePath)
			if err != nil || !valid {
				logging.LogError("Snapshot integrity verification failed for file %s: %v", filePath, err)
			}
		}
	}
}
