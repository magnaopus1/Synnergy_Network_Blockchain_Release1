package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// StorageManager manages storage operations, including encryption and decryption.
type StorageManager struct {
	mu        sync.Mutex
	basePath  string
	secretKey []byte
}

// NewStorageManager initializes a new StorageManager.
func NewStorageManager(basePath string, secretKey []byte) *StorageManager {
	return &StorageManager{
		basePath:  basePath,
		secretKey: secretKey,
	}
}

// EncryptData encrypts the given data using AES-GCM with Scrypt-derived key.
func (sm *StorageManager) EncryptData(plainText []byte) ([]byte, error) {
	key, err := scrypt.Key(sm.secretKey, sm.secretKey, 16384, 8, 1, 32)
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

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	return cipherText, nil
}

// DecryptData decrypts the given data using AES-GCM with Scrypt-derived key.
func (sm *StorageManager) DecryptData(cipherText []byte) ([]byte, error) {
	key, err := scrypt.Key(sm.secretKey, sm.secretKey, 16384, 8, 1, 32)
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

	if len(cipherText) < gcm.NonceSize() {
		return nil, errors.New("cipherText too short")
	}

	nonce, cipherText := cipherText[:gcm.NonceSize()], cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// SaveData saves the given data to a specified file, encrypted.
func (sm *StorageManager) SaveData(fileName string, data interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	filePath := sm.basePath + "/" + fileName

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	encryptedData, err := sm.EncryptData(jsonData)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, encryptedData, 0644)
}

// LoadData loads and decrypts data from a specified file.
func (sm *StorageManager) LoadData(fileName string, data interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	filePath := sm.basePath + "/" + fileName

	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	jsonData, err := sm.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	return json.Unmarshal(jsonData, data)
}

// BackupManager handles the backup operations, integrating with redundancy features.
type BackupManager struct {
	RedundancyManager *RedundancyManager
	StorageManager    *StorageManager
	backupInterval    time.Duration
}

// NewBackupManager initializes a new BackupManager.
func NewBackupManager(redundancyManager *RedundancyManager, storageManager *StorageManager, backupInterval time.Duration) *BackupManager {
	return &BackupManager{
		RedundancyManager: redundancyManager,
		StorageManager:    storageManager,
		backupInterval:    backupInterval,
	}
}

// StartAutoBackup starts the automatic backup process at the specified interval.
func (bm *BackupManager) StartAutoBackup() {
	ticker := time.NewTicker(bm.backupInterval)
	go func() {
		for range ticker.C {
			bm.performBackup()
		}
	}()
}

// performBackup executes the backup operation, saving and synchronizing data.
func (bm *BackupManager) performBackup() {
	// Here you would define what data to backup, for example:
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		// Add more data fields as needed
	}

	if err := bm.StorageManager.SaveData("backup.json", data); err != nil {
		// Handle error, possibly logging it
		return
	}

	// Sync the backup with redundancy manager
	if err := bm.RedundancyManager.SyncBackups(); err != nil {
		// Handle error, possibly logging it
		return
	}
}

// ManualBackup triggers a manual backup operation.
func (bm *BackupManager) ManualBackup() error {
	// Here you would define what data to backup, for example:
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		// Add more data fields as needed
	}

	if err := bm.StorageManager.SaveData("manual_backup.json", data); err != nil {
		return err
	}

	return bm.RedundancyManager.SyncBackups()
}

// RestoreBackup restores data from a specified backup file.
func (bm *BackupManager) RestoreBackup(backupFile string, data interface{}) error {
	return bm.StorageManager.LoadData(backupFile, data)
}
