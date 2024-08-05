package storage

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
	"time"

	"golang.org/x/crypto/scrypt"
)

// StorageManager handles various storage solutions for identity tokens
type StorageManager struct {
	dataPath       string
	encryptionKey  []byte
	backupManager  *BackupManager
	encryptionSalt []byte
}

// NewStorageManager initializes a new StorageManager
func NewStorageManager(dataPath, backupPath string, backupFrequency time.Duration, password string) (*StorageManager, error) {
	encryptionSalt := generateRandomBytes(16)
	encryptionKey, err := deriveKey(password, encryptionSalt)
	if err != nil {
		return nil, err
	}

	backupManager, err := NewBackupManager(dataPath, backupPath, backupFrequency)
	if err != nil {
		return nil, err
	}

	manager := &StorageManager{
		dataPath:       dataPath,
		encryptionKey:  encryptionKey,
		backupManager:  backupManager,
		encryptionSalt: encryptionSalt,
	}

	return manager, nil
}

// SaveData encrypts and saves data to the storage
func (sm *StorageManager) SaveData(filename string, data []byte) error {
	encryptedData, err := sm.encryptData(data)
	if err != nil {
		return err
	}

	filePath := fmt.Sprintf("%s/%s", sm.dataPath, filename)
	return ioutil.WriteFile(filePath, encryptedData, 0644)
}

// LoadData loads and decrypts data from the storage
func (sm *StorageManager) LoadData(filename string) ([]byte, error) {
	filePath := fmt.Sprintf("%s/%s", sm.dataPath, filename)
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return sm.decryptData(encryptedData)
}

// encryptData encrypts the data using AES-GCM
func (sm *StorageManager) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := generateRandomBytes(aesGCM.NonceSize())
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts the data using AES-GCM
func (sm *StorageManager) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// generateRandomBytes generates a slice of random bytes
func generateRandomBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// deriveKey derives a key from the password using scrypt
func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

// BackupManager handles redundancy and backup operations for identity tokens
type BackupManager struct {
	primaryDBPath   string
	backupDBPath    string
	backupFrequency time.Duration
	quit            chan bool
}

// NewBackupManager initializes a new BackupManager
func NewBackupManager(primaryDBPath, backupDBPath string, backupFrequency time.Duration) (*BackupManager, error) {
	manager := &BackupManager{
		primaryDBPath:   primaryDBPath,
		backupDBPath:    backupDBPath,
		backupFrequency: backupFrequency,
		quit:            make(chan bool),
	}

	if err := manager.verifyPaths(); err != nil {
		return nil, err
	}

	go manager.startBackupRoutine()

	return manager, nil
}

// verifyPaths checks if the primary and backup database paths are valid
func (bm *BackupManager) verifyPaths() error {
	if _, err := os.Stat(bm.primaryDBPath); os.IsNotExist(err) {
		return fmt.Errorf("primary database path does not exist: %v", bm.primaryDBPath)
	}

	if err := os.MkdirAll(bm.backupDBPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create backup directory: %v", err)
	}

	return nil
}

// startBackupRoutine initiates the routine to backup the primary database periodically
func (bm *BackupManager) startBackupRoutine() {
	ticker := time.NewTicker(bm.backupFrequency)
	for {
		select {
		case <-ticker.C:
			if err := bm.createBackup(); err != nil {
				fmt.Printf("Backup failed: %v\n", err)
			} else {
				fmt.Println("Backup completed successfully")
			}
		case <-bm.quit:
			ticker.Stop()
			return
		}
	}
}

// createBackup creates a backup of the primary database
func (bm *BackupManager) createBackup() error {
	backupFileName := fmt.Sprintf("backup_%s.db", time.Now().Format("20060102150405"))
	backupFilePath := fmt.Sprintf("%s/%s", bm.backupDBPath, backupFileName)

	sourceFile, err := os.Open(bm.primaryDBPath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(backupFilePath)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

// RestoreBackup restores the database from a specified backup file
func (bm *BackupManager) RestoreBackup(backupFileName string) error {
	backupFilePath := fmt.Sprintf("%s/%s", bm.backupDBPath, backupFileName)

	if _, err := os.Stat(backupFilePath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %v", backupFilePath)
	}

	sourceFile, err := os.Open(backupFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(bm.primaryDBPath)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

// ListBackups lists all backup files available in the backup directory
func (bm *BackupManager) ListBackups() ([]string, error) {
	files, err := os.ReadDir(bm.backupDBPath)
	if err != nil {
		return nil, err
	}

	var backups []string
	for _, file := range files {
		if !file.IsDir() {
			backups = append(backups, file.Name())
		}
	}

	return backups, nil
}

// Stop stops the backup routine
func (bm *BackupManager) Stop() {
	bm.quit <- true
}
