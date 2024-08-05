package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/scrypt"
)

// BackupManager handles backup and redundancy operations for the SYN3000 database
type BackupManager struct {
	mu            sync.RWMutex
	db            *Database
	encryptionKey []byte
}

// NewBackupManager initializes a new BackupManager with the given database and password
func NewBackupManager(db *Database, password string) (*BackupManager, error) {
	key, err := generateEncryptionKey(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &BackupManager{
		db:            db,
		encryptionKey: key,
	}, nil
}

// CreateBackup creates a backup of the current database state
func (bm *BackupManager) CreateBackup(backupFile string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	data, err := json.Marshal(bm.db)
	if err != nil {
		return fmt.Errorf("failed to marshal database: %v", err)
	}

	encryptedData, err := bm.encrypt(string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt backup data: %v", err)
	}

	err = os.WriteFile(backupFile, []byte(encryptedData), 0644)
	if err != nil {
		return fmt.Errorf("failed to write backup file: %v", err)
	}

	fmt.Printf("Backup created successfully: %s\n", backupFile)
	return nil
}

// RestoreBackup restores the database state from a backup file
func (bm *BackupManager) RestoreBackup(backupFile string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	encryptedData, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %v", err)
	}

	data, err := bm.decrypt(string(encryptedData))
	if err != nil {
		return fmt.Errorf("failed to decrypt backup data: %v", err)
	}

	err = json.Unmarshal([]byte(data), &bm.db)
	if err != nil {
		return fmt.Errorf("failed to unmarshal database: %v", err)
	}

	fmt.Printf("Backup restored successfully from: %s\n", backupFile)
	return nil
}

// ScheduleBackups schedules regular backups at the given interval
func (bm *BackupManager) ScheduleBackups(interval time.Duration, backupDir string) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				backupFile := fmt.Sprintf("%s/backup_%d.bak", backupDir, time.Now().Unix())
				err := bm.CreateBackup(backupFile)
				if err != nil {
					fmt.Printf("Failed to create backup: %v\n", err)
				}
			}
		}
	}()
}

// encrypt encrypts the given plaintext using AES
func (bm *BackupManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the given ciphertext using AES
func (bm *BackupManager) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateEncryptionKey generates an encryption key using scrypt
func generateEncryptionKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}
