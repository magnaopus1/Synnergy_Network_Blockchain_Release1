package backups

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/scrypt"
	"encoding/base64"
	"errors"
	"io"

	"synnergy_network/core/wallet/crypto"
)

// Constants for encryption standards
const (
	keyLength = 32 // AES-256
	saltSize  = 16
	nonceSize = 12 // Recommended size for GCM
)

// EncryptData encrypts data using AES-256-GCM with a key derived from the passphrase using scrypt.
func EncryptData(data []byte, passphrase string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keyLength)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptData decrypts data using AES-256-GCM with a key derived from the passphrase using scrypt.
func DecryptData(encryptedData string, passphrase string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(data) < nonceSize {
		return nil, errors.New("invalid data size")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keyLength)
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

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
package backups

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/scrypt"
    "encoding/base64"
    "errors"
    "io"

    "synnergy_network/core/wallet/crypto"
    "synnergy_network/storage/decentralized"
)

// Constants for encryption and recovery
const (
    keyLength = 32 // Using AES-256
    saltSize  = 16
    nonceSize = 12
)

// RecoveryHandler manages the operations for restoring wallet backups.
type RecoveryHandler struct {
    storageProvider decentralized.StorageProvider
}

// NewRecoveryHandler creates a new instance of RecoveryHandler.
func NewRecoveryHandler(provider decentralized.StorageProvider) *RecoveryHandler {
    return &RecoveryHandler{
        storageProvider: provider,
    }
}

// RecoverData retrieves and decrypts wallet data from storage.
func (rh *RecoveryHandler) RecoverData(encryptedData, passphrase string) ([]byte, error) {
    // Decode the base64 encrypted data
    data, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        return nil, err
    }

    // Extract salt and nonce from the data
    if len(data) < (saltSize + nonceSize) {
        return nil, errors.New("invalid data format")
    }
    salt := data[:saltSize]
    nonce := data[saltSize : saltSize+nonceSize]
    ciphertext := data[saltSize+nonceSize:]

    // Generate key from passphrase and salt
    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keyLength)
    if err != nil {
        return nil, err
    }

    // Decrypt the data using AES-GCM
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Decrypt the data
    decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return decrypted, nil
}

// RetrieveBackup locates and recovers a backup from the decentralized storage system.
func (rh *RecoveryHandler) RetrieveBackup(userID, passphrase string) ([]byte, error) {
    // Retrieve encrypted data from decentralized storage
    encryptedData, err := rh.storageProvider.FetchData(userID)
    if err != nil {
        return nil, err
    }

    // Recover the actual data by decrypting it
    return rh.RecoverData(encryptedData, passphrase)
}
package backups

import (
	"time"
	"synnergy_network/core/wallet/backups"
	"synnergy_network/high_availability/data_backup"
	"synnergy_network/storage/decentralized"
	"log"
)

// Scheduler manages the scheduling of backup tasks.
type Scheduler struct {
	LocalBackupManager   *backups.LocalBackup
	CloudBackupManager   *backups.CloudBackup
	BackupFrequency      time.Duration
	NextScheduledBackup  time.Time
}

// NewScheduler initializes a new backup scheduler with specified backup frequency.
func NewScheduler(local *backups.LocalBackup, cloud *backups.CloudBackup, frequency time.Duration) *Scheduler {
	return &Scheduler{
		LocalBackupManager:  local,
		CloudBackupManager:  cloud,
		BackupFrequency:     frequency,
		NextScheduledBackup: time.Now().Add(frequency),
	}
}

// ScheduleBackups starts the periodic backup process.
func (s *Scheduler) ScheduleBackups() {
	for {
		currentTime := time.Now()
		if currentTime.After(s.NextScheduledBackup) {
			s.performBackups()
			s.NextScheduledBackup = currentTime.Add(s.BackupFrequency)
		}
		time.Sleep(time.Minute) // Sleep to prevent tight looping, adjust as needed for efficiency.
	}
}

// performBackups executes the backup process for both local and cloud backups.
func (s *Scheduler) performBackups() {
	go func() {
		if err := s.LocalBackupManager.Backup(); err != nil {
			log.Printf("Failed to perform local backup: %v", err)
		} else {
			log.Println("Local backup completed successfully.")
		}
	}()

	go func() {
		if err := s.CloudBackupManager.Backup(); err != nil {
			log.Printf("Failed to perform cloud backup: %v", err)
		} else {
			log.Println("Cloud backup completed successfully.")
		}
	}()
}

// SetBackupFrequency updates the frequency of backups.
func (s *Scheduler) SetBackupFrequency(newFrequency time.Duration) {
	s.BackupFrequency = newFrequency
	s.NextScheduledBackup = time.Now().Add(newFrequency)
	log.Printf("Backup frequency updated to every %v.", newFrequency)
}

package backups

import (
	"errors"
	"time"
	"synnergy_network/core/wallet/backups"
	"synnergy_network/high_availability/data_backup"
	"synnergy_network/storage/decentralized"
	"synnergy_network/utils/logger"
)

// BackupService manages all backup operations for the wallet, ensuring data integrity and security.
type BackupService struct {
	Scheduler        *backups.Scheduler
	LocalBackup      *backups.LocalBackup
	CloudBackup      *backups.CloudBackup
	BackupRepository decentralized.StorageProvider
	Logger           *logger.Logger
}

// NewBackupService creates a new BackupService with given components.
func NewBackupService(scheduler *backups.Scheduler, localBackup *backups.LocalBackup, cloudBackup *backups.CloudBackup, repository decentralized.StorageProvider, log *logger.Logger) *BackupService {
	return &BackupService{
		Scheduler:        scheduler,
		LocalBackup:      localBackup,
		CloudBackup:      cloudBackup,
		BackupRepository: repository,
		Logger:           log,
	}
}

// PerformBackup initiates a backup process, both locally and on cloud, according to the predefined schedule.
func (bs *BackupService) PerformBackup() error {
	bs.Logger.Info("Initiating backup process")
	err := bs.Scheduler.ScheduleBackups()
	if err != nil {
		bs.Logger.Error("Error scheduling backups", err)
		return err
	}
	bs.Logger.Info("Backup process completed successfully")
	return nil
}

// RestoreBackup handles the restoration process using the backup data from local or cloud storage.
func (bs *BackupService) RestoreBackup(backupID string, passphrase string) ([]byte, error) {
	bs.Logger.Info("Initiating backup restoration")
	data, err := bs.BackupRepository.FetchData(backupID)
	if err != nil {
		bs.Logger.Error("Failed to fetch backup data", err)
		return nil, err
	}

	decryptedData, err := bs.LocalBackup.DecryptData(data, passphrase)
	if err != nil {
		bs.Logger.Error("Failed to decrypt backup data", err)
		return nil, err
	}
	bs.Logger.Info("Backup restored successfully")
	return decryptedData, nil
}

// ScheduleBackup sets or updates the backup frequency and reinitializes the scheduler.
func (bs *BackupService) ScheduleBackup(interval time.Duration) error {
	if interval <= 0 {
		return errors.New("invalid interval: must be greater than zero")
	}
	bs.Logger.Info("Updating backup schedule")
	bs.Scheduler.SetBackupFrequency(interval)
	bs.Logger.Info("Backup schedule updated successfully")
	return nil
}

// GetBackupStatus provides the current status and details of the backup processes.
func (bs *BackupService) GetBackupStatus() string {
	// This method would interface with internal status tracking to provide a detailed report
	return "Backup status fetched successfully"
}
package backups

import (
    "synnergy_network/storage/decentralized"
    "synnergy_network/utils/logger"
    "errors"
    "fmt"
)

// CloudBackup manages the storage of wallet backups on decentralized cloud storage.
type CloudBackup struct {
    Storage decentralized.StorageProvider
    Log     *logger.Logger
}

// NewCloudBackup creates a new instance of CloudBackup.
func NewCloudBackup(storage decentralized.StorageProvider, log *logger.Logger) *CloudBackup {
    return &CloudBackup{
        Storage: storage,
        Log:     log,
    }
}

// Backup takes the encrypted wallet data and stores it in the cloud.
func (cb *CloudBackup) Backup(userID string, data []byte) error {
    if len(data) == 0 {
        return errors.New("no data provided for backup")
    }
    
    cb.Log.Info("Starting cloud backup for user: ", userID)
    err := cb.Storage.StoreData(userID, data)
    if err != nil {
        cb.Log.Error("Failed to backup data to cloud for user: ", userID, " Error: ", err)
        return fmt.Errorf("failed to backup data to cloud: %w", err)
    }
    cb.Log.Info("Cloud backup completed successfully for user: ", userID)
    return nil
}

// Restore retrieves the encrypted wallet data from the cloud.
func (cb *CloudBackup) Restore(userID string) ([]byte, error) {
    cb.Log.Info("Starting cloud restore for user: ", userID)
    data, err := cb.Storage.FetchData(userID)
    if err != nil {
        cb.Log.Error("Failed to restore data from cloud for user: ", userID, " Error: ", err)
        return nil, fmt.Errorf("failed to restore data from cloud: %w", err)
    }
    cb.Log.Info("Cloud restore completed successfully for user: ", userID)
    return data, nil
}

package backups

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/scrypt"
    "encoding/base64"
    "errors"
    "io"
    "io/ioutil"
    "os"
    "path/filepath"

    "synnergy_network/utils/logger"
    "synnergy_network/storage/secure_storage"
)

// LocalBackup handles local storage and retrieval of wallet backups.
type LocalBackup struct {
    BackupDirectory string
    Logger          *logger.Logger
}

// NewLocalBackup creates a new LocalBackup instance with a designated backup directory.
func NewLocalBackup(directory string, log *logger.Logger) *LocalBackup {
    if _, err := os.Stat(directory); os.IsNotExist(err) {
        os.MkdirAll(directory, 0700) // Ensures that the directory is secure
    }
    return &LocalBackup{
        BackupDirectory: directory,
        Logger:          log,
    }
}

// Backup encrypts and stores wallet data locally.
func (lb *LocalBackup) Backup(data []byte, passphrase string) error {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return err
    }

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    encryptedData := gcm.Seal(nonce, nonce, data, nil)
    encodedData := base64.StdEncoding.EncodeToString(encryptedData)

    filePath := filepath.Join(lb.BackupDirectory, "wallet_backup.enc")
    return ioutil.WriteFile(filePath, []byte(encodedData), 0600)
}

// Restore decrypts and retrieves wallet data from local storage.
func (lb *LocalBackup) Restore(passphrase string) ([]byte, error) {
    filePath := filepath.Join(lb.BackupDirectory, "wallet_backup.enc")
    encodedData, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    encryptedData, err := base64.StdEncoding.DecodeString(string(encodedData))
    if err != nil {
        return nil, err
    }

    if len(encryptedData) < 12 {
        return nil, errors.New("invalid backup data")
    }

    nonce, ciphertext := encryptedData[:12], encryptedData[12:]
    salt := ciphertext[:16]
    ciphertext = ciphertext[16:]

    key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
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

    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return decryptedData, nil
}
