package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"errors"
	"io/ioutil"
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"golang.org/x/crypto/scrypt"
)

// StorageManager manages data storage and retrieval with encryption and redundancy.
type StorageManager struct {
	StoragePath  string
	EncryptionKey []byte
	mutex        sync.RWMutex
}

// NewStorageManager initializes a new StorageManager with a specified storage path and encryption key.
func NewStorageManager(storagePath string, passphrase string) (*StorageManager, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}
	return &StorageManager{
		StoragePath:  storagePath,
		EncryptionKey: key,
	}, nil
}

// SaveData securely saves data to the storage system with encryption.
func (sm *StorageManager) SaveData(filename string, data interface{}) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	filePath := filepath.Join(sm.StoragePath, filename)
	encryptedData, err := sm.encryptData(data)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	return nil
}

// LoadData loads and decrypts data from the storage system.
func (sm *StorageManager) LoadData(filename string, data interface{}) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	filePath := filepath.Join(sm.StoragePath, filename)
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read data from file: %w", err)
	}

	err = sm.decryptData(encryptedData, data)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	return nil
}

// DeleteData deletes a specified file from the storage system.
func (sm *StorageManager) DeleteData(filename string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	filePath := filepath.Join(sm.StoragePath, filename)
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// ListFiles lists all files in the storage directory.
func (sm *StorageManager) ListFiles() ([]string, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	files, err := ioutil.ReadDir(sm.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage directory: %w", err)
	}

	var filenames []string
	for _, file := range files {
		if !file.IsDir() {
			filenames = append(filenames, file.Name())
		}
	}

	return filenames, nil
}

// encryptData encrypts data using AES-GCM.
func (sm *StorageManager) encryptData(data interface{}) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	block, err := aes.NewCipher(sm.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES-GCM.
func (sm *StorageManager) decryptData(ciphertext []byte, data interface{}) error {
	block, err := aes.NewCipher(sm.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	err = json.Unmarshal(plaintext, data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return nil
}

// generateKey derives a key from a passphrase using Scrypt.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// RotateEncryptionKey rotates the encryption key used for storing data.
func (sm *StorageManager) RotateEncryptionKey(newPassphrase string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	newKey, err := generateKey(newPassphrase)
	if err != nil {
		return err
	}

	files, err := sm.ListFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		var data interface{}
		if err := sm.LoadData(file, &data); err != nil {
			return err
		}

		sm.EncryptionKey = newKey
		if err := sm.SaveData(file, data); err != nil {
			return err
		}
	}

	sm.EncryptionKey = newKey
	return nil
}
