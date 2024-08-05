package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// StorageSolutions provides comprehensive data storage management including encryption, decryption, and secure storage.
type StorageSolutions struct {
	primaryStorage map[string][]byte
	backupStorage  map[string][]byte
	encryptionKey  []byte
	backupInterval time.Duration
}

// NewStorageSolutions initializes a new StorageSolutions instance with a given encryption key and backup interval.
func NewStorageSolutions(key []byte, backupInterval time.Duration) *StorageSolutions {
	return &StorageSolutions{
		primaryStorage: make(map[string][]byte),
		backupStorage:  make(map[string][]byte),
		encryptionKey:  key,
		backupInterval: backupInterval,
	}
}

// EncryptData encrypts data using AES-GCM with the provided key.
func (s *StorageSolutions) EncryptData(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
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

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptData decrypts data using AES-GCM with the provided key.
func (s *StorageSolutions) DecryptData(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// StoreData securely stores data by encrypting it before storing it in primary storage.
func (s *StorageSolutions) StoreData(key string, data []byte) error {
	encryptedData, err := s.EncryptData(data)
	if err != nil {
		return err
	}

	s.primaryStorage[key] = encryptedData
	return nil
}

// RetrieveData retrieves and decrypts data from primary storage.
func (s *StorageSolutions) RetrieveData(key string) ([]byte, error) {
	encryptedData, exists := s.primaryStorage[key]
	if !exists {
		return nil, errors.New("data not found for key: " + key)
	}

	return s.DecryptData(encryptedData)
}

// BackupData copies data from primary to backup storage and encrypts it.
func (s *StorageSolutions) BackupData() {
	for key, data := range s.primaryStorage {
		encryptedData, err := s.EncryptData(data)
		if err != nil {
			fmt.Printf("Failed to backup data for key %s: %v\n", key, err)
			continue
		}
		s.backupStorage[key] = encryptedData
	}
}

// RestoreData restores data from backup storage to primary storage.
func (s *StorageSolutions) RestoreData(key string) error {
	encryptedData, exists := s.backupStorage[key]
	if !exists {
		return errors.New("backup not found for key: " + key)
	}

	decryptedData, err := s.DecryptData(encryptedData)
	if err != nil {
		return err
	}

	s.primaryStorage[key] = decryptedData
	return nil
}

// RunBackupScheduler starts a scheduler to perform regular backups.
func (s *StorageSolutions) RunBackupScheduler() {
	ticker := time.NewTicker(s.backupInterval)
	go func() {
		for range ticker.C {
			s.BackupData()
		}
	}()
}

// ListStoredKeys lists all keys currently stored in primary storage.
func (s *StorageSolutions) ListStoredKeys() []string {
	keys := make([]string, 0, len(s.primaryStorage))
	for key := range s.primaryStorage {
		keys = append(keys, key)
	}
	return keys
}

// RemoveData removes specified data from both primary and backup storage.
func (s *StorageSolutions) RemoveData(key string) error {
	_, primaryExists := s.primaryStorage[key]
	_, backupExists := s.backupStorage[key]

	if !primaryExists && !backupExists {
		return errors.New("data not found in either primary or backup storage for key: " + key)
	}

	delete(s.primaryStorage, key)
	delete(s.backupStorage, key)
	fmt.Printf("Data for key %s removed from storage.\n", key)
	return nil
}

// AuditStorage verifies the integrity and consistency of stored data between primary and backup storage.
func (s *StorageSolutions) AuditStorage() error {
	for key, primaryData := range s.primaryStorage {
		backupData, exists := s.backupStorage[key]
		if !exists {
			return fmt.Errorf("data inconsistency: key %s missing in backup storage", key)
		}

		decryptedPrimaryData, err := s.DecryptData(primaryData)
		if err != nil {
			return fmt.Errorf("error decrypting primary data for key %s: %v", key, err)
		}

		decryptedBackupData, err := s.DecryptData(backupData)
		if err != nil {
			return fmt.Errorf("error decrypting backup data for key %s: %v", key, err)
		}

		if string(decryptedPrimaryData) != string(decryptedBackupData) {
			return fmt.Errorf("data mismatch for key %s between primary and backup storage", key)
		}
	}
	return nil
}
