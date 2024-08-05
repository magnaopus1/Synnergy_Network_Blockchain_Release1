package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// Storage represents the storage for SYN223 tokens.
type Storage struct {
	mu        sync.RWMutex
	filePath  string
	data      map[string]interface{}
	passphrase string
}

// NewStorage initializes a new Storage instance.
func NewStorage(filePath, passphrase string) (*Storage, error) {
	storage := &Storage{
		filePath:  filePath,
		data:      make(map[string]interface{}),
		passphrase: passphrase,
	}

	if err := storage.load(); err != nil {
		return nil, err
	}

	return storage, nil
}

// load reads the storage file and loads the data into memory.
func (s *Storage) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return nil
	}

	file, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	decryptedData, err := utils.DecryptData(string(file), s.passphrase)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(decryptedData), &s.data); err != nil {
		return err
	}

	return nil
}

// save writes the current data to the storage file.
func (s *Storage) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	encryptedData, err := utils.EncryptData(string(file), s.passphrase)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(s.filePath, []byte(encryptedData), 0644); err != nil {
		return err
	}

	return nil
}

// Get retrieves a value from the storage.
func (s *Storage) Get(key string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, exists := s.data[key]
	if !exists {
		return nil, errors.New("key not found")
	}

	return value, nil
}

// Set stores a value in the storage.
func (s *Storage) Set(key string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = value
	return s.save()
}

// Delete removes a value from the storage.
func (s *Storage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[key]; !exists {
		return errors.New("key not found")
	}

	delete(s.data, key)
	return s.save()
}

// ListKeys returns all keys stored in the storage.
func (s *Storage) ListKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.data))
	for key := range s.data {
		keys = append(keys, key)
	}

	return keys
}

// Backup creates a backup of the current storage.
func (s *Storage) Backup(backupFilePath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	file, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	encryptedData, err := utils.EncryptData(string(file), s.passphrase)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(backupFilePath, []byte(encryptedData), 0644); err != nil {
		return err
	}

	return nil
}

// Restore restores the storage from a backup file.
func (s *Storage) Restore(backupFilePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := ioutil.ReadFile(backupFilePath)
	if err != nil {
		return err
	}

	decryptedData, err := utils.DecryptData(string(file), s.passphrase)
	if err != nil {
		return err
	}

	if err := json.Unmarshal([]byte(decryptedData), &s.data); err != nil {
		return err
	}

	return s.save()
}

// EncryptData encrypts data using the passphrase.
func (s *Storage) EncryptData(data string) (string, error) {
	return utils.EncryptData(data, s.passphrase)
}

// DecryptData decrypts data using the passphrase.
func (s *Storage) DecryptData(data string) (string, error) {
	return utils.DecryptData(data, s.passphrase)
}

// HashKey hashes a key using a secure hashing algorithm.
func (s *Storage) HashKey(key string) string {
	return utils.HashData(key)
}
