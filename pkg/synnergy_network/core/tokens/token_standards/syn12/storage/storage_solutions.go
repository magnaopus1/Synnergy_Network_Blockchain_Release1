package storage

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// StorageManager handles the storage operations for the blockchain network.
type StorageManager struct {
	storagePath string
	data        map[string]interface{}
	mu          sync.RWMutex
}

// NewStorageManager creates a new instance of StorageManager.
func NewStorageManager(storagePath string) (*StorageManager, error) {
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %v", err)
	}

	return &StorageManager{
		storagePath: storagePath,
		data:        make(map[string]interface{}),
	}, nil
}

// SaveData saves data to the storage system.
func (sm *StorageManager) SaveData(key string, value interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Serialize data using gob
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("failed to encode data: %v", err)
	}

	// Write to file
	filePath := sm.getFilePath(key)
	if err := ioutil.WriteFile(filePath, buffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write data to file: %v", err)
	}

	sm.data[key] = value
	return nil
}

// LoadData loads data from the storage system.
func (sm *StorageManager) LoadData(key string, value interface{}) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check if data is already in memory
	if data, exists := sm.data[key]; exists {
		// Type assertion to ensure the correct type is returned
		switch v := value.(type) {
		case *map[string]interface{}:
			*v = data.(map[string]interface{})
		case *string:
			*v = data.(string)
		case *int:
			*v = data.(int)
		default:
			return errors.New("unsupported data type")
		}
		return nil
	}

	// Read from file
	filePath := sm.getFilePath(key)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read data from file: %v", err)
	}

	// Deserialize data
	buffer := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buffer)
	if err := dec.Decode(value); err != nil {
		return fmt.Errorf("failed to decode data: %v", err)
	}

	// Store in memory
	sm.data[key] = value
	return nil
}

// DeleteData removes data from the storage system.
func (sm *StorageManager) DeleteData(key string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	filePath := sm.getFilePath(key)
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete data file: %v", err)
	}

	delete(sm.data, key)
	return nil
}

// getFilePath constructs the file path for a given key.
func (sm *StorageManager) getFilePath(key string) string {
	return fmt.Sprintf("%s/%s.gob", sm.storagePath, key)
}

// Cleanup removes old data files and optimizes storage.
func (sm *StorageManager) Cleanup() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	files, err := ioutil.ReadDir(sm.storagePath)
	if err != nil {
		return fmt.Errorf("failed to read storage directory: %v", err)
	}

	for _, file := range files {
		filePath := fmt.Sprintf("%s/%s", sm.storagePath, file.Name())
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove old data file %s: %v", file.Name(), err)
		}
	}

	sm.data = make(map[string]interface{})
	return nil
}

// ListKeys returns a list of all keys stored in the system.
func (sm *StorageManager) ListKeys() ([]string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var keys []string
	for key := range sm.data {
		keys = append(keys, key)
	}
	return keys, nil
}

// Exists checks if a specific key exists in the storage system.
func (sm *StorageManager) Exists(key string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, exists := sm.data[key]
	return exists
}
