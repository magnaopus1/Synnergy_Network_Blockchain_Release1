package storage

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// Database represents a simple file-based key-value store.
type Database struct {
	mu       sync.RWMutex
	filePath string
	data     map[string]interface{}
}

// NewDatabase initializes a new Database instance.
func NewDatabase(filePath string) (*Database, error) {
	db := &Database{
		filePath: filePath,
		data:     make(map[string]interface{}),
	}

	if err := db.load(); err != nil {
		return nil, err
	}

	return db, nil
}

// load reads the database file and loads the data into memory.
func (db *Database) load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, err := os.Stat(db.filePath); os.IsNotExist(err) {
		return nil
	}

	file, err := ioutil.ReadFile(db.filePath)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(file, &db.data); err != nil {
		return err
	}

	return nil
}

// save writes the current data to the database file.
func (db *Database) save() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(db.filePath, file, 0644); err != nil {
		return err
	}

	return nil
}

// Get retrieves a value from the database.
func (db *Database) Get(key string) (interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	value, exists := db.data[key]
	if !exists {
		return nil, errors.New("key not found")
	}

	return value, nil
}

// Set stores a value in the database.
func (db *Database) Set(key string, value interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.data[key] = value
	return db.save()
}

// Delete removes a value from the database.
func (db *Database) Delete(key string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; !exists {
		return errors.New("key not found")
	}

	delete(db.data, key)
	return db.save()
}

// EncryptData encrypts data before storing it in the database.
func (db *Database) EncryptData(key, data, passphrase string) error {
	encryptedData, err := utils.EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	return db.Set(key, encryptedData)
}

// DecryptData decrypts data retrieved from the database.
func (db *Database) DecryptData(key, passphrase string) (string, error) {
	encryptedData, err := db.Get(key)
	if err != nil {
		return "", err
	}

	decryptedData, err := utils.DecryptData(encryptedData.(string), passphrase)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

// HashKey hashes a key using a secure hashing algorithm.
func (db *Database) HashKey(key string) string {
	return utils.HashData(key)
}
