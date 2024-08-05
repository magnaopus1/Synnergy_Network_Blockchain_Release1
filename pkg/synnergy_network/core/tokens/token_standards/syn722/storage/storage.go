package storage

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
)

// Storage struct to handle the LevelDB instance and provide advanced storage functionalities
type Storage struct {
	db    *leveldb.DB
	mutex sync.Mutex
}

// NewStorage initializes and returns a new Storage instance
func NewStorage(path string) (*Storage, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &Storage{db: db}, nil
}

// Close closes the LevelDB instance
func (s *Storage) Close() error {
	return s.db.Close()
}

// Put stores a value associated with a key in the database
func (s *Storage) Put(key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return s.db.Put([]byte(key), data, nil)
}

// Get retrieves the value associated with a key from the database
func (s *Storage) Get(key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := s.db.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, value)
}

// Delete removes a key-value pair from the database
func (s *Storage) Delete(key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.db.Delete([]byte(key), nil)
}

// BatchPut stores multiple key-value pairs in the database
func (s *Storage) BatchPut(pairs map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	batch := new(leveldb.Batch)
	for key, value := range pairs {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		batch.Put([]byte(key), data)
	}

	return s.db.Write(batch, &opt.WriteOptions{Sync: true})
}

// BatchDelete removes multiple key-value pairs from the database
func (s *Storage) BatchDelete(keys []string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	batch := new(leveldb.Batch)
	for _, key := range keys {
		batch.Delete([]byte(key))
	}

	return s.db.Write(batch, &opt.WriteOptions{Sync: true})
}

// ListKeys returns a list of all keys in the database, optionally filtered by a prefix
func (s *Storage) ListKeys(prefix string) ([]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var keys []string
	iter := s.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	for iter.Next() {
		keys = append(keys, string(iter.Key()))
	}
	iter.Release()
	return keys, iter.Error()
}

// SecurePut encrypts the value and stores it in the database using a passphrase
func (s *Storage) SecurePut(key, passphrase string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt([]byte(passphrase), data)
	if err != nil {
		return err
	}

	return s.db.Put([]byte(key), encryptedData, nil)
}

// SecureGet retrieves and decrypts the value associated with a key from the database using a passphrase
func (s *Storage) SecureGet(key, passphrase string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	encryptedData, err := s.db.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	decryptedData, err := security.Decrypt([]byte(passphrase), encryptedData)
	if err != nil {
		return err
	}

	return json.Unmarshal(decryptedData, value)
}

// Backup creates a backup of the database
func (s *Storage) Backup(backupPath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	iter := s.db.NewIterator(nil, nil)
	defer iter.Release()

	backupDB, err := leveldb.OpenFile(backupPath, nil)
	if err != nil {
		return err
	}
	defer backupDB.Close()

	batch := new(leveldb.Batch)
	for iter.Next() {
		batch.Put(iter.Key(), iter.Value())
	}

	return backupDB.Write(batch, &opt.WriteOptions{Sync: true})
}

// Restore restores the database from a backup
func (s *Storage) Restore(backupPath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	backupDB, err := leveldb.OpenFile(backupPath, nil)
	if err != nil {
		return err
	}
	defer backupDB.Close()

	iter := backupDB.NewIterator(nil, nil)
	defer iter.Release()

	batch := new(leveldb.Batch)
	for iter.Next() {
		batch.Put(iter.Key(), iter.Value())
	}

	return s.db.Write(batch, &opt.WriteOptions{Sync: true})
}

// GetAll returns all key-value pairs in the database
func (s *Storage) GetAll(prefix string) (map[string]interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	results := make(map[string]interface{})
	iter := s.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		var value interface{}
		if err := json.Unmarshal(iter.Value(), &value); err != nil {
			return nil, err
		}
		results[key] = value
	}

	return results, iter.Error()
}

// Iterate provides a way to iterate over key-value pairs with a custom function
func (s *Storage) Iterate(prefix string, fn func(key string, value interface{}) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	iter := s.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		var value interface{}
		if err := json.Unmarshal(iter.Value(), &value); err != nil {
			return err
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}

	return iter.Error()
}
