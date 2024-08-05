package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"github.com/synnergy_network/core/tokens/token_standards/syn722/security"
)

// Database struct to handle the LevelDB instance
type Database struct {
	db    *leveldb.DB
	mutex sync.Mutex
}

// NewDatabase initializes and returns a new Database instance
func NewDatabase(path string) (*Database, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &Database{db: db}, nil
}

// Close closes the LevelDB instance
func (d *Database) Close() error {
	return d.db.Close()
}

// Put stores a value associated with a key in the database
func (d *Database) Put(key string, value interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return d.db.Put([]byte(key), data, nil)
}

// Get retrieves the value associated with a key from the database
func (d *Database) Get(key string, value interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	data, err := d.db.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, value)
}

// Delete removes a key-value pair from the database
func (d *Database) Delete(key string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.db.Delete([]byte(key), nil)
}

// BatchPut stores multiple key-value pairs in the database
func (d *Database) BatchPut(pairs map[string]interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	batch := new(leveldb.Batch)
	for key, value := range pairs {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		batch.Put([]byte(key), data)
	}

	return d.db.Write(batch, &opt.WriteOptions{Sync: true})
}

// BatchDelete removes multiple key-value pairs from the database
func (d *Database) BatchDelete(keys []string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	batch := new(leveldb.Batch)
	for _, key := range keys {
		batch.Delete([]byte(key))
	}

	return d.db.Write(batch, &opt.WriteOptions{Sync: true})
}

// ListKeys returns a list of all keys in the database
func (d *Database) ListKeys(prefix string) ([]string, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var keys []string
	iter := d.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	for iter.Next() {
		keys = append(keys, string(iter.Key()))
	}
	iter.Release()
	return keys, iter.Error()
}

// SecurePut encrypts the value and stores it in the database
func (d *Database) SecurePut(key, passphrase string, value interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt([]byte(passphrase), data)
	if err != nil {
		return err
	}

	return d.db.Put([]byte(key), encryptedData, nil)
}

// SecureGet retrieves and decrypts the value associated with a key from the database
func (d *Database) SecureGet(key, passphrase string, value interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	encryptedData, err := d.db.Get([]byte(key), nil)
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
func (d *Database) Backup(backupPath string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	iter := d.db.NewIterator(nil, nil)
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
func (d *Database) Restore(backupPath string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

	return d.db.Write(batch, &opt.WriteOptions{Sync: true})
}
