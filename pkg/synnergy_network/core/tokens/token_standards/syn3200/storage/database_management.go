package storage

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/crypto/scrypt"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// DataRecord represents a generic record stored in the database
type DataRecord struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// DatabaseManager manages the database operations
type DatabaseManager struct {
	DB   *leveldb.DB
	mu   sync.Mutex
	salt []byte
}

// NewDatabaseManager initializes a new database manager
func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	return &DatabaseManager{DB: db, salt: salt}, nil
}

// CloseDB closes the database connection
func (dm *DatabaseManager) CloseDB() error {
	return dm.DB.Close()
}

// AddRecord adds a new record to the database
func (dm *DatabaseManager) AddRecord(record DataRecord) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	record.Timestamp = time.Now()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encryptedData, err := encryptData(data, dm.salt)
	if err != nil {
		return err
	}
	return dm.DB.Put([]byte("record_"+record.ID), encryptedData, nil)
}

// GetRecord retrieves a record from the database by its ID
func (dm *DatabaseManager) GetRecord(recordID string) (*DataRecord, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	data, err := dm.DB.Get([]byte("record_"+recordID), nil)
	if err != nil {
		return nil, err
	}
	decryptedData, err := decryptData(data, dm.salt)
	if err != nil {
		return nil, err
	}
	var record DataRecord
	err = json.Unmarshal(decryptedData, &record)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// UpdateRecord updates an existing record in the database
func (dm *DatabaseManager) UpdateRecord(record DataRecord) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	record.Timestamp = time.Now()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encryptedData, err := encryptData(data, dm.salt)
	if err != nil {
		return err
	}
	return dm.DB.Put([]byte("record_"+record.ID), encryptedData, nil)
}

// DeleteRecord deletes a record from the database by its ID
func (dm *DatabaseManager) DeleteRecord(recordID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return dm.DB.Delete([]byte("record_"+recordID), nil)
}

// ListRecords lists all records in the database
func (dm *DatabaseManager) ListRecords() ([]DataRecord, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	var records []DataRecord
	iter := dm.DB.NewIterator(nil, nil)
	for iter.Next() {
		value := iter.Value()
		decryptedData, err := decryptData(value, dm.salt)
		if err != nil {
			return nil, err
		}
		var record DataRecord
		err = json.Unmarshal(decryptedData, &record)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return records, nil
}

// EncryptData encrypts data using AES encryption
func encryptData(data []byte, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(data, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

// DecryptData decrypts data using AES decryption
func decryptData(data []byte, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(data, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

// GenerateSalt generates a random salt for encryption
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
