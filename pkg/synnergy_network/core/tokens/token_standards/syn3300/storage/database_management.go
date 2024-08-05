package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

// DatabaseManager handles interactions with the underlying storage system
type DatabaseManager struct {
	dbPath string
	key    []byte
}

// NewDatabaseManager creates a new instance of DatabaseManager
func NewDatabaseManager(dbPath, password string) (*DatabaseManager, error) {
	key, err := deriveKey(password)
	if err != nil {
		return nil, err
	}

	return &DatabaseManager{
		dbPath: dbPath,
		key:    key,
	}, nil
}

// deriveKey derives a secure key from the given password
func deriveKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return append(salt, key...), nil
}

// saveKey saves the derived key to a file
func (dm *DatabaseManager) saveKey() error {
	keyFilePath := dm.dbPath + ".key"
	return os.WriteFile(keyFilePath, dm.key, 0644)
}

// loadKey loads the derived key from a file
func (dm *DatabaseManager) loadKey() error {
	keyFilePath := dm.dbPath + ".key"
	key, err := os.ReadFile(keyFilePath)
	if err != nil {
		return err
	}
	dm.key = key
	return nil
}

// Encrypt encrypts the given data using AES encryption
func (dm *DatabaseManager) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(dm.key[16:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given encrypted string using AES encryption
func (dm *DatabaseManager) Decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dm.key[16:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SaveRecord saves a record to the database after encrypting it
func (dm *DatabaseManager) SaveRecord(recordID string, data []byte) error {
	encryptedData, err := dm.Encrypt(data)
	if err != nil {
		return err
	}

	filePath := fmt.Sprintf("%s/%s.record", dm.dbPath, recordID)
	return os.WriteFile(filePath, []byte(encryptedData), 0644)
}

// LoadRecord loads a record from the database and decrypts it
func (dm *DatabaseManager) LoadRecord(recordID string) ([]byte, error) {
	filePath := fmt.Sprintf("%s/%s.record", dm.dbPath, recordID)
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return dm.Decrypt(string(encryptedData))
}

// DeleteRecord deletes a record from the database
func (dm *DatabaseManager) DeleteRecord(recordID string) error {
	filePath := fmt.Sprintf("%s/%s.record", dm.dbPath, recordID)
	return os.Remove(filePath)
}

// ListRecords lists all record IDs in the database
func (dm *DatabaseManager) ListRecords() ([]string, error) {
	files, err := os.ReadDir(dm.dbPath)
	if err != nil {
		return nil, err
	}

	var recordIDs []string
	for _, file := range files {
		if file.Type().IsRegular() {
			recordID := file.Name()
			recordIDs = append(recordIDs, recordID[:len(recordID)-len(".record")])
		}
	}
	return recordIDs, nil
}
