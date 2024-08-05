package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

// StorageSolutions provides methods for secure storage of data
type StorageSolutions struct {
	dataPath    string
	encryptionKey []byte
}

// NewStorageSolutions creates a new instance of StorageSolutions
func NewStorageSolutions(dataPath, password string) (*StorageSolutions, error) {
	encryptionKey, err := generateKeyFromPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &StorageSolutions{
		dataPath:    dataPath,
		encryptionKey: encryptionKey,
	}, nil
}

// SaveData securely saves data to a file with encryption
func (ss *StorageSolutions) SaveData(filename string, data []byte) error {
	encryptedData, err := ss.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	filePath := filepath.Join(ss.dataPath, filename)
	err = os.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data to file: %v", err)
	}

	return nil
}

// LoadData securely loads data from a file with decryption
func (ss *StorageSolutions) LoadData(filename string) ([]byte, error) {
	filePath := filepath.Join(ss.dataPath, filename)
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from file: %v", err)
	}

	data, err := ss.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return data, nil
}

// PurgeOldData removes data files older than the specified retention period
func (ss *StorageSolutions) PurgeOldData(retentionDays int) error {
	files, err := os.ReadDir(ss.dataPath)
	if err != nil {
		return fmt.Errorf("failed to read data directory: %v", err)
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	for _, file := range files {
		fileInfo, err := file.Info()
		if err != nil {
			return fmt.Errorf("failed to get file info: %v", err)
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			err := os.Remove(filepath.Join(ss.dataPath, file.Name()))
			if err != nil {
				return fmt.Errorf("failed to remove old data: %v", err)
			}
		}
	}

	return nil
}

// encryptData encrypts data using AES
func (ss *StorageSolutions) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES
func (ss *StorageSolutions) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// generateKeyFromPassword generates a key from a password using scrypt
func generateKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return key, nil
}

// HashData hashes the given data using SHA-256
func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

