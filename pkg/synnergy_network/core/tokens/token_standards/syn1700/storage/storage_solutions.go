package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// StorageSolutions handles various storage-related functionalities including secure storage and retrieval of data.
type StorageSolutions struct {
	storageDir string
	aesKey     []byte
	salt       []byte
	mu         sync.Mutex
}

// NewStorageSolutions creates a new instance of StorageSolutions
func NewStorageSolutions(storageDir, passphrase string) (*StorageSolutions, error) {
	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &StorageSolutions{
		storageDir: storageDir,
		aesKey:     key,
		salt:       salt,
	}, nil
}

// SaveData securely saves data to a file
func (ss *StorageSolutions) SaveData(filename string, data []byte) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Create a file in the storage directory
	filePath := fmt.Sprintf("%s/%s.enc", ss.storageDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encrypt and write data to the file
	encryptedData, err := ss.encrypt(data)
	if err != nil {
		return err
	}

	_, err = file.Write(encryptedData)
	if err != nil {
		return err
	}

	log.Printf("Data saved securely to: %s", filePath)
	return nil
}

// LoadData securely loads data from a file
func (ss *StorageSolutions) LoadData(filename string) ([]byte, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Open the file in the storage directory
	filePath := fmt.Sprintf("%s/%s.enc", ss.storageDir, filename)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read and decrypt the data from the file
	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	data, err := ss.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	log.Printf("Data loaded securely from: %s", filePath)
	return data, nil
}

// encrypt encrypts the data using AES-GCM
func (ss *StorageSolutions) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// decrypt decrypts the data using AES-GCM
func (ss *StorageSolutions) decrypt(data []byte) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ss.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(decodedData) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedData[:gcm.NonceSize()], decodedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ListFiles lists all files in the storage directory
func (ss *StorageSolutions) ListFiles() ([]string, error) {
	files, err := os.ReadDir(ss.storageDir)
	if err != nil {
		return nil, err
	}

	var fileList []string
	for _, file := range files {
		if !file.IsDir() && file.Name() != ".DS_Store" {
			fileList = append(fileList, file.Name())
		}
	}

	return fileList, nil
}

// DeleteFile deletes a file from the storage directory
func (ss *StorageSolutions) DeleteFile(filename string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	filePath := fmt.Sprintf("%s/%s.enc", ss.storageDir, filename)
	err := os.Remove(filePath)
	if err != nil {
		return err
	}

	log.Printf("File deleted: %s", filePath)
	return nil
}

// CleanUpOldFiles deletes files older than the specified duration
func (ss *StorageSolutions) CleanUpOldFiles(olderThan time.Duration) error {
	files, err := os.ReadDir(ss.storageDir)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, file := range files {
		if file.IsDir() || file.Name() == ".DS_Store" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			return err
		}

		if now.Sub(info.ModTime()) > olderThan {
			err := os.Remove(fmt.Sprintf("%s/%s", ss.storageDir, file.Name()))
			if err != nil {
				return err
			}
			log.Printf("Deleted old file: %s", file.Name())
		}
	}

	return nil
}
