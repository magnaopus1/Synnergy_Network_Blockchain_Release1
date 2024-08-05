package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/ipfs/go-ipfs-api"
	"golang.org/x/crypto/scrypt"
)

// StorageManager handles interactions with IPFS and local storage encryption
type StorageManager struct {
	sh         *shell.Shell
	aesKey     []byte
	scryptSalt []byte
	lock       sync.RWMutex
}

// NewStorageManager initializes a new StorageManager
func NewStorageManager(ipfsAddress string, password string, salt []byte) (*StorageManager, error) {
	sh := shell.NewShell(ipfsAddress)

	key, err := generateKey(password, salt)
	if err != nil {
		return nil, err
	}

	return &StorageManager{
		sh:         sh,
		aesKey:     key,
		scryptSalt: salt,
	}, nil
}

// AddFile adds a file to IPFS, encrypting it first
func (sm *StorageManager) AddFile(fileContent []byte) (string, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	encryptedData, err := sm.encryptData(fileContent)
	if err != nil {
		return "", err
	}

	hash, err := sm.sh.Add(bytes.NewReader(encryptedData))
	if err != nil {
		return "", err
	}

	return hash, nil
}

// GetFile retrieves a file from IPFS and decrypts it
func (sm *StorageManager) GetFile(hash string) ([]byte, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	encryptedData, err := sm.sh.Cat(hash)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(encryptedData)
	if err != nil {
		return nil, err
	}

	decryptedData, err := sm.decryptData(data)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// generateKey generates a key for encryption using scrypt
func generateKey(password string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// encryptData encrypts data using AES
func (sm *StorageManager) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.aesKey)
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES
func (sm *StorageManager) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.aesKey)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// UpdateAESKey updates the AES encryption key
func (sm *StorageManager) UpdateAESKey(newPassword string) error {
	newKey, err := generateKey(newPassword, sm.scryptSalt)
	if err != nil {
		return err
	}

	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.aesKey = newKey
	return nil
}

// DeleteFile deletes a file from IPFS
func (sm *StorageManager) DeleteFile(hash string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	err := sm.sh.Unpin(hash)
	if err != nil {
		return err
	}

	return nil
}

// ListFiles lists all files in IPFS
func (sm *StorageManager) ListFiles() ([]string, error) {
	// IPFS does not provide a direct list method; typically, this would be managed locally or with metadata
	return nil, errors.New("listing files is not directly supported by IPFS")
}

// generateSalt generates a new random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// HashAndEncryptPassword hashes and encrypts the password using scrypt and AES
func HashAndEncryptPassword(password string, salt []byte) (string, error) {
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return hex.EncodeToString(ciphertext), nil
}

func main() {
	// Example usage of the StorageManager
	ipfsAddress := "localhost:5001"
	password := "securepassword"
	salt, err := generateSalt()
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	sm, err := NewStorageManager(ipfsAddress, password, salt)
	if err != nil {
		log.Fatalf("Failed to initialize StorageManager: %v", err)
	}

	// Add a file
	content := []byte("Example file content")
	hash, err := sm.AddFile(content)
	if err != nil {
		log.Fatalf("Failed to add file: %v", err)
	}
	fmt.Printf("File added with hash: %s\n", hash)

	// Get the file
	retrievedContent, err := sm.GetFile(hash)
	if err != nil {
		log.Fatalf("Failed to get file: %v", err)
	}
	fmt.Printf("Retrieved file co
