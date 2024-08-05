package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/ipfs/go-ipfs-api"
	"golang.org/x/crypto/scrypt"
)

// OptimizedStorage represents a comprehensive solution for optimized storage of asset data.
type OptimizedStorage struct {
	Shell *shell.Shell
}

// NewOptimizedStorage initializes a new OptimizedStorage.
func NewOptimizedStorage(ipfsAddr string) *OptimizedStorage {
	return &OptimizedStorage{
		Shell: shell.NewShell(ipfsAddr),
	}
}

// StoreData stores data in IPFS with encryption and returns the corresponding IPFS hash.
func (storage *OptimizedStorage) StoreData(data []byte, passphrase string) (string, string, error) {
	encryptedData, salt, err := EncryptData(data, passphrase)
	if err != nil {
		return "", "", err
	}

	hash, err := storage.Shell.Add(bytes.NewReader(encryptedData))
	if err != nil {
		return "", "", err
	}

	return hash, salt, nil
}

// RetrieveData retrieves and decrypts data from IPFS using the provided hash and passphrase.
func (storage *OptimizedStorage) RetrieveData(hash, passphrase, salt string) ([]byte, error) {
	dataReader, err := storage.Shell.Cat(hash)
	if err != nil {
		return nil, err
	}

	encryptedData, err := ioutil.ReadAll(dataReader)
	if err != nil {
		return nil, err
	}

	decryptedData, err := DecryptData(encryptedData, passphrase, salt)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// EncryptData encrypts data using AES with Scrypt for key derivation.
func EncryptData(plaintext []byte, passphrase string) ([]byte, string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, hex.EncodeToString(salt), nil
}

// DecryptData decrypts data using AES with Scrypt for key derivation.
func DecryptData(ciphertext []byte, passphrase string, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ArchiveData archives data locally before uploading to IPFS for additional redundancy.
func (storage *OptimizedStorage) ArchiveData(data []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// RetrieveArchivedData retrieves data from a local archive file.
func RetrieveArchivedData(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ExampleUsage demonstrates how to use the OptimizedStorage with encryption, decryption, and local archiving.
func ExampleUsage() {
	ipfsAddr := "localhost:5001"
	storage := NewOptimizedStorage(ipfsAddr)

	// Data to be stored
	data := []byte("This is a secret asset data")

	// Archive data locally
	localFilePath := "local_archive.dat"
	err := storage.ArchiveData(data, localFilePath)
	if err != nil {
		log.Fatalf("Error archiving data: %v", err)
	}

	fmt.Println("Data archived locally at:", localFilePath)

	// Retrieve data from local archive
	archivedData, err := RetrieveArchivedData(localFilePath)
	if err != nil {
		log.Fatalf("Error retrieving archived data: %v", err)
	}

	fmt.Println("Retrieved Archived Data:", string(archivedData))

	// Store data in IPFS
	ipfsHash, salt, err := storage.StoreData(data, "passphrase123")
	if err != nil {
		log.Fatalf("Error storing data in IPFS: %v", err)
	}

	fmt.Println("Data stored in IPFS with hash:", ipfsHash)

	// Retrieve data from IPFS
	retrievedData, err := storage.RetrieveData(ipfsHash, "passphrase123", salt)
	if err != nil {
		log.Fatalf("Error retrieving data from IPFS: %v", err)
	}

	fmt.Println("Retrieved Data from IPFS:", string(retrievedData))
}
