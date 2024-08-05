package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ipfs/go-ipfs-api"
	"golang.org/x/crypto/scrypt"
)

// IPFSStorage represents the integration with IPFS for storing asset data
type IPFSStorage struct {
	Shell *shell.Shell
}

// NewIPFSStorage initializes a new IPFSStorage
func NewIPFSStorage(ipfsAddr string) *IPFSStorage {
	return &IPFSStorage{
		Shell: shell.NewShell(ipfsAddr),
	}
}

// StoreData stores data in IPFS and returns the corresponding IPFS hash
func (storage *IPFSStorage) StoreData(data []byte, passphrase string) (string, string, error) {
	encryptedData, salt, err := EncryptData(string(data), passphrase)
	if err != nil {
		return "", "", err
	}

	hash, err := storage.Shell.Add(shell.NewBuffer(strings.NewReader(encryptedData)))
	if err != nil {
		return "", "", err
	}
	return hash, salt, nil
}

// RetrieveData retrieves and decrypts data from IPFS using the provided hash and passphrase
func (storage *IPFSStorage) RetrieveData(hash, passphrase, salt string) ([]byte, error) {
	encryptedData, err := storage.Shell.Cat(hash)
	if err != nil {
		return nil, err
	}

	decryptedData, err := DecryptData(encryptedData, passphrase, salt)
	if err != nil {
		return nil, err
	}

	return []byte(decryptedData), nil
}

// EncryptData encrypts data using AES with Scrypt for key derivation
func EncryptData(plaintext string, passphrase string) (string, string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), hex.EncodeToString(salt), nil
}

// DecryptData decrypts data using AES with Scrypt for key derivation
func DecryptData(ciphertextHex string, passphrase string, saltHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ExampleUsage demonstrates how to use the IPFSStorage with encryption and decryption
func ExampleUsage() {
	ipfsAddr := "localhost:5001"
	storage := NewIPFSStorage(ipfsAddr)

	// Data to be stored
	data := []byte("This is a secret asset data")

	// Store data in IPFS
	ipfsHash, salt, err := storage.StoreData(data, "passphrase123")
	if err != nil {
		fmt.Println("Error storing data:", err)
		return
	}

	fmt.Println("Data stored in IPFS with hash:", ipfsHash)

	// Retrieve data from IPFS
	retrievedData, err := storage.RetrieveData(ipfsHash, "passphrase123", salt)
	if err != nil {
		fmt.Println("Error retrieving data:", err)
		return
	}

	fmt.Println("Retrieved Data:", string(retrievedData))
}

