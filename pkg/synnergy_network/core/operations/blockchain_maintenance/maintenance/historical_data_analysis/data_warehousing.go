package historical_data_analysis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/synnergy_network/utils/encryption_utils"
	"github.com/synnergy_network/utils/logging_utils"
	"github.com/synnergy_network/utils/monitoring_utils"
)

// DataWarehouse represents the structure for managing historical data warehousing.
type DataWarehouse struct {
	storageBackend StorageBackend
	encryptionKey  []byte
}

// StorageBackend interface for different types of storage backends.
type StorageBackend interface {
	Store(data []byte, key string) error
	Retrieve(key string) ([]byte, error)
	Delete(key string) error
	ListKeys() ([]string, error)
}

// NewDataWarehouse creates a new instance of DataWarehouse.
func NewDataWarehouse(storage StorageBackend, encryptionKey []byte) *DataWarehouse {
	return &DataWarehouse{
		storageBackend: storage,
		encryptionKey:  encryptionKey,
	}
}

// StoreData stores data in the warehouse with encryption.
func (dw *DataWarehouse) StoreData(data []byte, key string) error {
	encryptedData, err := encrypt(data, dw.encryptionKey)
	if err != nil {
		logging_utils.LogError("Failed to encrypt data", err)
		return err
	}

	err = dw.storageBackend.Store(encryptedData, key)
	if err != nil {
		logging_utils.LogError("Failed to store data", err)
		return err
	}

	monitoring_utils.RecordMetrics("data_store_success", 1)
	return nil
}

// RetrieveData retrieves data from the warehouse and decrypts it.
func (dw *DataWarehouse) RetrieveData(key string) ([]byte, error) {
	encryptedData, err := dw.storageBackend.Retrieve(key)
	if err != nil {
		logging_utils.LogError("Failed to retrieve data", err)
		return nil, err
	}

	data, err := decrypt(encryptedData, dw.encryptionKey)
	if err != nil {
		logging_utils.LogError("Failed to decrypt data", err)
		return nil, err
	}

	monitoring_utils.RecordMetrics("data_retrieve_success", 1)
	return data, nil
}

// DeleteData deletes data from the warehouse.
func (dw *DataWarehouse) DeleteData(key string) error {
	err := dw.storageBackend.Delete(key)
	if err != nil {
		logging_utils.LogError("Failed to delete data", err)
		return err
	}

	monitoring_utils.RecordMetrics("data_delete_success", 1)
	return nil
}

// ListDataKeys lists all the keys in the warehouse.
func (dw *DataWarehouse) ListDataKeys() ([]string, error) {
	keys, err := dw.storageBackend.ListKeys()
	if err != nil {
		logging_utils.LogError("Failed to list data keys", err)
		return nil, err
	}

	return keys, nil
}

// Encrypt data using AES encryption.
func encrypt(data []byte, key []byte) ([]byte, error) {
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

// Decrypt data using AES encryption.
func decrypt(data []byte, key []byte) ([]byte, error) {
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

// ExampleStorageBackend is a simple implementation of the StorageBackend interface for demonstration.
type ExampleStorageBackend struct {
	data map[string][]byte
}

// NewExampleStorageBackend creates a new ExampleStorageBackend.
func NewExampleStorageBackend() *ExampleStorageBackend {
	return &ExampleStorageBackend{data: make(map[string][]byte)}
}

// Store stores data in the backend.
func (esb *ExampleStorageBackend) Store(data []byte, key string) error {
	esb.data[key] = data
	return nil
}

// Retrieve retrieves data from the backend.
func (esb *ExampleStorageBackend) Retrieve(key string) ([]byte, error) {
	data, exists := esb.data[key]
	if !exists {
		return nil, errors.New("data not found")
	}
	return data, nil
}

// Delete deletes data from the backend.
func (esb *ExampleStorageBackend) Delete(key string) error {
	delete(esb.data, key)
	return nil
}

// ListKeys lists all keys in the backend.
func (esb *ExampleStorageBackend) ListKeys() ([]string, error) {
	keys := make([]string, 0, len(esb.data))
	for key := range esb.data {
		keys = append(keys, key)
	}
	return keys, nil
}

func main() {
	// Initialize a new data warehouse with example storage backend and an encryption key.
	encryptionKey := []byte("a very very very very secret key") // 32 bytes for AES-256
	warehouse := NewDataWarehouse(NewExampleStorageBackend(), encryptionKey)

	// Store some data.
	data := []byte("example data to be stored")
	err := warehouse.StoreData(data, "example_key")
	if err != nil {
		log.Fatalf("Failed to store data: %v", err)
	}

	// Retrieve the stored data.
	retrievedData, err := warehouse.RetrieveData("example_key")
	if err != nil {
		log.Fatalf("Failed to retrieve data: %v", err)
	}
	fmt.Printf("Retrieved data: %s\n", retrievedData)

	// List data keys.
	keys, err := warehouse.ListDataKeys()
	if err != nil {
		log.Fatalf("Failed to list data keys: %v", err)
	}
	fmt.Printf("Data keys: %v\n", keys)

	// Delete the data.
	err = warehouse.DeleteData("example_key")
	if err != nil {
		log.Fatalf("Failed to delete data: %v", err)
	}
}
