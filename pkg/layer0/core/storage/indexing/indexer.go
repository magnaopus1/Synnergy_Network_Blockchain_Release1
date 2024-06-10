package indexing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"synthron_blockchain/pkg/layer0/core/storage"
)

// Indexer handles indexing and querying blockchain data
type Indexer struct {
	db           storage.Database
	indexMutex   sync.RWMutex
	indexes      map[string]*Index
	dataChannels map[string]chan []byte
}

// NewIndexer creates a new Indexer
func NewIndexer(db storage.Database) *Indexer {
	return &Indexer{
		db:           db,
		indexes:      make(map[string]*Index),
		dataChannels: make(map[string]chan []byte),
	}
}

// Index defines the structure for blockchain data indexes
type Index struct {
	Key       string
	Data      map[string]interface{}
	UpdatedAt time.Time
}

// BuildIndex constructs an index for a specific key using provided data
func (idx *Indexer) BuildIndex(key string, data []byte) error {
	idx.indexMutex.Lock()
	defer idx.indexMutex.Unlock()

	// Decrypt data for indexing if needed
	decryptedData, err := idx.decryptData(data)
	if err != nil {
		return fmt.Errorf("error decrypting data: %w", err)
	}

	var content map[string]interface{}
	if err := json.Unmarshal(decryptedData, &content); err != nil {
		return fmt.Errorf("error unmarshalling data: %w", err)
	}

	// Create or update the index
	index, exists := idx.indexes[key]
	if !exists {
		index = &Index{
			Key: key,
			Data: content,
			UpdatedAt: time.Now(),
		}
		idx.indexes[key] = index
	} else {
		index.Data = content
		index.UpdatedAt = time.Now()
	}

	return nil
}

// QueryIndex retrieves data based on the specified key
func (idx *Indexer) QueryIndex(key string) ([]byte, error) {
	idx.indexMutex.RLock()
	defer idx.indexMutex.RUnlock()

	index, exists := idx.indexes[key]
	if !exists {
		return nil, fmt.Errorf("no index found for key: %s", key)
	}

	data, err := json.Marshal(index.Data)
	if err != nil {
		return nil, fmt.Errorf("error marshalling data: %w", err)
	}

	// Encrypt data for security if needed
	encryptedData, err := idx.encryptData(data)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	return encryptedData, nil
}

// encryptData encrypts data using AES-256
func (idx *Indexer) encryptData(data []byte) ([]byte, error) {
	key := []byte("the-key-has-to-be-32-bytes-long!")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// decryptData decrypts data using AES-256
func (idx *Indexer) decryptData(data []byte) ([]byte, error) {
	key := []byte("the-key-has-to-be-32-bytes-long!")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// Setup and demonstration of usage
	db := storage.NewDatabase() // Placeholder for database setup
	indexer := NewIndexer(db)

	// Example data
	data := []byte(`{"transactionId":"123", "amount": "1000", "currency":"USD"}`)
	indexer.BuildIndex("transaction123", data)

	// Query the built index
	if queriedData, err := indexer.QueryIndex("transaction123"); err != nil {
		fmt.Println("Error querying index:", err)
	} else {
		fmt.Println("Queried Data:", string(queriedData))
	}
}
