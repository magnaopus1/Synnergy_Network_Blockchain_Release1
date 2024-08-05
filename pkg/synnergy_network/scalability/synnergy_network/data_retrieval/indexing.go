package data_retrieval

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
	"log"
	"sync"
	"time"
)

// IndexItem represents a single item in the index.
type IndexItem struct {
	Key       string
	Timestamp int64
	Data      []byte
}

// Index represents a thread-safe in-memory index with optional data encryption.
type Index struct {
	items map[string]*IndexItem
	mu    sync.RWMutex
	key   []byte
}

// NewIndex initializes a new Index with an optional passphrase for data encryption.
func NewIndex(passphrase string) (*Index, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &Index{
		items: make(map[string]*IndexItem),
		key:   key,
	}, nil
}

// Add adds an item to the index.
func (i *Index) Add(key string, data []byte) error {
	encryptedData, err := encrypt(data, i.key)
	if err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	i.items[key] = &IndexItem{
		Key:       key,
		Timestamp: time.Now().UnixNano(),
		Data:      encryptedData,
	}

	return nil
}

// Get retrieves an item from the index.
func (i *Index) Get(key string) ([]byte, bool, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	item, found := i.items[key]
	if !found {
		return nil, false, nil
	}

	decryptedData, err := decrypt(item.Data, i.key)
	if err != nil {
		return nil, false, err
	}

	return decryptedData, true, nil
}

// Delete removes an item from the index.
func (i *Index) Delete(key string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	delete(i.items, key)
}

// Clear removes all items from the index.
func (i *Index) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.items = make(map[string]*IndexItem)
}

// Export exports the entire index to a JSON file.
func (i *Index) Export(filename string) error {
	i.mu.RLock()
	defer i.mu.RUnlock()

	data, err := json.Marshal(i.items)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports an index from a JSON file.
func (i *Index) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	var items map[string]*IndexItem
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	i.items = items

	return nil
}

// generateKey derives a key from the given passphrase using Argon2.
func generateKey(passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// encrypt encrypts the given data with the provided key using AES.
func encrypt(data, key []byte) ([]byte, error) {
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

// decrypt decrypts the given data with the provided key using AES.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// saveToFile saves the data to a file.
func saveToFile(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// loadFromFile loads the data from a file.
func loadFromFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}
