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
	"io"
	"log"
	"sync"
	"time"
)

// PrefetchItem represents a single item in the prefetch cache.
type PrefetchItem struct {
	Key       string
	Timestamp int64
	Data      []byte
}

// PrefetchCache represents a thread-safe in-memory prefetch cache with optional data encryption.
type PrefetchCache struct {
	items map[string]*PrefetchItem
	mu    sync.RWMutex
	key   []byte
}

// NewPrefetchCache initializes a new PrefetchCache with an optional passphrase for data encryption.
func NewPrefetchCache(passphrase string) (*PrefetchCache, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &PrefetchCache{
		items: make(map[string]*PrefetchItem),
		key:   key,
	}, nil
}

// Add adds an item to the prefetch cache.
func (pc *PrefetchCache) Add(key string, data []byte) error {
	encryptedData, err := encrypt(data, pc.key)
	if err != nil {
		return err
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.items[key] = &PrefetchItem{
		Key:       key,
		Timestamp: time.Now().UnixNano(),
		Data:      encryptedData,
	}

	return nil
}

// Get retrieves an item from the prefetch cache.
func (pc *PrefetchCache) Get(key string) ([]byte, bool, error) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	item, found := pc.items[key]
	if !found {
		return nil, false, nil
	}

	decryptedData, err := decrypt(item.Data, pc.key)
	if err != nil {
		return nil, false, err
	}

	return decryptedData, true, nil
}

// Delete removes an item from the prefetch cache.
func (pc *PrefetchCache) Delete(key string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	delete(pc.items, key)
}

// Clear removes all items from the prefetch cache.
func (pc *PrefetchCache) Clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.items = make(map[string]*PrefetchItem)
}

// Export exports the entire prefetch cache to a JSON file.
func (pc *PrefetchCache) Export(filename string) error {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	data, err := json.Marshal(pc.items)
	if err != nil {
		return err
	}

	return saveToFile(filename, data)
}

// Import imports a prefetch cache from a JSON file.
func (pc *PrefetchCache) Import(filename string) error {
	data, err := loadFromFile(filename)
	if err != nil {
		return err
	}

	var items map[string]*PrefetchItem
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.items = items

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

// GC runs garbage collection to remove expired items from the prefetch cache.
func (pc *PrefetchCache) GC(ttl time.Duration) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	now := time.Now().UnixNano()
	for key, item := range pc.items {
		if now-item.Timestamp > int64(ttl) {
			delete(pc.items, key)
		}
	}
}

// StartGC starts the garbage collection process to run periodically.
func (pc *PrefetchCache) StartGC(interval, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				pc.GC(ttl)
			}
		}
	}()
}

// StopGC stops the garbage collection process.
func (pc *PrefetchCache) StopGC() {
	ticker := time.NewTicker(0)
	ticker.Stop()
}
