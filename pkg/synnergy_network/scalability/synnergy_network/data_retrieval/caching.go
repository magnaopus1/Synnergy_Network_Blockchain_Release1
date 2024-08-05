package data_retrieval

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"sync"
	"time"
)

// CacheItem represents a single item in the cache.
type CacheItem struct {
	Data       []byte
	Expiration int64
}

// Cache represents a thread-safe in-memory cache with optional data encryption.
type Cache struct {
	items map[string]*CacheItem
	mu    sync.RWMutex
	key   []byte
}

// NewCache initializes a new Cache with an optional passphrase for data encryption.
func NewCache(passphrase string) (*Cache, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	return &Cache{
		items: make(map[string]*CacheItem),
		key:   key,
	}, nil
}

// Set adds an item to the cache with an expiration duration.
func (c *Cache) Set(key string, data []byte, duration time.Duration) error {
	encryptedData, err := encrypt(data, c.key)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &CacheItem{
		Data:       encryptedData,
		Expiration: time.Now().Add(duration).UnixNano(),
	}

	return nil
}

// Get retrieves an item from the cache.
func (c *Cache) Get(key string) ([]byte, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found || item.Expired() {
		return nil, false, nil
	}

	decryptedData, err := decrypt(item.Data, c.key)
	if err != nil {
		return nil, false, err
	}

	return decryptedData, true, nil
}

// Delete removes an item from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
}

// Clear removes all items from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*CacheItem)
}

// Expired checks if the cache item has expired.
func (item *CacheItem) Expired() bool {
	return time.Now().UnixNano() > item.Expiration
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

// logError logs errors with additional context.
func logError(context string, err error) {
	if err != nil {
		log.Printf("Error [%s]: %s\n", context, err)
	}
}

// GC runs garbage collection to remove expired items from the cache.
func (c *Cache) GC() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UnixNano()
	for key, item := range c.items {
		if item.Expired() {
			delete(c.items, key)
		}
	}
}

// StartGC starts the garbage collection process to run periodically.
func (c *Cache) StartGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				c.GC()
			}
		}
	}()
}

// StopGC stops the garbage collection process.
func (c *Cache) StopGC() {
	ticker := time.NewTicker(0)
	ticker.Stop()
}
