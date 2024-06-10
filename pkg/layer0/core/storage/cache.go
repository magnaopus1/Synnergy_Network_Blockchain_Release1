package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"synthron_blockchain/pkg/layer0/core/chain"
	"synthron_blockchain/pkg/layer0/core/crypto"
)

// Cache implements a thread-safe in-memory cache for storing blockchain data.
type Cache struct {
	mu       sync.RWMutex
	data     map[string]string // stores data hashes to values
	ttl      map[string]time.Time // stores expiration time for cache items
	lifetime time.Duration
}

// NewCache initializes a new Cache with a default lifetime for items.
func NewCache(defaultLifetime time.Duration) *Cache {
	return &Cache{
		data:     make(map[string]string),
		ttl:      make(map[string]time.Time),
		lifetime: defaultLifetime,
	}
}

// Set stores data in the cache with an associated hash key.
func (c *Cache) Set(key string, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = value
	c.ttl[key] = time.Now().Add(c.lifetime)
}

// Get retrieves data from the cache using a hash key.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if data, found := c.data[key]; found {
		if time.Now().Before(c.ttl[key]) {
			return data, true
		}
	}
	return "", false
}

// Purge checks and removes expired items from the cache.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, expiry := range c.ttl {
		if now.After(expiry) {
			delete(c.data, key)
			delete(c.ttl, key)
		}
	}
}

// HashData generates a SHA-256 hash for given data and uses it as a key in the cache.
func (c *Cache) HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyData ensures the integrity of data retrieved from cache by comparing with its hash key.
func (c *Cache) VerifyData(data string, hashKey string) bool {
	expectedHash := c.HashData([]byte(data))
	return hashKey == expectedHash
}

// SecureSet uses encryption to store data securely in the cache.
func (c *Cache) SecureSet(key string, value string, secretKey []byte) error {
	encryptedValue, err := crypto.EncryptAES(value, secretKey)
	if err != nil {
		return err
	}
	c.Set(key, encryptedValue)
	return nil
}

// SecureGet decrypts data retrieved from the cache.
func (c *Cache) SecureGet(key string, secretKey []byte) (string, bool, error) {
	encryptedValue, found := c.Get(key)
	if !found {
		return "", false, nil
	}

	decryptedValue, err := crypto.DecryptAES(encryptedValue, secretKey)
	if err != nil {
		return "", false, err
	}

	return decryptedValue, true, nil
}
