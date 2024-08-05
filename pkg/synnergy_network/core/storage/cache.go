package storage

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"
    "github.com/patrickmn/go-cache"
    "golang.org/x/crypto/scrypt"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
    "errors"
)

// Cache is the main structure for our caching mechanism
type Cache struct {
    memoryCache *cache.Cache
    lock        sync.RWMutex
    encryptionKey []byte
}

// NewCache creates a new instance of Cache
func NewCache(defaultExpiration, cleanupInterval time.Duration, encryptionKey string) *Cache {
    return &Cache{
        memoryCache: cache.New(defaultExpiration, cleanupInterval),
        encryptionKey: []byte(encryptionKey),
    }
}

// Set adds an item to the cache, with optional encryption
func (c *Cache) Set(key string, value interface{}, encrypted bool) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if encrypted {
        encryptedValue, err := c.encryptValue(value)
        if err != nil {
            return err
        }
        c.memoryCache.Set(key, encryptedValue, cache.DefaultExpiration)
    } else {
        c.memoryCache.Set(key, value, cache.DefaultExpiration)
    }

    return nil
}

// Get retrieves an item from the cache, decrypting if necessary
func (c *Cache) Get(key string, encrypted bool) (interface{}, bool, error) {
    c.lock.RLock()
    defer c.lock.RUnlock()

    cachedValue, found := c.memoryCache.Get(key)
    if !found {
        return nil, false, nil
    }

    if encrypted {
        decryptedValue, err := c.decryptValue(cachedValue)
        if err != nil {
            return nil, false, err
        }
        return decryptedValue, true, nil
    }

    return cachedValue, true, nil
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
    c.lock.Lock()
    defer c.lock.Unlock()
    c.memoryCache.Delete(key)
}

// encryptValue encrypts the value before caching
func (c *Cache) encryptValue(value interface{}) ([]byte, error) {
    serializedValue, err := serialize(value)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(c.encryptionKey)
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

    ciphertext := gcm.Seal(nonce, nonce, serializedValue, nil)
    return ciphertext, nil
}

// decryptValue decrypts the cached value
func (c *Cache) decryptValue(data interface{}) (interface{}, error) {
    ciphertext, ok := data.([]byte)
    if !ok {
        return nil, errors.New("invalid data format")
    }

    block, err := aes.NewCipher(c.encryptionKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return deserialize(plaintext)
}

// serialize serializes the value for storage
func serialize(value interface{}) ([]byte, error) {
    // Implement serialization logic
    // This is just a placeholder
    return json.Marshal(value)
}

// deserialize deserializes the value after retrieval
func deserialize(data []byte) (interface{}, error) {
    // Implement deserialization logic
    // This is just a placeholder
    var value interface{}
    err := json.Unmarshal(data, &value)
    return value, err
}

// HashKey hashes the key to ensure consistent length and format
func HashKey(key string) string {
    hash := sha256.New()
    hash.Write([]byte(key))
    return hex.EncodeToString(hash.Sum(nil))
}

// PasswordHashing hashes a password using scrypt
func PasswordHashing(password, salt string) (string, error) {
    hashedPassword, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hashedPassword), nil
}
