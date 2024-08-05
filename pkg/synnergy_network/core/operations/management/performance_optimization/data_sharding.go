package performance_optimization

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "os"
    "sync"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// Shard represents a single shard in the blockchain.
type Shard struct {
    ID        string
    Data      map[string]interface{}
    Encrypted bool
}

// Blockchain represents the complete blockchain with sharding.
type Blockchain struct {
    Shards       map[string]*Shard
    Mutex        sync.Mutex
    CipherKey    []byte
    ShardCount   int
    ShardSize    int
    ShardMapping map[string]string // Map from data ID to shard ID
}

// NewBlockchain initializes a new Blockchain.
func NewBlockchain(shardCount int, shardSize int, password string) *Blockchain {
    cipherKey := deriveKey(password)
    return &Blockchain{
        Shards:       make(map[string]*Shard),
        CipherKey:    cipherKey,
        ShardCount:   shardCount,
        ShardSize:    shardSize,
        ShardMapping: make(map[string]string),
    }
}

// deriveKey derives a key from the given password using scrypt.
func deriveKey(password string) []byte {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        log.Fatalf("Failed to generate salt: %v", err)
    }
    key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    if err != nil {
        log.Fatalf("Failed to derive key: %v", err)
    }
    return key
}

// AddData adds data to the blockchain, automatically determining the appropriate shard.
func (bc *Blockchain) AddData(dataID string, data map[string]interface{}) error {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    shardID := bc.determineShard(dataID)
    shard, exists := bc.Shards[shardID]
    if !exists {
        shard = &Shard{
            ID:   shardID,
            Data: make(map[string]interface{}),
        }
        bc.Shards[shardID] = shard
    }

    if len(shard.Data) >= bc.ShardSize {
        return errors.New("shard is full")
    }

    shard.Data[dataID] = data
    bc.ShardMapping[dataID] = shardID
    return nil
}

// determineShard determines which shard should store the given data ID.
func (bc *Blockchain) determineShard(dataID string) string {
    hash := argon2.IDKey([]byte(dataID), bc.CipherKey, 1, 64*1024, 4, 32)
    return fmt.Sprintf("%x", hash)[:8]
}

// EncryptShard encrypts the data in the specified shard.
func (bc *Blockchain) EncryptShard(shardID string) error {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    shard, exists := bc.Shards[shardID]
    if !exists {
        return errors.New("shard not found")
    }

    if shard.Encrypted {
        return errors.New("shard already encrypted")
    }

    dataBytes, err := json.Marshal(shard.Data)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(bc.CipherKey)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return err
    }

    encryptedData := gcm.Seal(nonce, nonce, dataBytes, nil)
    shard.Data = map[string]interface{}{
        "encrypted_data": encryptedData,
    }
    shard.Encrypted = true

    return nil
}

// DecryptShard decrypts the data in the specified shard.
func (bc *Blockchain) DecryptShard(shardID string) error {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    shard, exists := bc.Shards[shardID]
    if !exists {
        return errors.New("shard not found")
    }

    if !shard.Encrypted {
        return errors.New("shard is not encrypted")
    }

    encryptedData, ok := shard.Data["encrypted_data"].([]byte)
    if !ok {
        return errors.New("invalid encrypted data format")
    }

    block, err := aes.NewCipher(bc.CipherKey)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonceSize := gcm.NonceSize()
    if len(encryptedData) < nonceSize {
        return errors.New("invalid encrypted data size")
    }

    nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
    decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    var data map[string]interface{}
    if err := json.Unmarshal(decryptedData, &data); err != nil {
        return err
    }

    shard.Data = data
    shard.Encrypted = false

    return nil
}

// GetShardData retrieves the data for a specific shard.
func (bc *Blockchain) GetShardData(shardID string) (map[string]interface{}, error) {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    shard, exists := bc.Shards[shardID]
    if !exists {
        return nil, errors.New("shard not found")
    }

    if shard.Encrypted {
        return nil, errors.New("shard is encrypted")
    }

    return shard.Data, nil
}

// SaveShardToFile saves a shard's data to a file.
func (bc *Blockchain) SaveShardToFile(shardID string, filepath string) error {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    shard, exists := bc.Shards[shardID]
    if !exists {
        return errors.New("shard not found")
    }

    dataBytes, err := json.Marshal(shard.Data)
    if err != nil {
        return err
    }

    return os.WriteFile(filepath, dataBytes, 0644)
}

// LoadShardFromFile loads a shard's data from a file.
func (bc *Blockchain) LoadShardFromFile(shardID string, filepath string) error {
    bc.Mutex.Lock()
    defer bc.Mutex.Unlock()

    dataBytes, err := os.ReadFile(filepath)
    if err != nil {
        return err
    }

    var data map[string]interface{}
    if err := json.Unmarshal(dataBytes, &data); err != nil {
        return err
    }

    bc.Shards[shardID] = &Shard{
        ID:        shardID,
        Data:      data,
        Encrypted: false,
    }

    return nil
}
