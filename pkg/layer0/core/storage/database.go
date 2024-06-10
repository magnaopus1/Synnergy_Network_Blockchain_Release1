package storage

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"

    "github.com/dgraph-io/badger/v3"
)

// BlockchainDatabase encapsulates the database operations with security and performance optimizations.
type BlockchainDatabase struct {
    db         *badger.DB
    encryption cipher.Block
    mutex      sync.RWMutex
}

// NewBlockchainDatabase creates a new instance of BlockchainDatabase with initialized encryption.
func NewDatabase(dbPath string, encryptionKey string) (*BlockchainDatabase, error) {
    opts := badger.DefaultOptions(dbPath)
    db, err := badger.Open(opts)
    if err != nil {
        return nil, err
    }

    key := sha256.Sum256([]byte(encryptionKey))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, err
    }

    return &BlockchainDatabase{
        db:         db,
        encryption: block,
    }, nil
}

// Set encrypts and stores data with a given key.
func (db *BlockchainDatabase) Set(key, data []byte) error {
    db.mutex.Lock()
    defer db.mutex.Unlock()

    encryptedData, err := db.encryptData(data)
    if err != nil {
        return err
    }

    err = db.db.Update(func(txn *badger.Txn) error {
        return txn.Set(key, encryptedData)
    })

    return err
}

// Get retrieves and decrypts data for a given key.
func (db *BlockchainDatabase) Get(key []byte) ([]byte, error) {
    db.mutex.RLock()
    defer db.mutex.RUnlock()

    var data []byte
    err := db.db.View(func(txn *badger.Txn) error {
        item, err := txn.Get(key)
        if err != nil {
            return err
        }
        data, err = item.ValueCopy(nil)
        return err
    })
    if err != nil {
        return nil, err
    }

    return db.decryptData(data)
}

// encryptData uses AES to encrypt data.
func (db *BlockchainDatabase) encryptData(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(db.encryption)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    // In a production system, populate nonce with a cryptographically secure random sequence
    return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptData decrypts data using AES.
func (db *BlockchainDatabase) decryptData(data []byte) ([]byte, error) {
    gcm, err := cipher.NewGCM(db.encryption)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, err
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// Close safely closes the database connection.
func (db *BlockchainDatabase) Close() error {
    return db.db.Close()
}
