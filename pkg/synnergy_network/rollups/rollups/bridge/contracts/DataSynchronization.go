package contracts

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// DataSyncEntry represents an entry in the data synchronization log
type DataSyncEntry struct {
    ID            string
    Source        string
    Destination   string
    Timestamp     time.Time
    DataHash      string
    EncryptedData string
}

// DataSynchronization provides tools for synchronizing data across the blockchain
type DataSynchronization struct {
    SyncLog map[string]DataSyncEntry
}

// NewDataSynchronization initializes a new DataSynchronization
func NewDataSynchronization() *DataSynchronization {
    return &DataSynchronization{
        SyncLog: make(map[string]DataSyncEntry),
    }
}

// CreateDataSyncEntry creates a new data synchronization entry with encryption
func (ds *DataSynchronization) CreateDataSyncEntry(source, destination, data, secret string) (string, error) {
    id := uuid.New().String()
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    dataHash := createHash(data)
    entry := DataSyncEntry{
        ID:            id,
        Source:        source,
        Destination:   destination,
        Timestamp:     time.Now(),
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    ds.SyncLog[id] = entry
    return id, nil
}

// VerifyDataSyncEntry verifies the integrity of a data synchronization entry
func (ds *DataSynchronization) VerifyDataSyncEntry(id, data string) (bool, error) {
    entry, exists := ds.SyncLog[id]
    if !exists {
        return false, errors.New("data sync entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == entry.DataHash, nil
}

// GetDataSyncEntry retrieves a data synchronization entry by ID and decrypts it
func (ds *DataSynchronization) GetDataSyncEntry(id, secret string) (DataSyncEntry, error) {
    entry, exists := ds.SyncLog[id]
    if !exists {
        return DataSyncEntry{}, errors.New("data sync entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return DataSyncEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListDataSyncEntries lists all data synchronization entries
func (ds *DataSynchronization) ListDataSyncEntries() []DataSyncEntry {
    entries := []DataSyncEntry{}
    for _, entry := range ds.SyncLog {
        entries = append(entries, entry)
    }
    return entries
}

// EncryptData encrypts the given data using AES
func encryptData(secret, data string) (string, error) {
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, aesGCM.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
    return hex.EncodeToString(encrypted), nil
}

// DecryptData decrypts the given data using AES
func decryptData(secret, encryptedData string) (string, error) {
    data, err := hex.DecodeString(encryptedData)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher([]byte(createHash(secret)))
    if err != nil {
        return "", err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := aesGCM.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(decrypted), nil
}

// CreateHash creates a hash from the secret key
func createHash(key string) string {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}

// GenerateSignature generates a signature for the data synchronization entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
