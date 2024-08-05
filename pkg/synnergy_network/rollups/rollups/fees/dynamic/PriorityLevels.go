package dynamic

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/argon2"
)

// PriorityLevel represents a priority level for transactions
type PriorityLevel int

const (
    Low PriorityLevel = iota
    Medium
    High
)

// PriorityLevelEntry represents an entry for priority levels
type PriorityLevelEntry struct {
    ID            string
    TransactionID string
    BaseFee       float64
    Priority      PriorityLevel
    PriorityFee   float64
    TotalFee      float64
    Timestamp     time.Time
    DataHash      string
    EncryptedData string
}

// PriorityLevels handles dynamic priority levels
type PriorityLevels struct {
    PriorityEntries map[string]PriorityLevelEntry
    mutex           sync.Mutex
}

// NewPriorityLevels initializes a new PriorityLevels
func NewPriorityLevels() *PriorityLevels {
    return &PriorityLevels{
        PriorityEntries: make(map[string]PriorityLevelEntry),
    }
}

// CreatePriorityEntry creates a new priority level entry with encryption
func (pl *PriorityLevels) CreatePriorityEntry(transactionID string, baseFee float64, priority PriorityLevel, priorityFee float64, secret string) (string, error) {
    pl.mutex.Lock()
    defer pl.mutex.Unlock()

    id := uuid.New().String()
    totalFee := baseFee + priorityFee
    data := fmt.Sprintf("%s:%f:%d:%f:%f", transactionID, baseFee, priority, priorityFee, totalFee)
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    entry := PriorityLevelEntry{
        ID:            id,
        TransactionID: transactionID,
        BaseFee:       baseFee,
        Priority:      priority,
        PriorityFee:   priorityFee,
        TotalFee:      totalFee,
        Timestamp:     time.Now(),
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    pl.PriorityEntries[id] = entry
    return id, nil
}

// VerifyPriorityEntry verifies the integrity of a priority level entry
func (pl *PriorityLevels) VerifyPriorityEntry(id, data string) (bool, error) {
    pl.mutex.Lock()
    defer pl.mutex.Unlock()

    entry, exists := pl.PriorityEntries[id]
    if !exists {
        return false, errors.New("priority level entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == entry.DataHash, nil
}

// GetPriorityEntry retrieves a priority level entry by ID and decrypts it
func (pl *PriorityLevels) GetPriorityEntry(id, secret string) (PriorityLevelEntry, error) {
    pl.mutex.Lock()
    defer pl.mutex.Unlock()

    entry, exists := pl.PriorityEntries[id]
    if !exists {
        return PriorityLevelEntry{}, errors.New("priority level entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return PriorityLevelEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListPriorityEntries lists all priority level entries
func (pl *PriorityLevels) ListPriorityEntries() []PriorityLevelEntry {
    pl.mutex.Lock()
    defer pl.mutex.Unlock()

    entries := []PriorityLevelEntry{}
    for _, entry := range pl.PriorityEntries {
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

// GenerateSignature generates a signature for the priority level entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
