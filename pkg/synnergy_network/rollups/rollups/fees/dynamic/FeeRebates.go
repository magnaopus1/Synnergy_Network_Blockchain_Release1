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

// FeeRebateEntry represents an entry for fee rebates
type FeeRebateEntry struct {
    ID            string
    TransactionID string
    OriginalFee   float64
    RebateAmount  float64
    NetFee        float64
    Timestamp     time.Time
    DataHash      string
    EncryptedData string
}

// FeeRebates handles dynamic fee rebates
type FeeRebates struct {
    RebateEntries map[string]FeeRebateEntry
    mutex         sync.Mutex
}

// NewFeeRebates initializes a new FeeRebates
func NewFeeRebates() *FeeRebates {
    return &FeeRebates{
        RebateEntries: make(map[string]FeeRebateEntry),
    }
}

// CreateRebateEntry creates a new rebate entry with encryption
func (fr *FeeRebates) CreateRebateEntry(transactionID string, originalFee, rebateAmount float64, secret string) (string, error) {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    id := uuid.New().String()
    netFee := originalFee - rebateAmount
    data := fmt.Sprintf("%s:%f:%f:%f", transactionID, originalFee, rebateAmount, netFee)
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    entry := FeeRebateEntry{
        ID:            id,
        TransactionID: transactionID,
        OriginalFee:   originalFee,
        RebateAmount:  rebateAmount,
        NetFee:        netFee,
        Timestamp:     time.Now(),
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    fr.RebateEntries[id] = entry
    return id, nil
}

// VerifyRebateEntry verifies the integrity of a rebate entry
func (fr *FeeRebates) VerifyRebateEntry(id, data string) (bool, error) {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    entry, exists := fr.RebateEntries[id]
    if !exists {
        return false, errors.New("rebate entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == entry.DataHash, nil
}

// GetRebateEntry retrieves a rebate entry by ID and decrypts it
func (fr *FeeRebates) GetRebateEntry(id, secret string) (FeeRebateEntry, error) {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    entry, exists := fr.RebateEntries[id]
    if !exists {
        return FeeRebateEntry{}, errors.New("rebate entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return FeeRebateEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListRebateEntries lists all rebate entries
func (fr *FeeRebates) ListRebateEntries() []FeeRebateEntry {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    entries := []FeeRebateEntry{}
    for _, entry := range fr.RebateEntries {
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

// GenerateSignature generates a signature for the rebate entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
