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

// CongestionPricingEntry represents an entry for congestion pricing
type CongestionPricingEntry struct {
    ID            string
    TransactionID string
    BaseFee       float64
    CongestionFee float64
    TotalFee      float64
    Timestamp     time.Time
    DataHash      string
    EncryptedData string
}

// CongestionPricing handles dynamic congestion pricing
type CongestionPricing struct {
    PricingEntries map[string]CongestionPricingEntry
    mutex          sync.Mutex
}

// NewCongestionPricing initializes a new CongestionPricing
func NewCongestionPricing() *CongestionPricing {
    return &CongestionPricing{
        PricingEntries: make(map[string]CongestionPricingEntry),
    }
}

// CreatePricingEntry creates a new pricing entry with encryption
func (cp *CongestionPricing) CreatePricingEntry(transactionID string, baseFee, congestionFee float64, secret string) (string, error) {
    cp.mutex.Lock()
    defer cp.mutex.Unlock()

    id := uuid.New().String()
    totalFee := baseFee + congestionFee
    data := fmt.Sprintf("%s:%f:%f:%f", transactionID, baseFee, congestionFee, totalFee)
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    entry := CongestionPricingEntry{
        ID:            id,
        TransactionID: transactionID,
        BaseFee:       baseFee,
        CongestionFee: congestionFee,
        TotalFee:      totalFee,
        Timestamp:     time.Now(),
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    cp.PricingEntries[id] = entry
    return id, nil
}

// VerifyPricingEntry verifies the integrity of a pricing entry
func (cp *CongestionPricing) VerifyPricingEntry(id, data string) (bool, error) {
    cp.mutex.Lock()
    defer cp.mutex.Unlock()

    entry, exists := cp.PricingEntries[id]
    if !exists {
        return false, errors.New("pricing entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == entry.DataHash, nil
}

// GetPricingEntry retrieves a pricing entry by ID and decrypts it
func (cp *CongestionPricing) GetPricingEntry(id, secret string) (CongestionPricingEntry, error) {
    cp.mutex.Lock()
    defer cp.mutex.Unlock()

    entry, exists := cp.PricingEntries[id]
    if !exists {
        return CongestionPricingEntry{}, errors.New("pricing entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return CongestionPricingEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListPricingEntries lists all pricing entries
func (cp *CongestionPricing) ListPricingEntries() []CongestionPricingEntry {
    cp.mutex.Lock()
    defer cp.mutex.Unlock()

    entries := []CongestionPricingEntry{}
    for _, entry := range cp.PricingEntries {
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

// GenerateSignature generates a signature for the congestion pricing entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
