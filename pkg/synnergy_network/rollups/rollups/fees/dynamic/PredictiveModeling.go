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

// PredictiveModelEntry represents an entry for predictive modeling
type PredictiveModelEntry struct {
    ID            string
    TransactionID string
    BaseFee       float64
    PredictedFee  float64
    TotalFee      float64
    Timestamp     time.Time
    DataHash      string
    EncryptedData string
}

// PredictiveModeling handles dynamic predictive modeling
type PredictiveModeling struct {
    ModelEntries map[string]PredictiveModelEntry
    mutex        sync.Mutex
}

// NewPredictiveModeling initializes a new PredictiveModeling
func NewPredictiveModeling() *PredictiveModeling {
    return &PredictiveModeling{
        ModelEntries: make(map[string]PredictiveModelEntry),
    }
}

// CreateModelEntry creates a new predictive modeling entry with encryption
func (pm *PredictiveModeling) CreateModelEntry(transactionID string, baseFee, predictedFee float64, secret string) (string, error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()

    id := uuid.New().String()
    totalFee := baseFee + predictedFee
    data := fmt.Sprintf("%s:%f:%f:%f", transactionID, baseFee, predictedFee, totalFee)
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    entry := PredictiveModelEntry{
        ID:            id,
        TransactionID: transactionID,
        BaseFee:       baseFee,
        PredictedFee:  predictedFee,
        TotalFee:      totalFee,
        Timestamp:     time.Now(),
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    pm.ModelEntries[id] = entry
    return id, nil
}

// VerifyModelEntry verifies the integrity of a predictive modeling entry
func (pm *PredictiveModeling) VerifyModelEntry(id, data string) (bool, error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()

    entry, exists := pm.ModelEntries[id]
    if !exists {
        return false, errors.New("predictive modeling entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == entry.DataHash, nil
}

// GetModelEntry retrieves a predictive modeling entry by ID and decrypts it
func (pm *PredictiveModeling) GetModelEntry(id, secret string) (PredictiveModelEntry, error) {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()

    entry, exists := pm.ModelEntries[id]
    if !exists {
        return PredictiveModelEntry{}, errors.New("predictive modeling entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return PredictiveModelEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListModelEntries lists all predictive modeling entries
func (pm *PredictiveModeling) ListModelEntries() []PredictiveModelEntry {
    pm.mutex.Lock()
    defer pm.mutex.Unlock()

    entries := []PredictiveModelEntry{}
    for _, entry := range pm.ModelEntries {
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

// GenerateSignature generates a signature for the predictive modeling entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
