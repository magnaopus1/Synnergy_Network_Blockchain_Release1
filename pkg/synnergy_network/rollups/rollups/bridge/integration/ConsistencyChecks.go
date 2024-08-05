package integration

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

// ConsistencyCheckEntry represents a consistency check entry
type ConsistencyCheckEntry struct {
    ID            string
    ChainID       string
    Timestamp     time.Time
    Status        string
    DataHash      string
    EncryptedData string
}

// ConsistencyChecks handles consistency checks between blockchains
type ConsistencyChecks struct {
    Checks map[string]ConsistencyCheckEntry
}

// NewConsistencyChecks initializes a new ConsistencyChecks
func NewConsistencyChecks() *ConsistencyChecks {
    return &ConsistencyChecks{
        Checks: make(map[string]ConsistencyCheckEntry),
    }
}

// CreateConsistencyCheck creates a new consistency check with encryption
func (cc *ConsistencyChecks) CreateConsistencyCheck(chainID, data, secret string) (string, error) {
    id := uuid.New().String()
    dataHash := createHash(data)
    encryptedData, err := encryptData(secret, data)
    if err != nil {
        return "", err
    }
    check := ConsistencyCheckEntry{
        ID:            id,
        ChainID:       chainID,
        Timestamp:     time.Now(),
        Status:        "pending",
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    cc.Checks[id] = check
    return id, nil
}

// VerifyConsistencyCheck verifies the integrity of a consistency check entry
func (cc *ConsistencyChecks) VerifyConsistencyCheck(id, data string) (bool, error) {
    check, exists := cc.Checks[id]
    if !exists {
        return false, errors.New("consistency check entry does not exist")
    }
    dataHash := createHash(data)
    return dataHash == check.DataHash, nil
}

// CompleteConsistencyCheck completes a consistency check
func (cc *ConsistencyChecks) CompleteConsistencyCheck(id string) error {
    check, exists := cc.Checks[id]
    if !exists {
        return errors.New("consistency check entry does not exist")
    }
    if check.Status != "pending" {
        return errors.New("consistency check is not pending")
    }
    check.Status = "completed"
    cc.Checks[id] = check
    return nil
}

// GetConsistencyCheck retrieves a consistency check entry by ID and decrypts it
func (cc *ConsistencyChecks) GetConsistencyCheck(id, secret string) (ConsistencyCheckEntry, error) {
    check, exists := cc.Checks[id]
    if !exists {
        return ConsistencyCheckEntry{}, errors.New("consistency check entry does not exist")
    }
    decryptedData, err := decryptData(secret, check.EncryptedData)
    if err != nil {
        return ConsistencyCheckEntry{}, err
    }
    check.EncryptedData = decryptedData
    return check, nil
}

// ListConsistencyChecks lists all consistency check entries
func (cc *ConsistencyChecks) ListConsistencyChecks() []ConsistencyCheckEntry {
    checks := []ConsistencyCheckEntry{}
    for _, check := range cc.Checks {
        checks = append(checks, check)
    }
    return checks
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

// GenerateSignature generates a signature for the consistency check entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
