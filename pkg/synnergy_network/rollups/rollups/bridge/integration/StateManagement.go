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

// StateEntry represents a state entry in the blockchain
type StateEntry struct {
    ID            string
    ChainID       string
    StateData     string
    Timestamp     time.Time
    Status        string
    DataHash      string
    EncryptedData string
}

// StateManagement handles state management between blockchains
type StateManagement struct {
    States map[string]StateEntry
}

// NewStateManagement initializes a new StateManagement
func NewStateManagement() *StateManagement {
    return &StateManagement{
        States: make(map[string]StateEntry),
    }
}

// CreateStateEntry creates a new state entry with encryption
func (sm *StateManagement) CreateStateEntry(chainID, stateData, secret string) (string, error) {
    id := uuid.New().String()
    dataHash := createHash(stateData)
    encryptedData, err := encryptData(secret, stateData)
    if err != nil {
        return "", err
    }
    entry := StateEntry{
        ID:            id,
        ChainID:       chainID,
        StateData:     stateData,
        Timestamp:     time.Now(),
        Status:        "pending",
        DataHash:      dataHash,
        EncryptedData: encryptedData,
    }
    sm.States[id] = entry
    return id, nil
}

// VerifyStateEntry verifies the integrity of a state entry
func (sm *StateManagement) VerifyStateEntry(id, stateData string) (bool, error) {
    entry, exists := sm.States[id]
    if !exists {
        return false, errors.New("state entry does not exist")
    }
    dataHash := createHash(stateData)
    return dataHash == entry.DataHash, nil
}

// CompleteStateEntry completes a state entry
func (sm *StateManagement) CompleteStateEntry(id string) error {
    entry, exists := sm.States[id]
    if !exists {
        return errors.New("state entry does not exist")
    }
    if entry.Status != "pending" {
        return errors.New("state entry is not pending")
    }
    entry.Status = "completed"
    sm.States[id] = entry
    return nil
}

// GetStateEntry retrieves a state entry by ID and decrypts it
func (sm *StateManagement) GetStateEntry(id, secret string) (StateEntry, error) {
    entry, exists := sm.States[id]
    if !exists {
        return StateEntry{}, errors.New("state entry does not exist")
    }
    decryptedData, err := decryptData(secret, entry.EncryptedData)
    if err != nil {
        return StateEntry{}, err
    }
    entry.EncryptedData = decryptedData
    return entry, nil
}

// ListStateEntries lists all state entries
func (sm *StateManagement) ListStateEntries() []StateEntry {
    entries := []StateEntry{}
    for _, entry := range sm.States {
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

// GenerateSignature generates a signature for the state entry using Argon2
func generateSignature(data, secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(data), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
