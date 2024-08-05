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

// AtomicSwap represents an atomic swap transaction
type AtomicSwap struct {
    ID            string
    SourceChain   string
    DestinationChain string
    Amount        float64
    Sender        string
    Receiver      string
    HashLock      string
    Timestamp     time.Time
    Status        string
    EncryptedData string
}

// AtomicSwaps handles atomic swaps between blockchains
type AtomicSwaps struct {
    Swaps map[string]AtomicSwap
}

// NewAtomicSwaps initializes a new AtomicSwaps
func NewAtomicSwaps() *AtomicSwaps {
    return &AtomicSwaps{
        Swaps: make(map[string]AtomicSwap),
    }
}

// CreateAtomicSwap creates a new atomic swap with encryption
func (as *AtomicSwaps) CreateAtomicSwap(sourceChain, destinationChain, sender, receiver string, amount float64, secret string) (string, error) {
    id := uuid.New().String()
    hashLock := generateHashLock(secret)
    encryptedData, err := encryptData(secret, fmt.Sprintf("%s:%s:%f", sender, receiver, amount))
    if err != nil {
        return "", err
    }
    swap := AtomicSwap{
        ID:               id,
        SourceChain:      sourceChain,
        DestinationChain: destinationChain,
        Amount:           amount,
        Sender:           sender,
        Receiver:         receiver,
        HashLock:         hashLock,
        Timestamp:        time.Now(),
        Status:           "pending",
        EncryptedData:    encryptedData,
    }
    as.Swaps[id] = swap
    return id, nil
}

// CompleteAtomicSwap completes an atomic swap if the hashLock matches
func (as *AtomicSwaps) CompleteAtomicSwap(id, hashLock string) error {
    swap, exists := as.Swaps[id]
    if !exists {
        return errors.New("swap does not exist")
    }
    if swap.Status != "pending" {
        return errors.New("swap is not pending")
    }
    if swap.HashLock != hashLock {
        return errors.New("invalid hash lock")
    }
    swap.Status = "completed"
    as.Swaps[id] = swap
    return nil
}

// RevokeAtomicSwap revokes an atomic swap
func (as *AtomicSwaps) RevokeAtomicSwap(id, secret string) error {
    swap, exists := as.Swaps[id]
    if !exists {
        return errors.New("swap does not exist")
    }
    if swap.Status != "pending" {
        return errors.New("swap is not pending")
    }
    decryptedData, err := decryptData(secret, swap.EncryptedData)
    if err != nil {
        return err
    }
    swap.Status = "revoked"
    swap.EncryptedData = decryptedData
    as.Swaps[id] = swap
    return nil
}

// GetAtomicSwap retrieves an atomic swap by ID and decrypts it
func (as *AtomicSwaps) GetAtomicSwap(id, secret string) (AtomicSwap, error) {
    swap, exists := as.Swaps[id]
    if !exists {
        return AtomicSwap{}, errors.New("swap does not exist")
    }
    decryptedData, err := decryptData(secret, swap.EncryptedData)
    if err != nil {
        return AtomicSwap{}, err
    }
    swap.EncryptedData = decryptedData
    return swap, nil
}

// ListAtomicSwaps lists all atomic swaps
func (as *AtomicSwaps) ListAtomicSwaps() []AtomicSwap {
    swaps := []AtomicSwap{}
    for _, swap := range as.Swaps {
        swaps = append(swaps, swap)
    }
    return swaps
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

// GenerateHashLock generates a hash lock using Argon2
func generateHashLock(secret string) string {
    salt := make([]byte, 16)
    _, _ = rand.Read(salt)
    hash := argon2.IDKey([]byte(secret), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}
