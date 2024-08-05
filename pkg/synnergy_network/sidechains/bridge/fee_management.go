package bridge

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "github.com/synnergy_network/bridge/transfer_logs"
)

// FeeConfig represents the configuration for the fee management system
type FeeConfig struct {
    BaseFee         float64
    FeeMultiplier   float64
    MaxFee          float64
    MinFee          float64
    EncryptionKey   string
}

// FeeManager manages the fee system
type FeeManager struct {
    config      *FeeConfig
    collectedFees map[string]float64
    mu          sync.RWMutex
}

// NewFeeManager creates a new FeeManager
func NewFeeManager(config *FeeConfig) *FeeManager {
    return &FeeManager{
        config:        config,
        collectedFees: make(map[string]float64),
    }
}

// CalculateFee calculates the fee based on the amount and other factors
func (fm *FeeManager) CalculateFee(amount float64) float64 {
    fee := amount * fm.config.FeeMultiplier
    if fee > fm.config.MaxFee {
        fee = fm.config.MaxFee
    } else if fee < fm.config.MinFee {
        fee = fm.config.MinFee
    }
    return fee
}

// CollectFee collects the fee for a specific transaction
func (fm *FeeManager) CollectFee(transactionID string, amount float64) (float64, error) {
    fee := fm.CalculateFee(amount)
    fm.mu.Lock()
    fm.collectedFees[transactionID] = fee
    fm.mu.Unlock()
    transfer_logs.LogFeeCollection(transactionID, fee)
    return fee, nil
}

// GetCollectedFees retrieves all collected fees
func (fm *FeeManager) GetCollectedFees() map[string]float64 {
    fm.mu.RLock()
    defer fm.mu.RUnlock()
    return fm.collectedFees
}

// EncryptFees encrypts the collected fees data for secure storage
func (fm *FeeManager) EncryptFees() (string, error) {
    fm.mu.RLock()
    defer fm.mu.RUnlock()

    key := sha256.Sum256([]byte(fm.config.EncryptionKey))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return "", err
    }

    feeData, err := json.Marshal(fm.collectedFees)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(feeData))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], feeData)

    return hex.EncodeToString(ciphertext), nil
}

// DecryptFees decrypts the collected fees data for use
func (fm *FeeManager) DecryptFees(encryptedFees string) (map[string]float64, error) {
    key := sha256.Sum256([]byte(fm.config.EncryptionKey))
    ciphertext, _ := hex.DecodeString(encryptedFees)
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    var fees map[string]float64
    if err := json.Unmarshal(ciphertext, &fees); err != nil {
        return nil, err
    }

    return fees, nil
}

// Example usage demonstrating comprehensive functionality
func ExampleComprehensiveFunctionality() {
    config := &FeeConfig{
        BaseFee:       0.1,
        FeeMultiplier: 0.01,
        MaxFee:        10.0,
        MinFee:        0.01,
        EncryptionKey: "superSecureKey",
    }
    fm := NewFeeManager(config)

    // Calculate and collect fee for a transaction
    transactionID := "tx12345"
    amount := 500.0
    fee, err := fm.CollectFee(transactionID, amount)
    if err != nil {
        fmt.Println("Error collecting fee:", err)
        return
    }

    fmt.Println("Collected Fee for Transaction:", transactionID, "is", fee)

    // Encrypt collected fees
    encryptedFees, err := fm.EncryptFees()
    if err != nil {
        fmt.Println("Error encrypting fees:", err)
        return
    }

    fmt.Println("Encrypted Fees:", encryptedFees)

    // Decrypt collected fees
    decryptedFees, err := fm.DecryptFees(encryptedFees)
    if err != nil {
        fmt.Println("Error decrypting fees:", err)
        return
    }

    fmt.Println("Decrypted Fees:", decryptedFees)
}
