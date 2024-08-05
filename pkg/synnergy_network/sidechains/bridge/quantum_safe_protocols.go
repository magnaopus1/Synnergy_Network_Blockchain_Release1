package bridge

import (
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "sync"

    "github.com/synnergy_network/bridge/transfer_logs"
    "github.com/synnergy_network/bridge/security_protocols"
)

// QuantumSafeKey represents a quantum-safe key structure
type QuantumSafeKey struct {
    KeyID  string
    PubKey []byte
    PrivKey []byte
}

// QuantumSafeManager manages quantum-safe encryption protocols
type QuantumSafeManager struct {
    keys map[string]QuantumSafeKey
    mu   sync.RWMutex
}

// NewQuantumSafeManager creates a new QuantumSafeManager
func NewQuantumSafeManager() *QuantumSafeManager {
    return &QuantumSafeManager{
        keys: make(map[string]QuantumSafeKey),
    }
}

// GenerateKey generates a new quantum-safe key pair
func (qsm *QuantumSafeManager) GenerateKey(keyID string) (QuantumSafeKey, error) {
    pubKey, privKey, err := qsm.generateKeyPair()
    if err != nil {
        return QuantumSafeKey{}, err
    }

    qsm.mu.Lock()
    qsm.keys[keyID] = QuantumSafeKey{
        KeyID:  keyID,
        PubKey: pubKey,
        PrivKey: privKey,
    }
    qsm.mu.Unlock()

    transfer_logs.LogQuantumKeyGeneration(keyID)

    return QuantumSafeKey{
        KeyID:  keyID,
        PubKey: pubKey,
        PrivKey: privKey,
    }, nil
}

// Encrypt encrypts the given data using the quantum-safe public key
func (qsm *QuantumSafeManager) Encrypt(keyID string, data []byte) (string, error) {
    qsm.mu.RLock()
    key, exists := qsm.keys[keyID]
    qsm.mu.RUnlock()

    if !exists {
        return "", errors.New("key not found")
    }

    encryptedData, err := security_protocols.QuantumSafeEncrypt(key.PubKey, data)
    if err != nil {
        return "", err
    }

    return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// Decrypt decrypts the given data using the quantum-safe private key
func (qsm *QuantumSafeManager) Decrypt(keyID string, encryptedData string) ([]byte, error) {
    qsm.mu.RLock()
    key, exists := qsm.keys[keyID]
    qsm.mu.RUnlock()

    if !exists {
        return nil, errors.New("key not found")
    }

    decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
