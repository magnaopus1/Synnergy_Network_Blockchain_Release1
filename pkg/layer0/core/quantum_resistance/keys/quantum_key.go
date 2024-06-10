package keys

import (
    "crypto/rand"
    "sync"
    "errors"

    "github.com/synthron/synthron_blockchain/crypto/quantum"
    "github.com/synthron/synthron_blockchain/network"
)

// QuantumKeyManager handles the lifecycle and operations of quantum-resistant keys.
type QuantumKeyManager struct {
    keyStore map[string]*quantum.Key
    lock     sync.Mutex
    network  network.API
}

// NewQuantumKeyManager creates a new manager for quantum keys.
func NewQuantumKeyManager(networkAPI network.API) *QuantumKeyManager {
    return &QuantumKeyManager{
        keyStore: make(map[string]*quantum.Key),
        network:  networkAPI,
    }
}

// GenerateKeys initializes quantum keys for the provided node identifiers.
func (qkm *QuantumKeyManager) GenerateKeys(nodeIDs []string) error {
    qkm.lock.Lock()
    defer qkm.lock.Unlock()

    for _, id := range nodeIDs {
        key, err := quantum.GenerateKey()
        if err != nil {
            return err
        }
        qkm.keyStore[id] = key
        if err := qkm.network.SendKey(id, key); err != nil {
            return err
        }
    }
    return nil
}

// RevokeKey safely removes a quantum key from the manager and the network node.
func (qkm *QuantumKeyManager) RevokeKey(nodeID string) error {
    qkm.lock.Lock()
    defer qkm.lock.Unlock()

    if _, exists := qkm.keyStore[nodeID]; !exists {
        return errors.New("key does not exist for node")
    }
    delete(qkm.keyStore, nodeID)
    return qkm.network.RevokeKey(nodeID)
}

// RenewKey reissues a new quantum key to replace an old one.
func (qke *QuantumKeyManager) RenewKey(nodeID string) error {
    qke.lock.Lock()
    defer qke.lock.Unlock()

    key, err := quantum.GenerateKey()
    if err != nil {
        return err
    }
    qke.keyStore[nodeID] = key
    return qke.network.SendKey(nodeID, key)
}

// GetKey retrieves a key for a given node ID, ensuring secure key handling.
func (qkm *QuantumKeyManager) GetKey(nodeID string) (*quantum.Key, error) {
    qkm.lock.Lock()
    defer qkm.lock.Unlock()

    key, exists := qkm.keyStore[nodeID]
    if !exists {
        return nil, errors.New("no key found for node ID")
    }
    return key, nil
}

