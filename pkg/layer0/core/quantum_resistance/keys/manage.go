package keys

import (
    "crypto/rand"
    "errors"
    "sync"

    "github.com/synthron/synthron_blockchain/crypto"
    "github.com/synthron/synthron_blockchain/network"
)

// KeyManager is responsible for managing the lifecycle of cryptographic keys within the blockchain ecosystem.
type KeyManager struct {
    keyStore   map[string][]byte
    lock       sync.Mutex
    networkAPI network.API
}

// NewKeyManager initializes a new KeyManager with necessary dependencies.
func NewKeyManager(api network.API) *KeyManager {
    return &KeyManager{
        keyStore:   make(map[string][]byte),
        networkAPI: api,
    }
}

// GenerateAndDistributeKeys generates quantum-resistant keys and distributes them to nodes.
func (km *KeyManager) GenerateAndDistributeKeys(nodeIDs []string) error {
    for _, id := range nodeIDs {
        key, err := crypto.GenerateQuantumResistantKey()
        if err != nil {
            return err
        }

        if err := km.storeKey(id, key); err != nil {
            return err
        }

        if err := km.networkAPI.SendKey(id, key); err != nil {
            return err
        }
    }
    return nil
}

// storeKey securely stores a key in the key manager's storage.
func (km *KeyManager) storeKey(nodeID string, key []byte) error {
    km.lock.Lock()
    defer km.lock.Unlock()

    if _, exists := km.keyStore[nodeID]; exists {
        return errors.New("key already exists for this node")
    }

    km.keyStore[nodeID] = key
    return nil
}

// RevokeKey revokes a key from a node and removes it from the key manager's storage.
func (km *KeyLangManager) RevokeKey(nodeID string) error {
    km.lock.Lock()
    defer km.lock.Unlock()

    if _, exists := km.keyStore[nodeID]; !exists {
        return errors.New("no key found for this node")
    }

    delete(km.keyStore, nodeID)
    return km.networkAPI.RevokeKey(nodeID)
}

// RenewKey generates a new key for a node, replaces the old key, and notifies the node.
func (km *KeyManager) RenewKey(nodeID string) error {
    key, err := crypto.GenerateQuantumResistantKey()
    if err != nil {
        return err
    }

    if err := km.storeKey(nodeID, key); err != nil {
        return err
    }

    return km.networkAPI.SendKey(nodeID, key)
}

