package keys

import (
	"errors"
	"sync"

	"github.com/synthron/synthron_blockchain/crypto"
)

// QuantumKeyStore manages the storage and lifecycle of quantum keys.
type QuantumKeyStore struct {
	store map[string]*crypto.QuantumKey
	mu    sync.RWMutex
}

// NewQuantumKeyStore initializes a new instance of QuantumKeyStore.
func NewQuantumKeyStore() *QuantumKeyStore {
	return &QuantumKeyStore{
		store: make(map[string]*crypto.QuantumKey),
	}
}

// StoreKey safely stores a quantum key against a node identifier.
func (qks *QuantumKeyStore) StoreKey(nodeID string, key *crypto.QuantumKey) error {
	qks.mu.Lock()
	defer qks.mu.Unlock()

	if _, exists := qks.store[nodeID]; exists {
		return errors.New("key already exists for node")
	}

	qks.store[nodeID] = key
	return nil
}

// RetrieveKey retrieves a quantum key associated with a node identifier.
func (qks *QuantumKeyStore) RetrieveKey(nodeID string) (*crypto.QuantumKey, error) {
	qks.mu.RLock()
	defer qks.mu.RUnlock()

	key, exists := qks.store[nodeID]
	if !exists {
		return nil, errors.New("no key found for node")
	}

	return key, nil
}

// UpdateKey updates the quantum key associated with a node identifier.
func (qks *QuantumKeyStore) UpdateKey(nodeID string, newKey *crypto.QuantumKey) error {
	qks.mu.Lock()
	defer qks.mu.Unlock()

	if _, exists := qks.store[nodeID]; !exists {
		return errors.New("no key found for node")
	}

	qks.store[nodeID] = newKey
	return nil
}

// DeleteKey deletes a quantum key associated with a node identifier.
func (qks *QuantumKeyStore) DeleteKey(nodeID string) error {
	qks.mu.Lock()
	defer qks.mu.Unlock()

	if _, exists := qks.store[nodeID]; !exists {
		return errors.New("no key found for node")
	}

	delete(qks.store, nodeID)
	return nil
}
