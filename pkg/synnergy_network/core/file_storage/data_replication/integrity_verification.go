// Package data_replication focuses on ensuring data integrity across the Synnergy Network blockchain.
// This includes implementation of robust cryptographic hash verification mechanisms for data integrity.
package data_replication

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"synthron_blockchain/pkg/utils"
)

// IntegrityManager manages the integrity verification of replicated data across the blockchain nodes.
type IntegrityManager struct {
	DataHashes map[string]string // Stores the SHA-256 hashes of the data items
	mu         sync.Mutex
}

// NewIntegrityManager initializes a new instance of IntegrityManager.
func NewIntegrityManager() *IntegrityManager {
	return &IntegrityManager{
		DataHashes: make(map[string]string),
	}
}

// GenerateHash computes the SHA-256 hash for given data and stores it with associated data ID.
func (im *IntegrityManager) GenerateHash(dataID string, data []byte) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])
	im.DataHashes[dataID] = hexHash
	return nil
}

// VerifyDataHash checks the integrity of the given data against the stored hash for its ID.
func (im *IntegrityManager) VerifyDataHash(dataID string, data []byte) (bool, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	expectedHash, exists := im.DataHashes[dataID]
	if !exists {
		return false, errors.New("no hash stored for data ID")
	}

	currentHash := sha256.Sum256(data)
	if hex.EncodeToString(currentHash[:]) == expectedHash {
		return true, nil
	}
	return false, nil
}

// Example usage of IntegrityManager
func main() {
	manager := NewIntegrityManager()
	data := []byte("synthron blockchain data content")

	// Generate hash for the data
	err := manager.GenerateHash("data1", data)
	if err != nil {
		panic(err)
	}

	// Verify the integrity of the data
	valid, err := manager.VerifyDataHash("data1", data)
	if err != nil {
		panic(err)
	}

	if valid {
		println("Data integrity verified successfully.")
	} else {
		println("Data integrity verification failed.")
	}
}

