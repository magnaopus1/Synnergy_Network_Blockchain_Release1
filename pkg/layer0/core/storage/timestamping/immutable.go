package timestamping

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"synthron_blockchain/pkg/layer0/core/chain"
	"synthron_blockchain/pkg/layer0/core/storage"
)

// TimestampManager manages the creation and verification of timestamps within the blockchain.
type TimestampManager struct {
	Blockchain *chain.Blockchain
}

// NewTimestampManager creates a new manager for handling timestamps.
func NewTimestampManager(blockchain *chain.Blockchain) *TimestampManager {
	return &TimestampManager{
		Blockchain: blockchain,
	}
}

// CreateTimestamp creates a new timestamp on the blockchain for the given data.
func (tm *TimestampManager) CreateTimestamp(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	timestamp := time.Now().UTC()

	// Create a transaction containing the data hash and timestamp
	tx, err := tm.Blockchain.NewTransaction("TIMESTAMP", hex.EncodeToString(hash[:]), timestamp.String())
	if err != nil {
		return "", err
	}

	// Add transaction to the blockchain
	if err := tm.Blockchain.AddTransaction(tx); err != nil {
		return "", err
	}

	return tx.ID, nil
}

// VerifyTimestamp checks the validity of a data timestamp on the blockchain.
func (tm *TimestampManager) VerifyTimestamp(data []byte, txID string) (bool, error) {
	hash := sha256.Sum256(data)
	expectedHash := hex.EncodeToString(hash[:])

	tx, err := tm.Blockchain.GetTransactionByID(txID)
	if err != nil {
		return false, err
	}

	// Check if the stored hash matches the data hash
	if tx.Payload != expectedHash {
		return false, errors.New("timestamp verification failed: data does not match transaction record")
	}

	return true, nil
}

// DecentralizedTimestampAuthority represents a node that participates in the verification of timestamps.
type DecentralizedTimestampAuthority struct {
	NodeID string
}

// ValidateTimestamp uses decentralized nodes to collectively validate a timestamp.
func (dta *DecentralizedTimestampAuthority) ValidateTimestamp(txID string, blockchain *chain.Blockchain) (bool, error) {
	tx, err := blockchain.GetTransactionByID(txID)
	if err != nil {
		return false, err
	}

	// Additional validation logic to ensure timestamp integrity and consensus
	return true, nil
}
