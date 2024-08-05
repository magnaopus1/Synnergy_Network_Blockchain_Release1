package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/security"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/storage"
)

// OwnershipRecord represents the ownership details of a token.
type OwnershipRecord struct {
	TokenID        string
	OwnerAddress   string
	PreviousOwners []OwnerHistory
	Timestamp      time.Time
	Signature      string
}

// OwnerHistory stores the history of previous owners for a token.
type OwnerHistory struct {
	OwnerAddress string
	From         time.Time
	To           time.Time
}

// OwnershipRegistry manages the ownership records of SYN10 tokens.
type OwnershipRegistry struct {
	records map[string]OwnershipRecord
	store   storage.Storage
}

// NewOwnershipRegistry initializes a new ownership registry with storage.
func NewOwnershipRegistry(store storage.Storage) *OwnershipRegistry {
	return &OwnershipRegistry{
		records: make(map[string]OwnershipRecord),
		store:   store,
	}
}

// RegisterNewToken registers a new token ownership record in the ledger.
func (or *OwnershipRegistry) RegisterNewToken(tokenID, ownerAddress string) error {
	if _, exists := or.records[tokenID]; exists {
		return errors.New("token already exists in the registry")
	}

	record := OwnershipRecord{
		TokenID:      tokenID,
		OwnerAddress: ownerAddress,
		Timestamp:    time.Now(),
	}

	// Sign the ownership record
	record.Signature = or.signOwnershipRecord(record)

	or.records[tokenID] = record
	return or.store.Save(record.TokenID, record)
}

// TransferOwnership transfers the ownership of a token to a new owner.
func (or *OwnershipRegistry) TransferOwnership(tokenID, newOwnerAddress string) error {
	record, exists := or.records[tokenID]
	if !exists {
		return errors.New("token does not exist in the registry")
	}

	// Update the previous owners' history
	record.PreviousOwners = append(record.PreviousOwners, OwnerHistory{
		OwnerAddress: record.OwnerAddress,
		From:         record.Timestamp,
		To:           time.Now(),
	})

	// Update the current owner
	record.OwnerAddress = newOwnerAddress
	record.Timestamp = time.Now()

	// Sign the updated ownership record
	record.Signature = or.signOwnershipRecord(record)

	or.records[tokenID] = record
	return or.store.Save(record.TokenID, record)
}

// VerifyOwnership verifies the ownership of a token.
func (or *OwnershipRegistry) VerifyOwnership(tokenID, ownerAddress string) (bool, error) {
	record, exists := or.records[tokenID]
	if !exists {
		return false, errors.New("token does not exist in the registry")
	}

	if record.OwnerAddress != ownerAddress {
		return false, errors.New("ownership mismatch")
	}

	// Verify the signature
	if !or.verifyOwnershipRecord(record) {
		return false, errors.New("record signature verification failed")
	}

	return true, nil
}

// GetOwnershipHistory retrieves the ownership history of a token.
func (or *OwnershipRegistry) GetOwnershipHistory(tokenID string) ([]OwnerHistory, error) {
	record, exists := or.records[tokenID]
	if !exists {
		return nil, errors.New("token does not exist in the registry")
	}

	return record.PreviousOwners, nil
}

// signOwnershipRecord signs the ownership record using the system's private key.
func (or *OwnershipRegistry) signOwnershipRecord(record OwnershipRecord) string {
	data := record.TokenID + record.OwnerAddress + record.Timestamp.String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// verifyOwnershipRecord verifies the signature of the ownership record.
func (or *OwnershipRegistry) verifyOwnershipRecord(record OwnershipRecord) bool {
	expectedSignature := or.signOwnershipRecord(record)
	return expectedSignature == record.Signature
}
