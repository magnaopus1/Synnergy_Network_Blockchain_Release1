package ledger

import (
	"errors"
	"sync"
	"time"
)

// OwnershipRecord represents the ownership details of a SYN12 token.
type OwnershipRecord struct {
	TokenID    string
	OwnerID    string
	AcquiredAt time.Time
}

// OwnershipLedger maintains a ledger of ownership records for SYN12 tokens.
type OwnershipLedger struct {
	records map[string]OwnershipRecord
	mutex   sync.RWMutex
}

// NewOwnershipLedger creates a new instance of OwnershipLedger.
func NewOwnershipLedger() *OwnershipLedger {
	return &OwnershipLedger{
		records: make(map[string]OwnershipRecord),
	}
}

// RecordOwnership adds or updates an ownership record in the ledger.
func (ol *OwnershipLedger) RecordOwnership(tokenID, ownerID string) error {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	// Check if the token already exists in the ledger
	if _, exists := ol.records[tokenID]; exists {
		return errors.New("token ID already exists in the ledger")
	}

	// Create a new ownership record
	record := OwnershipRecord{
		TokenID:    tokenID,
		OwnerID:    ownerID,
		AcquiredAt: time.Now(),
	}

	// Add the record to the ledger
	ol.records[tokenID] = record
	return nil
}

// TransferOwnership transfers ownership of a token to a new owner.
func (ol *OwnershipLedger) TransferOwnership(tokenID, newOwnerID string) error {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	// Find the existing ownership record
	record, exists := ol.records[tokenID]
	if !exists {
		return errors.New("token ID not found in the ledger")
	}

	// Update the owner ID and acquisition time
	record.OwnerID = newOwnerID
	record.AcquiredAt = time.Now()

	// Update the ledger
	ol.records[tokenID] = record
	return nil
}

// GetOwnershipRecord retrieves the ownership record for a specific token.
func (ol *OwnershipLedger) GetOwnershipRecord(tokenID string) (OwnershipRecord, error) {
	ol.mutex.RLock()
	defer ol.mutex.RUnlock()

	// Retrieve the record from the ledger
	record, exists := ol.records[tokenID]
	if !exists {
		return OwnershipRecord{}, errors.New("token ID not found in the ledger")
	}

	return record, nil
}

// VerifyOwnership checks if a given owner ID owns the specified token.
func (ol *OwnershipLedger) VerifyOwnership(tokenID, ownerID string) (bool, error) {
	ol.mutex.RLock()
	defer ol.mutex.RUnlock()

	// Retrieve the record and verify ownership
	record, exists := ol.records[tokenID]
	if !exists {
		return false, errors.New("token ID not found in the ledger")
	}

	return record.OwnerID == ownerID, nil
}

// RemoveOwnershipRecord removes an ownership record from the ledger, typically used when a token is redeemed or destroyed.
func (ol *OwnershipLedger) RemoveOwnershipRecord(tokenID string) error {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	// Remove the record from the ledger
	if _, exists := ol.records[tokenID]; !exists {
		return errors.New("token ID not found in the ledger")
	}

	delete(ol.records, tokenID)
	return nil
}

// GetOwnerTokens retrieves all tokens owned by a specific owner.
func (ol *OwnershipLedger) GetOwnerTokens(ownerID string) ([]OwnershipRecord, error) {
	ol.mutex.RLock()
	defer ol.mutex.RUnlock()

	var tokens []OwnershipRecord
	for _, record := range ol.records {
		if record.OwnerID == ownerID {
			tokens = append(tokens, record)
		}
	}

	if len(tokens) == 0 {
		return nil, errors.New("no tokens found for the given owner ID")
	}

	return tokens, nil
}
