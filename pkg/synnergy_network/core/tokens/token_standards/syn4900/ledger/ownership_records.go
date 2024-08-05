// Package ledger provides functionality for managing ownership records in the SYN4900 Token Standard.
package ledger

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/cryptography"
)

// OwnershipRecord represents a record of ownership for an agricultural token.
type OwnershipRecord struct {
	TokenID        string
	Owner          string
	PreviousOwners []string
	Timestamp      time.Time
	Signature      string
}

// OwnershipLedger represents the ledger that maintains ownership records.
type OwnershipLedger struct {
	records map[string]OwnershipRecord
	mutex   sync.Mutex
}

// NewOwnershipLedger initializes and returns a new OwnershipLedger.
func NewOwnershipLedger() *OwnershipLedger {
	return &OwnershipLedger{
		records: make(map[string]OwnershipRecord),
	}
}

// RecordOwnership records a new ownership or changes in ownership for a token.
func (ol *OwnershipLedger) RecordOwnership(tokenID, newOwner string) (OwnershipRecord, error) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	// Validate inputs
	if tokenID == "" || newOwner == "" {
		return OwnershipRecord{}, errors.New("invalid token ID or owner")
	}

	// Fetch the existing record, if any
	existingRecord, exists := ol.records[tokenID]
	if exists {
		existingRecord.PreviousOwners = append(existingRecord.PreviousOwners, existingRecord.Owner)
	}

	// Create a new ownership record
	newRecord := OwnershipRecord{
		TokenID:        tokenID,
		Owner:          newOwner,
		PreviousOwners: existingRecord.PreviousOwners,
		Timestamp:      time.Now(),
	}

	// Sign the record
	newRecord.Signature = cryptography.SignOwnershipRecord(newRecord)

	// Update the ledger
	ol.records[tokenID] = newRecord

	return newRecord, nil
}

// GetOwnershipRecord retrieves the ownership record for a specific token.
func (ol *OwnershipLedger) GetOwnershipRecord(tokenID string) (OwnershipRecord, error) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	record, exists := ol.records[tokenID]
	if !exists {
		return OwnershipRecord{}, errors.New("ownership record not found")
	}

	return record, nil
}

// VerifyOwnership verifies the ownership of a token by a specific owner.
func (ol *OwnershipLedger) VerifyOwnership(tokenID, owner string) (bool, error) {
	ol.mutex.Lock()
	defer ol.mutex.Unlock()

	record, exists := ol.records[tokenID]
	if !exists {
		return false, errors.New("ownership record not found")
	}

	// Verify ownership
	if record.Owner != owner {
		return false, errors.New("ownership verification failed")
	}

	// Verify the signature
	if !cryptography.VerifySignature(record) {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// cryptography package (placeholder) for demonstration purposes.
// Replace with actual cryptographic implementations as per system requirements.
package cryptography

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SignOwnershipRecord creates a digital signature for the ownership record.
func SignOwnershipRecord(record OwnershipRecord) string {
	data := fmt.Sprintf("%s%s%v%s", record.TokenID, record.Owner, record.PreviousOwners, record.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// VerifySignature verifies the digital signature of the ownership record.
func VerifySignature(record OwnershipRecord) bool {
	expectedSignature := SignOwnershipRecord(record)
	return expectedSignature == record.Signature
}
