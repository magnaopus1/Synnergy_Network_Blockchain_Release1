// ownership_records.go

package ledger

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// OwnershipRecord represents the ownership information for a gambling token
type OwnershipRecord struct {
	TokenID      string                 // Unique identifier for the token
	Owner        string                 // Current owner's address
	PreviousOwner string                // Previous owner's address, if applicable
	TransferredAt time.Time             // Timestamp of the last ownership transfer
	Metadata     map[string]interface{} // Additional metadata related to the ownership
	Hash         string                 // Hash of the record for integrity verification
}

// OwnershipLedger manages the ownership records of gambling tokens
type OwnershipLedger struct {
	records map[string]OwnershipRecord // Maps token IDs to their ownership records
}

// NewOwnershipLedger creates a new instance of OwnershipLedger
func NewOwnershipLedger() *OwnershipLedger {
	return &OwnershipLedger{
		records: make(map[string]OwnershipRecord),
	}
}

// AddOwnershipRecord adds a new ownership record to the ledger
func (ol *OwnershipLedger) AddOwnershipRecord(tokenID, owner, previousOwner string, metadata map[string]interface{}) (*OwnershipRecord, error) {
	if tokenID == "" || owner == "" {
		return nil, errors.New("token ID and owner must not be empty")
	}

	record := OwnershipRecord{
		TokenID:      tokenID,
		Owner:        owner,
		PreviousOwner: previousOwner,
		TransferredAt: time.Now(),
		Metadata:     metadata,
	}

	record.Hash = generateOwnershipRecordHash(record)
	ol.records[tokenID] = record

	return &record, nil
}

// GetOwnershipRecord retrieves the ownership record for a specific token
func (ol *OwnershipLedger) GetOwnershipRecord(tokenID string) (*OwnershipRecord, error) {
	record, exists := ol.records[tokenID]
	if !exists {
		return nil, errors.New("ownership record not found")
	}
	return &record, nil
}

// VerifyOwnershipRecordHash verifies the integrity of an ownership record using its hash
func (ol *OwnershipLedger) VerifyOwnershipRecordHash(tokenID string) (bool, error) {
	record, err := ol.GetOwnershipRecord(tokenID)
	if err != nil {
		return false, err
	}

	expectedHash := generateOwnershipRecordHash(*record)
	return record.Hash == expectedHash, nil
}

// generateOwnershipRecordHash generates a hash for the ownership record to ensure data integrity
func generateOwnershipRecordHash(record OwnershipRecord) string {
	data := fmt.Sprintf("%s:%s:%s:%s", record.TokenID, record.Owner, record.PreviousOwner, record.TransferredAt)
	hash := sha256.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// UpdateOwnership updates the ownership of a token, recording the previous owner
func (ol *OwnershipLedger) UpdateOwnership(tokenID, newOwner string) (*OwnershipRecord, error) {
	record, exists := ol.records[tokenID]
	if !exists {
		return nil, errors.New("token not found in the ownership ledger")
	}

	if record.Owner == newOwner {
		return nil, errors.New("new owner is the same as the current owner")
	}

	record.PreviousOwner = record.Owner
	record.Owner = newOwner
	record.TransferredAt = time.Now()
	record.Hash = generateOwnershipRecordHash(record)

	ol.records[tokenID] = record
	return &record, nil
}
