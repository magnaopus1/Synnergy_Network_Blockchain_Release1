package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// OwnershipRecord represents an ownership record for employment tokens
type OwnershipRecord struct {
	TokenID        string    `json:"token_id"`
	OwnerID        string    `json:"owner_id"`
	PreviousOwnerID string   `json:"previous_owner_id,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// OwnershipRecords manages the ownership records of employment tokens
type OwnershipRecords struct {
	records map[string][]OwnershipRecord
}

// NewOwnershipRecords initializes a new OwnershipRecords instance
func NewOwnershipRecords() *OwnershipRecords {
	return &OwnershipRecords{
		records: make(map[string][]OwnershipRecord),
	}
}

// AddOwnershipRecord adds a new ownership record to the ledger
func (or *OwnershipRecords) AddOwnershipRecord(tokenID, ownerID string) error {
	timestamp := time.Now()
	var previousOwnerID string
	if len(or.records[tokenID]) > 0 {
		previousOwnerID = or.records[tokenID][len(or.records[tokenID])-1].OwnerID
	}

	ownershipRecord := OwnershipRecord{
		TokenID:        tokenID,
		OwnerID:        ownerID,
		PreviousOwnerID: previousOwnerID,
		Timestamp:      timestamp,
	}

	or.records[tokenID] = append(or.records[tokenID], ownershipRecord)
	return nil
}

// GetCurrentOwner retrieves the current owner of a specific token
func (or *OwnershipRecords) GetCurrentOwner(tokenID string) (string, error) {
	if records, exists := or.records[tokenID]; exists && len(records) > 0 {
		return records[len(records)-1].OwnerID, nil
	}
	return "", errors.New("ownership record not found")
}

// GetOwnershipHistory retrieves the ownership history of a specific token
func (or *OwnershipRecords) GetOwnershipHistory(tokenID string) ([]OwnershipRecord, error) {
	if records, exists := or.records[tokenID]; exists {
		return records, nil
	}
	return nil, errors.New("ownership record not found")
}

// VerifyOwnership verifies the ownership of a token at a specific timestamp
func (or *OwnershipRecords) VerifyOwnership(tokenID, ownerID string, timestamp time.Time) (bool, error) {
	if records, exists := or.records[tokenID]; exists {
		for _, record := range records {
			if record.OwnerID == ownerID && record.Timestamp.Equal(timestamp) {
				return true, nil
			}
		}
	}
	return false, errors.New("ownership record not found or does not match")
}

// EncryptOwnershipData encrypts the ownership data for secure storage
func (or *OwnershipRecords) EncryptOwnershipData(tokenID, password string) (string, error) {
	if records, exists := or.records[tokenID]; exists {
		dataBytes, err := json.Marshal(records)
		if err != nil {
			return "", err
		}

		encryptedData, err := security.EncryptData(dataBytes, password)
		if err != nil {
			return "", err
		}

		return encryptedData, nil
	}
	return "", errors.New("ownership record not found")
}

// DecryptOwnershipData decrypts the ownership data
func (or *OwnershipRecords) DecryptOwnershipData(encryptedData, password string) ([]OwnershipRecord, error) {
	decryptedData, err := security.DecryptData(encryptedData, password)
	if err != nil {
		return nil, err
	}

	var records []OwnershipRecord
	err = json.Unmarshal([]byte(decryptedData), &records)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// OwnershipTransfer facilitates the transfer of token ownership
func (or *OwnershipRecords) OwnershipTransfer(tokenID, newOwnerID, password string) error {
	currentOwner, err := or.GetCurrentOwner(tokenID)
	if err != nil {
		return err
	}

	// Encrypt transfer details for security
	encryptedData, err := or.EncryptOwnershipData(tokenID, password)
	if err != nil {
		return err
	}

	// Decrypt to verify data integrity
	_, err = or.DecryptOwnershipData(encryptedData, password)
	if err != nil {
		return err
	}

	// Add new ownership record
	err = or.AddOwnershipRecord(tokenID, newOwnerID)
	if err != nil {
		return err
	}

	// Log transfer event (example logging, can be replaced with actual logging mechanism)
	fmt.Printf("Ownership of token %s transferred from %s to %s\n", tokenID, currentOwner, newOwnerID)
	return nil
}

