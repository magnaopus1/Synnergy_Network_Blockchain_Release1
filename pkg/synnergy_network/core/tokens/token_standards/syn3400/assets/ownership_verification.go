package assets

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type OwnershipVerification struct {
	OwnershipRecords map[string]OwnershipRecord
	mutex            sync.Mutex
}

type OwnershipRecord struct {
	TokenID     string    `json:"token_id"`
	Owner       string    `json:"owner"`
	Verified    bool      `json:"verified"`
	LastUpdated time.Time `json:"last_updated"`
}

// InitializeOwnershipVerification initializes the Ownership Verification structure
func InitializeOwnershipVerification() *OwnershipVerification {
	return &OwnershipVerification{
		OwnershipRecords: make(map[string]OwnershipRecord),
	}
}

// AddOwnershipRecord adds a new ownership record to the system
func (ov *OwnershipVerification) AddOwnershipRecord(tokenID, owner string, verified bool) error {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	if _, exists := ov.OwnershipRecords[tokenID]; exists {
		return errors.New("ownership record already exists")
	}

	ov.OwnershipRecords[tokenID] = OwnershipRecord{
		TokenID:     tokenID,
		Owner:       owner,
		Verified:    verified,
		LastUpdated: time.Now(),
	}

	return nil
}

// UpdateOwnership updates the owner and verification status of a token
func (ov *OwnershipVerification) UpdateOwnership(tokenID, newOwner string, verified bool) error {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	record, exists := ov.OwnershipRecords[tokenID]
	if !exists {
		return errors.New("ownership record not found")
	}

	record.Owner = newOwner
	record.Verified = verified
	record.LastUpdated = time.Now()
	ov.OwnershipRecords[tokenID] = record

	return nil
}

// GetOwnershipRecord retrieves the ownership record for a given tokenID
func (ov *OwnershipVerification) GetOwnershipRecord(tokenID string) (OwnershipRecord, error) {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	record, exists := ov.OwnershipRecords[tokenID]
	if !exists {
		return OwnershipRecord{}, errors.New("ownership record not found")
	}

	return record, nil
}

// VerifyTokenOwnership verifies the ownership of a given token
func (ov *OwnershipVerification) VerifyTokenOwnership(tokenID string) (bool, error) {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	record, exists := ov.OwnershipRecords[tokenID]
	if !exists {
		return false, errors.New("ownership record not found")
	}

	return record.Verified, nil
}

// SaveToFile saves the ownership records to a file
func (ov *OwnershipVerification) SaveToFile(filename string) error {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	data, err := json.Marshal(ov.OwnershipRecords)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, data, 0644)
}

// LoadFromFile loads the ownership records from a file
func (ov *OwnershipVerification) LoadFromFile(filename string) error {
	ov.mutex.Lock()
	defer ov.mutex.Unlock()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ov.OwnershipRecords)
}

// DisplayOwnership displays the ownership record of a token in a readable format
func (ov *OwnershipVerification) DisplayOwnership(tokenID string) error {
	record, err := ov.GetOwnershipRecord(tokenID)
	if err != nil {
		return err
	}

	fmt.Printf("Token ID: %s\nOwner: %s\nVerified: %t\nLast Updated: %s\n", record.TokenID, record.Owner, record.Verified, record.LastUpdated)
	return nil
}

