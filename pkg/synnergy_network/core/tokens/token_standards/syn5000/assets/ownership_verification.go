// ownership_verification.go

package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// OwnershipRecord represents a record of ownership for a gambling token
type OwnershipRecord struct {
	TokenID     string    // Unique identifier for the token
	Owner       string    // Current owner's identifier (e.g., wallet address)
	OwnershipStart time.Time // Start time of the current ownership
	SecureHash  string    // Secure hash for verifying ownership integrity
}

// OwnershipVerifier manages the verification and records of gambling token ownership
type OwnershipVerifier struct {
	mu             sync.RWMutex
	ownershipRecords map[string]*OwnershipRecord // In-memory storage of ownership records
}

// NewOwnershipVerifier creates a new instance of OwnershipVerifier
func NewOwnershipVerifier() *OwnershipVerifier {
	return &OwnershipVerifier{
		ownershipRecords: make(map[string]*OwnershipRecord),
	}
}

// VerifyOwnership checks if the provided owner is the current owner of the specified token
func (ov *OwnershipVerifier) VerifyOwnership(tokenID, owner string) (bool, error) {
	ov.mu.RLock()
	defer ov.mu.RUnlock()

	record, exists := ov.ownershipRecords[tokenID]
	if !exists {
		return false, errors.New("ownership record not found")
	}

	// Verify that the provided owner matches the current owner and the hash is valid
	isOwner := record.Owner == owner
	expectedHash := generateOwnershipSecureHash(record.TokenID, record.Owner, record.OwnershipStart)
	hashValid := expectedHash == record.SecureHash

	return isOwner && hashValid, nil
}

// UpdateOwnership updates the ownership of a gambling token to a new owner
func (ov *OwnershipVerifier) UpdateOwnership(tokenID, newOwner string) error {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	record, exists := ov.ownershipRecords[tokenID]
	if !exists {
		return errors.New("ownership record not found")
	}

	// Update the ownership details and secure hash
	record.Owner = newOwner
	record.OwnershipStart = time.Now()
	record.SecureHash = generateOwnershipSecureHash(record.TokenID, record.Owner, record.OwnershipStart)

	// Store the updated record
	ov.ownershipRecords[tokenID] = record

	return nil
}

// RegisterOwnership creates a new ownership record for a token
func (ov *OwnershipVerifier) RegisterOwnership(tokenID, owner string) error {
	ov.mu.Lock()
	defer ov.mu.Unlock()

	if _, exists := ov.ownershipRecords[tokenID]; exists {
		return errors.New("ownership record already exists")
	}

	// Generate a secure hash for the new ownership record
	ownershipStart := time.Now()
	secureHash := generateOwnershipSecureHash(tokenID, owner, ownershipStart)

	// Create and store the new ownership record
	record := &OwnershipRecord{
		TokenID:    tokenID,
		Owner:      owner,
		OwnershipStart: ownershipStart,
		SecureHash: secureHash,
	}
	ov.ownershipRecords[tokenID] = record

	return nil
}

// generateOwnershipSecureHash generates a secure hash for an ownership record
func generateOwnershipSecureHash(tokenID, owner string, ownershipStart time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(tokenID))
	hash.Write([]byte(owner))
	hash.Write([]byte(ownershipStart.String()))
	return hex.EncodeToString(hash.Sum(nil))
}
