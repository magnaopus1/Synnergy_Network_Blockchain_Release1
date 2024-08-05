package ledger

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
)

// OwnershipRecord represents the ownership details of a SYN11 token.
type OwnershipRecord struct {
	TokenID       string
	OwnerID       string
	OwnershipType string // Primary, Secondary, etc.
	IssuedAt      time.Time
	UpdatedAt     time.Time
	Status        string // Active, Revoked, etc.
}

// OwnershipLedger manages the ownership records for SYN11 tokens.
type OwnershipLedger struct {
	mu             sync.Mutex
	ownerships     map[string]OwnershipRecord
	complianceSvc  *compliance.ComplianceService
	securitySvc    *security.SecurityService
}

// NewOwnershipLedger creates a new OwnershipLedger.
func NewOwnershipLedger(complianceSvc *compliance.ComplianceService, securitySvc *security.SecurityService) *OwnershipLedger {
	return &OwnershipLedger{
		ownerships:    make(map[string]OwnershipRecord),
		complianceSvc: complianceSvc,
		securitySvc:   securitySvc,
	}
}

// RecordOwnership adds a new ownership record to the ledger.
func (ledger *OwnershipLedger) RecordOwnership(record OwnershipRecord) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	// Compliance and Security Checks
	if err := ledger.complianceSvc.ValidateOwnership(record); err != nil {
		return fmt.Errorf("compliance validation failed: %w", err)
	}

	if err := ledger.securitySvc.AuthorizeOwnershipChange(record); err != nil {
		return fmt.Errorf("ownership authorization failed: %w", err)
	}

	// Record the Ownership
	record.IssuedAt = time.Now()
	record.UpdatedAt = record.IssuedAt
	record.Status = "Active"
	ledger.ownerships[record.TokenID] = record

	log.Printf("Ownership recorded: %v", record)
	return nil
}

// GetOwnership retrieves an ownership record by TokenID.
func (ledger *OwnershipLedger) GetOwnership(tokenID string) (OwnershipRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	record, exists := ledger.ownerships[tokenID]
	if !exists {
		return OwnershipRecord{}, fmt.Errorf("ownership record for token ID %s not found", tokenID)
	}
	return record, nil
}

// ListOwnerships returns all ownership records.
func (ledger *OwnershipLedger) ListOwnerships() []OwnershipRecord {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	records := make([]OwnershipRecord, 0, len(ledger.ownerships))
	for _, record := range ledger.ownerships {
		records = append(records, record)
	}
	return records
}

// UpdateOwnership updates the ownership record for a token.
func (ledger *OwnershipLedger) UpdateOwnership(tokenID string, newOwnerID string) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	record, exists := ledger.ownerships[tokenID]
	if !exists {
		return fmt.Errorf("ownership record for token ID %s not found", tokenID)
	}

	// Compliance and Security Checks
	newRecord := record
	newRecord.OwnerID = newOwnerID
	newRecord.UpdatedAt = time.Now()

	if err := ledger.complianceSvc.ValidateOwnership(newRecord); err != nil {
		return fmt.Errorf("compliance validation failed: %w", err)
	}

	if err := ledger.securitySvc.AuthorizeOwnershipChange(newRecord); err != nil {
		return fmt.Errorf("ownership authorization failed: %w", err)
	}

	// Update the Ownership
	ledger.ownerships[tokenID] = newRecord

	log.Printf("Ownership updated for token ID %s: %v", tokenID, newRecord)
	return nil
}

// RevokeOwnership revokes an ownership record under certain conditions.
func (ledger *OwnershipLedger) RevokeOwnership(tokenID string, reason string) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	record, exists := ledger.ownerships[tokenID]
	if !exists {
		return fmt.Errorf("ownership record for token ID %s not found", tokenID)
	}

	// Compliance check for revocation
	if err := ledger.complianceSvc.ValidateRevocation(record); err != nil {
		return fmt.Errorf("revocation validation failed: %w", err)
	}

	record.Status = "Revoked"
	record.UpdatedAt = time.Now()
	ledger.ownerships[tokenID] = record

	log.Printf("Ownership revoked for token ID %s, Reason: %s", tokenID, reason)
	return nil
}
