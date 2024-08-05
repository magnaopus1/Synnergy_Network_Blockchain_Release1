package security

import (
	"fmt"
	"sync"
	"time"
)

// ComplianceStatus represents the compliance status of a token
type ComplianceStatus string

const (
	ComplianceStatusPending   ComplianceStatus = "Pending"
	ComplianceStatusApproved  ComplianceStatus = "Approved"
	ComplianceStatusRejected  ComplianceStatus = "Rejected"
	ComplianceStatusSuspended ComplianceStatus = "Suspended"
)

// ComplianceCheck represents a compliance check for a token
type ComplianceCheck struct {
	TokenID       string
	Status        ComplianceStatus
	CheckedBy     string
	CheckedAt     time.Time
	Comments      string
	ComplianceLogs []ComplianceLog
}

// ComplianceLog represents a log entry for compliance checks
type ComplianceLog struct {
	Timestamp time.Time
	Status    ComplianceStatus
	CheckedBy string
	Comments  string
}

// ComplianceManager manages regulatory compliance for SYN721 tokens
type ComplianceManager struct {
	complianceChecks map[string]*ComplianceCheck
	mutex            sync.Mutex
}

// NewComplianceManager initializes a new ComplianceManager
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		complianceChecks: make(map[string]*ComplianceCheck),
	}
}

// AddComplianceCheck adds a new compliance check for a token
func (cm *ComplianceManager) AddComplianceCheck(tokenID, checkedBy, comments string, status ComplianceStatus) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	check := &ComplianceCheck{
		TokenID:   tokenID,
		Status:    status,
		CheckedBy: checkedBy,
		CheckedAt: time.Now(),
		Comments:  comments,
		ComplianceLogs: []ComplianceLog{
			{
				Timestamp: time.Now(),
				Status:    status,
				CheckedBy: checkedBy,
				Comments:  comments,
			},
		},
	}

	cm.complianceChecks[tokenID] = check
	return nil
}

// UpdateComplianceStatus updates the compliance status of a token
func (cm *ComplianceManager) UpdateComplianceStatus(tokenID, checkedBy, comments string, status ComplianceStatus) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	check, exists := cm.complianceChecks[tokenID]
	if !exists {
		return fmt.Errorf("compliance check for token ID %s not found", tokenID)
	}

	log := ComplianceLog{
		Timestamp: time.Now(),
		Status:    status,
		CheckedBy: checkedBy,
		Comments:  comments,
	}

	check.Status = status
	check.CheckedBy = checkedBy
	check.CheckedAt = time.Now()
	check.Comments = comments
	check.ComplianceLogs = append(check.ComplianceLogs, log)

	return nil
}

// GetComplianceStatus retrieves the compliance status of a token
func (cm *ComplianceManager) GetComplianceStatus(tokenID string) (ComplianceCheck, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	check, exists := cm.complianceChecks[tokenID]
	if !exists {
		return ComplianceCheck{}, fmt.Errorf("compliance check for token ID %s not found", tokenID)
	}

	return *check, nil
}

// ListComplianceChecks lists all compliance checks for auditing purposes
func (cm *ComplianceManager) ListComplianceChecks() []ComplianceCheck {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	var checks []ComplianceCheck
	for _, check := range cm.complianceChecks {
		checks = append(checks, *check)
	}

	return checks
}

// IsTokenCompliant checks if a token is compliant
func (cm *ComplianceManager) IsTokenCompliant(tokenID string) (bool, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	check, exists := cm.complianceChecks[tokenID]
	if !exists {
		return false, fmt.Errorf("compliance check for token ID %s not found", tokenID)
	}

	return check.Status == ComplianceStatusApproved, nil
}
