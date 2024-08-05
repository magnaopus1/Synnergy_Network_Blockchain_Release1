package compliance

import (
	"errors"
	"fmt"
)

// KYCStatus represents the Know Your Customer verification status.
type KYCStatus string

const (
	// KYCNotStarted indicates that KYC has not been initiated.
	KYCNotStarted KYCStatus = "NOT_STARTED"

	// KYCInProgress indicates that KYC verification is in progress.
	KYCInProgress KYCStatus = "IN_PROGRESS"

	// KYCVerified indicates that the KYC verification has been completed successfully.
	KYCVerified KYCStatus = "VERIFIED"

	// KYCFailed indicates that the KYC verification failed.
	KYCFailed KYCStatus = "FAILED"
)

// AMLStatus represents the Anti-Money Laundering compliance status.
type AMLStatus string

const (
	// AMLCompliant indicates that AML compliance checks have been met.
	AMLCompliant AMLStatus = "COMPLIANT"

	// AMLPending indicates that AML compliance checks are pending.
	AMLPending AMLStatus = "PENDING"

	// AMLNonCompliant indicates that AML compliance checks failed.
AMLNonCompliant AMLStatus = "NON_COMPLIANT"
)

// ComplianceManager handles KYC and AML compliance checks.
type ComplianceManager struct {
	// KYCRecords stores KYC status by customer ID.
	KYCRecords map[string]KYCStatus

	// AMLRecords stores AML status by transaction ID or customer ID.
	AMLRecords map[string]AMLStatus
}

// NewComplianceManager creates a new ComplianceManager instance.
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		KYCRecords: make(map[string]KYCStatus),
		AMLRecords: make(map[string]AMLStatus),
	}
}

// StartKYCProcess initiates the KYC process for a given customer ID.
func (cm *ComplianceManager) StartKYCProcess(customerID string) error {
	if _, exists := cm.KYCRecords[customerID]; exists {
		return errors.New("KYC process already started for this customer")
	}
	cm.KYCRecords[customerID] = KYCInProgress
	return nil
}

// CompleteKYCProcess marks the KYC process as complete for a given customer ID.
func (cm *ComplianceManager) CompleteKYCProcess(customerID string) error {
	if status, exists := cm.KYCRecords[customerID]; !exists || status != KYCInProgress {
		return errors.New("KYC process not in progress for this customer")
	}
	cm.KYCRecords[customerID] = KYCVerified
	return nil
}

// FailKYCProcess marks the KYC process as failed for a given customer ID.
func (cm *ComplianceManager) FailKYCProcess(customerID string) error {
	if status, exists := cm.KYCRecords[customerID]; !exists || status != KYCInProgress {
		return errors.New("KYC process not in progress for this customer")
	}
	cm.KYCRecords[customerID] = KYCFailed
	return nil
}

// GetKYCStatus returns the KYC status for a given customer ID.
func (cm *ComplianceManager) GetKYCStatus(customerID string) (KYCStatus, error) {
	status, exists := cm.KYCRecords[customerID]
	if !exists {
		return KYCNotStarted, fmt.Errorf("no KYC record found for customer ID: %s", customerID)
	}
	return status, nil
}

// CheckAMLCompliance checks the AML compliance status for a given transaction or customer ID.
func (cm *ComplianceManager) CheckAMLCompliance(id string) (AMLStatus, error) {
	status, exists := cm.AMLRecords[id]
	if !exists {
		return AMLNonCompliant, fmt.Errorf("no AML record found for ID: %s", id)
	}
	return status, nil
}

// UpdateAMLCompliance updates the AML compliance status for a given transaction or customer ID.
func (cm *ComplianceManager) UpdateAMLCompliance(id string, status AMLStatus) error {
	cm.AMLRecords[id] = status
	return nil
}
