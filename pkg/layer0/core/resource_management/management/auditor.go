package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/core/resource_management/contracts"
)

// Auditor struct holds all necessary information to perform audits on resource allocations.
type Auditor struct {
	mutex     sync.Mutex
	log       []AuditEntry
	validator *contracts.Validator
}

// AuditEntry defines the structure for storing audit logs.
type AuditEntry struct {
	Timestamp     time.Time
	ResourceType  string
	Allocated     int
	Requested     int
	IsValid       bool
	TransactionID string
}

// NewAuditor initializes a new Auditor with a given validator.
func NewAuditor(validator *contracts.Validator) *Auditor {
	return &Auditor{
		validator: validator,
		log:       make([]AuditEntry, 0),
	}
}

// AuditResourceAllocation evaluates a resource allocation request against established rules.
func (a *Auditor) AuditResourceAllocation(transactionID, resourceType string, requested, allocated int) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	isValid, err := a.validator.ValidateTransaction(transactionID, resourceType, allocated)
	if err != nil {
		return err
	}

	entry := AuditEntry{
		Timestamp:     time.Now(),
		ResourceType:  resourceType,
		Allocated:     allocated,
		Requested:     requested,
		IsValid:       isValid,
		TransactionID: transactionID,
	}

	a.log = append(a.log, entry)
	return nil
}

// GenerateAuditReport generates a report of all audits conducted within a specified time range.
func (a *Auditor) GenerateAuditReport(startTime, endTime time.Time) ([]AuditEntry, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	var report []AuditEntry
	for _, entry := range a.log {
		if entry.Timestamp.After(startTime) && entry.Timestamp.Before(endTime) {
			report = append(report, entry)
		}
	}
	return report, nil
}

// SerializeAuditLog converts the audit log into a JSON format for storage or transmission.
func (a *Auditor) SerializeAuditLog() (string, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	data, err := json.Marshal(a.log)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeAuditLog restores the audit log from a JSON formatted string.
func (a *Auditor) DeserializeAuditLog(data string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	var entries []AuditEntry
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		return err
	}

	a.log = entries
	return nil
}

// ClearAuditLog clears the current audit log.
func (a *Auditor) ClearAuditLog() {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.log = []AuditEntry{}
}
