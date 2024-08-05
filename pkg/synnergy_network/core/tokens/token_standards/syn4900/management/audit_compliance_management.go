// Package management provides functionality for managing audit and compliance aspects in the SYN4900 Token Standard.
package management

import (
	"errors"
	"sync"
	"time"
)

// ComplianceRecord represents a record of compliance checks or audits for a given transaction or policy.
type ComplianceRecord struct {
	RecordID     string
	EntityID     string
	EntityType   string
	CheckType    string
	Status       string
	Details      string
	CheckedAt    time.Time
	ReviewedBy   string
	Comments     string
}

// AuditComplianceManager handles the creation, tracking, and management of compliance records and audit logs.
type AuditComplianceManager struct {
	records map[string]ComplianceRecord
	mutex   sync.Mutex
}

// NewAuditComplianceManager initializes and returns a new AuditComplianceManager.
func NewAuditComplianceManager() *AuditComplianceManager {
	return &AuditComplianceManager{
		records: make(map[string]ComplianceRecord),
	}
}

// AddComplianceRecord adds a new compliance record to the system.
func (acm *AuditComplianceManager) AddComplianceRecord(entityID, entityType, checkType, status, details, reviewedBy, comments string) (ComplianceRecord, error) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	// Validate inputs
	if entityID == "" || entityType == "" || checkType == "" || status == "" {
		return ComplianceRecord{}, errors.New("invalid compliance record details")
	}

	// Generate a unique record ID
	recordID := generateRecordID(entityID, entityType, time.Now())

	// Create the new compliance record
	record := ComplianceRecord{
		RecordID:   recordID,
		EntityID:   entityID,
		EntityType: entityType,
		CheckType:  checkType,
		Status:     status,
		Details:    details,
		CheckedAt:  time.Now(),
		ReviewedBy: reviewedBy,
		Comments:   comments,
	}

	// Store the record
	acm.records[recordID] = record

	return record, nil
}

// UpdateComplianceRecord updates an existing compliance record's status and details.
func (acm *AuditComplianceManager) UpdateComplianceRecord(recordID, status, details, reviewedBy, comments string) (ComplianceRecord, error) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	// Retrieve the existing compliance record
	record, exists := acm.records[recordID]
	if !exists {
		return ComplianceRecord{}, errors.New("compliance record not found")
	}

	// Update record details
	if status != "" {
		record.Status = status
	}
	if details != "" {
		record.Details = details
	}
	if reviewedBy != "" {
		record.ReviewedBy = reviewedBy
	}
	if comments != "" {
		record.Comments = comments
	}
	record.CheckedAt = time.Now()

	// Save the updated record
	acm.records[recordID] = record

	return record, nil
}

// GetComplianceRecord retrieves a compliance record by its ID.
func (acm *AuditComplianceManager) GetComplianceRecord(recordID string) (ComplianceRecord, error) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	record, exists := acm.records[recordID]
	if !exists {
		return ComplianceRecord{}, errors.New("compliance record not found")
	}

	return record, nil
}

// ListComplianceRecords returns all compliance records for a specific entity.
func (acm *AuditComplianceManager) ListComplianceRecords(entityID string) []ComplianceRecord {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	records := make([]ComplianceRecord, 0)
	for _, record := range acm.records {
		if record.EntityID == entityID {
			records = append(records, record)
		}
	}

	return records
}

// generateRecordID generates a unique ID for a compliance record based on entity ID, type, and creation time.
func generateRecordID(entityID, entityType string, createdAt time.Time) string {
	return entityID + "-" + entityType + "-" + createdAt.Format("20060102150405")
}
