// audit_compliance_management.go

package management

import (
	"encoding/json"
	"errors"
	"log"
	"time"
)

// AuditRecord represents a record of audit logs in the system
type AuditRecord struct {
	Timestamp   time.Time            // Time when the action was logged
	Action      string               // Description of the action taken
	Actor       string               // Identifier of the entity that performed the action
	Details     map[string]interface{} // Additional details relevant to the action
	Compliance  bool                 // Indicates if the action complies with relevant regulations
}

// AuditLog manages the collection of audit records
type AuditLog struct {
	records []AuditRecord // List of audit records
}

// NewAuditLog creates a new instance of AuditLog
func NewAuditLog() *AuditLog {
	return &AuditLog{
		records: make([]AuditRecord, 0),
	}
}

// AddAuditRecord adds a new audit record to the log
func (al *AuditLog) AddAuditRecord(action, actor string, details map[string]interface{}, compliance bool) {
	record := AuditRecord{
		Timestamp:  time.Now(),
		Action:     action,
		Actor:      actor,
		Details:    details,
		Compliance: compliance,
	}

	al.records = append(al.records, record)
}

// GetAuditRecords retrieves all audit records
func (al *AuditLog) GetAuditRecords() []AuditRecord {
	return al.records
}

// GetComplianceReports generates a compliance report for audit records
func (al *AuditLog) GetComplianceReports() (string, error) {
	nonCompliantRecords := []AuditRecord{}
	for _, record := range al.records {
		if !record.Compliance {
			nonCompliantRecords = append(nonCompliantRecords, record)
		}
	}

	report, err := json.MarshalIndent(nonCompliantRecords, "", "  ")
	if err != nil {
		return "", errors.New("failed to generate compliance report")
	}

	return string(report), nil
}

// CheckCompliance checks if a specific action complies with the relevant regulations
func CheckCompliance(action string, details map[string]interface{}) bool {
	// Implement detailed compliance checks based on regulations
	// Placeholder logic for demonstration purposes
	switch action {
	case "TRANSFER", "BET", "PAYOUT":
		return true // Assume compliant for standard transactions
	default:
		return false // Non-compliant for unrecognized actions
	}
}

// LogAction logs an action and its compliance status to the audit log
func (al *AuditLog) LogAction(action, actor string, details map[string]interface{}) {
	compliance := CheckCompliance(action, details)
	al.AddAuditRecord(action, actor, details, compliance)

	if !compliance {
		log.Printf("Non-compliant action detected: %s by %s", action, actor)
	}
}
