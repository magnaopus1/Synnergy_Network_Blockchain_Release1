package auditing

import (
	"encoding/json"
	"errors"
	"log"
	"time"
)

// AuditLog represents a single audit entry in the system
type AuditLog struct {
	Timestamp       time.Time
	NodeID          string
	Action          string
	ResourceType    string
	AmountAllocated float64
	Success         bool
	Details         string
}

// Auditor handles auditing processes within the Synnergy Network
type Auditor struct {
	AuditLogs   []AuditLog
	Thresholds  map[string]float64 // Thresholds for alerts
	Alerts      []string
	AlertChan   chan string
	DataStore   DataStore
}

// DataStore is an interface for storing and retrieving audit logs
type DataStore interface {
	StoreLog(log AuditLog) error
	FetchLogs() ([]AuditLog, error)
}

// NewAuditor initializes a new Auditor with given thresholds
func NewAuditor(dataStore DataStore, thresholds map[string]float64) *Auditor {
	return &Auditor{
		Thresholds: thresholds,
		AlertChan:  make(chan string),
		DataStore:  dataStore,
	}
}

// LogAction logs a resource allocation action for auditing
func (a *Auditor) LogAction(nodeID, action, resourceType string, amountAllocated float64, success bool, details string) {
	auditLog := AuditLog{
		Timestamp:       time.Now(),
		NodeID:          nodeID,
		Action:          action,
		ResourceType:    resourceType,
		AmountAllocated: amountAllocated,
		Success:         success,
		Details:         details,
	}

	a.AuditLogs = append(a.AuditLogs, auditLog)
	a.DataStore.StoreLog(auditLog)
	a.checkThresholds(auditLog)
}

// checkThresholds checks if any audit entry exceeds the defined thresholds and triggers an alert
func (a *Auditor) checkThresholds(log AuditLog) {
	if threshold, ok := a.Thresholds[log.ResourceType]; ok {
		if log.AmountAllocated > threshold {
			alert := "Threshold exceeded for " + log.ResourceType + " by Node " + log.NodeID
			a.AlertChan <- alert
			a.Alerts = append(a.Alerts, alert)
			log.Printf("ALERT: %s", alert)
		}
	}
}

// RetrieveLogs retrieves all audit logs for review
func (a *Auditor) RetrieveLogs() ([]AuditLog, error) {
	return a.DataStore.FetchLogs()
}

// ExportLogs exports the audit logs to a JSON file
func (a *Auditor) ExportLogs() ([]byte, error) {
	logs, err := a.RetrieveLogs()
	if err != nil {
		return nil, err
	}
	return json.Marshal(logs)
}

// ImportLogs imports audit logs from a JSON file
func (a *Auditor) ImportLogs(data []byte) error {
	var logs []AuditLog
	if err := json.Unmarshal(data, &logs); err != nil {
		return err
	}
	for _, log := range logs {
		a.DataStore.StoreLog(log)
		a.AuditLogs = append(a.AuditLogs, log)
	}
	return nil
}

// ReviewAuditTrail provides a summary of audit logs, highlighting key findings and areas for improvement
func (a *Auditor) ReviewAuditTrail() {
	logs, err := a.RetrieveLogs()
	if err != nil {
		log.Printf("Error retrieving logs: %v", err)
		return
	}

	for _, log := range logs {
		log.Printf("Audit Log: %+v", log)
		// Add more detailed analysis as needed
	}
}

// AutomatedAudit triggers automated auditing based on predefined schedules or conditions
func (a *Auditor) AutomatedAudit() {
	for {
		select {
		case alert := <-a.AlertChan:
			log.Printf("Received alert: %s", alert)
			// Handle alert (e.g., send notification, log for review, etc.)
		case <-time.After(24 * time.Hour): // Adjust frequency as needed
			a.ReviewAuditTrail()
		}
	}
}
