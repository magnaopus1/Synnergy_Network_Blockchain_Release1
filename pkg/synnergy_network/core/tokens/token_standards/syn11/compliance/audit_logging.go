package compliance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// AuditLog represents an audit log entry.
type AuditLog struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`
	Actor       string    `json:"actor"`
	Description string    `json:"description"`
	Hash        string    `json:"hash"`
}

// AuditLogger manages audit logging for compliance.
type AuditLogger struct {
	logFile *os.File
}

// NewAuditLogger initializes a new audit logger.
func NewAuditLogger(logFilePath string) (*AuditLogger, error) {
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}
	return &AuditLogger{logFile: file}, nil
}

// LogEvent logs an audit event.
func (al *AuditLogger) LogEvent(event, actor, description string) error {
	timestamp := time.Now()
	logEntry := &AuditLog{
		Timestamp:   timestamp,
		Event:       event,
		Actor:       actor,
		Description: description,
		Hash:        generateHash(timestamp.String() + event + actor + description),
	}
	entryBytes, err := json.Marshal(logEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %v", err)
	}

	_, err = al.logFile.Write(append(entryBytes, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write log entry to file: %v", err)
	}

	// Optional: Send to external monitoring system or ledger for redundancy
	// sendToMonitoringSystem(logEntry)

	return nil
}

// Close closes the audit log file.
func (al *AuditLogger) Close() error {
	return al.logFile.Close()
}

// generateHash creates a SHA-256 hash of the input data.
func generateHash(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// sendToMonitoringSystem sends the log entry to an external monitoring system.
// This function can be implemented to integrate with systems like SIEM (Security Information and Event Management).
func sendToMonitoringSystem(logEntry *AuditLog) {
	// Implement integration with external systems if required
	// Example: Sending log entry data to a remote server or third-party service
	// logEntryJSON, _ := json.Marshal(logEntry)
	// sendToExternalService(logEntryJSON)
}

// LogSystemEvent logs a system-level event (e.g., startup, shutdown).
func (al *AuditLogger) LogSystemEvent(event, description string) error {
	return al.LogEvent(event, "SYSTEM", description)
}

// LogComplianceEvent logs a compliance-related event.
func (al *AuditLogger) LogComplianceEvent(actor, description string) error {
	return al.LogEvent("COMPLIANCE", actor, description)
}

// LogTransaction logs a transaction-related event.
func (al *AuditLogger) LogTransaction(actor, description string) error {
	return al.LogEvent("TRANSACTION", actor, description)
}

// LogSecurityIncident logs a security-related incident.
func (al *AuditLogger) LogSecurityIncident(actor, description string) error {
	return al.LogEvent("SECURITY_INCIDENT", actor, description)
}
