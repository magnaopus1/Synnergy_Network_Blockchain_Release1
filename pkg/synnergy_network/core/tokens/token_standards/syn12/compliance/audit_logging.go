package compliance

import (
	"fmt"
	"log"
	"os"
	"time"
)

// AuditLevel defines the severity of the audit logs.
type AuditLevel string

const (
	// InfoLevel represents general information about system operations.
	InfoLevel AuditLevel = "INFO"

	// WarningLevel represents a warning that might require attention.
	WarningLevel AuditLevel = "WARNING"

	// ErrorLevel represents an error in the system.
	ErrorLevel AuditLevel = "ERROR"

	// CriticalLevel represents a critical error that might affect the system's stability.
	CriticalLevel AuditLevel = "CRITICAL"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp time.Time  // Time of the log entry
	Level     AuditLevel // Severity level of the log entry
	Message   string     // Log message
	UserID    string     // ID of the user involved (if applicable)
	Action    string     // Action that was performed
}

// AuditLogger handles logging of compliance-related events.
type AuditLogger struct {
	LogFile   *os.File
	LogWriter *log.Logger
}

// NewAuditLogger creates a new AuditLogger instance.
func NewAuditLogger(filePath string) (*AuditLogger, error) {
	logFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &AuditLogger{
		LogFile:   logFile,
		LogWriter: log.New(logFile, "", log.LstdFlags),
	}, nil
}

// Close closes the audit log file.
func (al *AuditLogger) Close() error {
	if err := al.LogFile.Close(); err != nil {
		return fmt.Errorf("failed to close audit log file: %w", err)
	}
	return nil
}

// LogEntry logs an audit entry with the specified details.
func (al *AuditLogger) LogEntry(level AuditLevel, message, userID, action string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		UserID:    userID,
		Action:    action,
	}
	al.LogWriter.Printf("[%s] %s: %s (User: %s, Action: %s)\n", entry.Timestamp.Format(time.RFC3339), entry.Level, entry.Message, entry.UserID, entry.Action)
}

// LogInfo logs an informational message.
func (al *AuditLogger) LogInfo(message, userID, action string) {
	al.LogEntry(InfoLevel, message, userID, action)
}

// LogWarning logs a warning message.
func (al *AuditLogger) LogWarning(message, userID, action string) {
	al.LogEntry(WarningLevel, message, userID, action)
}

// LogError logs an error message.
func (al *AuditLogger) LogError(message, userID, action string) {
	al.LogEntry(ErrorLevel, message, userID, action)
}

// LogCritical logs a critical error message.
func (al *AuditLogger) LogCritical(message, userID, action string) {
	al.LogEntry(CriticalLevel, message, userID, action)
}
