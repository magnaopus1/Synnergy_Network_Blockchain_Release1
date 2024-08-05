package assets

import (
	"encoding/json"
	"errors"
	"time"
)

// AccessLog represents a log entry for access requests and disclosures of identity data
type AccessLog struct {
	Timestamp    time.Time `json:"timestamp"`
	UserID       string    `json:"user_id"`
	ResourceID   string    `json:"resource_id"`
	AccessType   string    `json:"access_type"` // e.g., "read", "write", "update", "delete"
	AccessStatus string    `json:"access_status"` // e.g., "granted", "denied"
	Reason       string    `json:"reason,omitempty"` // Reason for access or denial
}

// AccessLogger provides functionalities to log and retrieve access logs
type AccessLogger struct {
	logs []AccessLog
}

// NewAccessLogger initializes a new AccessLogger
func NewAccessLogger() *AccessLogger {
	return &AccessLogger{
		logs: make([]AccessLog, 0),
	}
}

// LogAccess logs an access event
func (al *AccessLogger) LogAccess(userID, resourceID, accessType, accessStatus, reason string) {
	log := AccessLog{
		Timestamp:    time.Now(),
		UserID:       userID,
		ResourceID:   resourceID,
		AccessType:   accessType,
		AccessStatus: accessStatus,
		Reason:       reason,
	}
	al.logs = append(al.logs, log)
}

// GetLogs retrieves all access logs
func (al *AccessLogger) GetLogs() []AccessLog {
	return al.logs
}

// FindLogsByUserID retrieves access logs by user ID
func (al *AccessLogger) FindLogsByUserID(userID string) []AccessLog {
	var userLogs []AccessLog
	for _, log := range al.logs {
		if log.UserID == userID {
			userLogs = append(userLogs, log)
		}
	}
	return userLogs
}

// FindLogsByResourceID retrieves access logs by resource ID
func (al *AccessLogger) FindLogsByResourceID(resourceID string) []AccessLog {
	var resourceLogs []AccessLog
	for _, log := range al.logs {
		if log.ResourceID == resourceID {
			resourceLogs = append(resourceLogs, log)
		}
	}
	return resourceLogs
}

// SaveLogs serializes the logs to JSON
func (al *AccessLogger) SaveLogs() (string, error) {
	data, err := json.Marshal(al.logs)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadLogs deserializes the logs from JSON
func (al *AccessLogger) LoadLogs(data string) error {
	var logs []AccessLog
	err := json.Unmarshal([]byte(data), &logs)
	if err != nil {
		return err
	}
	al.logs = logs
	return nil
}

// ClearLogs clears all access logs
func (al *AccessLogger) ClearLogs() {
	al.logs = make([]AccessLog, 0)
}

// Add additional functionalities as needed
// ...

func main() {
	// Example usage
	logger := NewAccessLogger()
	logger.LogAccess("user1", "resource1", "read", "granted", "User authenticated successfully")
	logger.LogAccess("user2", "resource2", "write", "denied", "User not authorized")
	
	logs, err := logger.SaveLogs()
	if err != nil {
		fmt.Println("Error saving logs:", err)
		return
	}

	err = logger.LoadLogs(logs)
	if err != nil {
		fmt.Println("Error loading logs:", err)
		return
	}

	user1Logs := logger.FindLogsByUserID("user1")
	for _, log := range user1Logs {
		fmt.Printf("User1 Log: %+v\n", log)
	}

	resource1Logs := logger.FindLogsByResourceID("resource1")
	for _, log := range resource1Logs {
		fmt.Printf("Resource1 Log: %+v\n", log)
	}

	// Clear all logs
	logger.ClearLogs()
}
