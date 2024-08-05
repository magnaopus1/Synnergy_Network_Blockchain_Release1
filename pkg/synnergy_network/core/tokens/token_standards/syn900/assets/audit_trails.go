package assets

import (
	"encoding/json"
	"errors"
	"time"
)

// AuditRecord represents an audit log entry
type AuditRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	UserID      string    `json:"user_id"`
	Success     bool      `json:"success"`
	Reason      string    `json:"reason,omitempty"` // Reason for action failure if any
}

// AuditLogger provides functionalities to log and retrieve audit trails
type AuditLogger struct {
	trails []AuditRecord
}

// NewAuditLogger initializes a new AuditLogger
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		trails: make([]AuditRecord, 0),
	}
}

// LogAction logs an audit trail action
func (al *AuditLogger) LogAction(action, description, userID string, success bool, reason string) {
	record := AuditRecord{
		Timestamp:   time.Now(),
		Action:      action,
		Description: description,
		UserID:      userID,
		Success:     success,
		Reason:      reason,
	}
	al.trails = append(al.trails, record)
}

// GetTrails retrieves all audit trails
func (al *AuditLogger) GetTrails() []AuditRecord {
	return al.trails
}

// FindTrailsByUserID retrieves audit trails by user ID
func (al *AuditLogger) FindTrailsByUserID(userID string) []AuditRecord {
	var userTrails []AuditRecord
	for _, trail := range al.trails {
		if trail.UserID == userID {
			userTrails = append(userTrails, trail)
		}
	}
	return userTrails
}

// FindTrailsByAction retrieves audit trails by action
func (al *AuditLogger) FindTrailsByAction(action string) []AuditRecord {
	var actionTrails []AuditRecord
	for _, trail := range al.trails {
		if trail.Action == action {
			actionTrails = append(actionTrails, trail)
		}
	}
	return actionTrails
}

// SaveTrails serializes the audit trails to JSON
func (al *AuditLogger) SaveTrails() (string, error) {
	data, err := json.Marshal(al.trails)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadTrails deserializes the audit trails from JSON
func (al *AuditLogger) LoadTrails(data string) error {
	var trails []AuditRecord
	err := json.Unmarshal([]byte(data), &trails)
	if err != nil {
		return err
	}
	al.trails = trails
	return nil
}

// ClearTrails clears all audit trails
func (al *AuditLogger) ClearTrails() {
	al.trails = make([]AuditRecord, 0)
}

// Example usage of AuditLogger
func main() {
	logger := NewAuditLogger()
	logger.LogAction("create_token", "User created a new token", "user1", true, "")
	logger.LogAction("update_token", "User updated token details", "user2", false, "Insufficient permissions")

	trails, err := logger.SaveTrails()
	if err != nil {
		fmt.Println("Error saving trails:", err)
		return
	}

	err = logger.LoadTrails(trails)
	if err != nil {
		fmt.Println("Error loading trails:", err)
		return
	}

	user1Trails := logger.FindTrailsByUserID("user1")
	for _, trail := range user1Trails {
		fmt.Printf("User1 Trail: %+v\n", trail)
	}

	createTokenTrails := logger.FindTrailsByAction("create_token")
	for _, trail := range createTokenTrails {
		fmt.Printf("Create Token Trail: %+v\n", trail)
	}

	// Clear all trails
	logger.ClearTrails()
}
