package assets

import (
	"encoding/json"
	"errors"
	"time"
)

// ComplianceRecord represents a compliance log entry
type ComplianceRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Regulation  string    `json:"regulation"`
	Description string    `json:"description"`
	UserID      string    `json:"user_id"`
	Status      string    `json:"status"` // e.g., "compliant", "non-compliant"
	Reason      string    `json:"reason,omitempty"` // Reason for non-compliance if any
}

// ComplianceLogger provides functionalities to log and retrieve compliance records
type ComplianceLogger struct {
	records []ComplianceRecord
}

// NewComplianceLogger initializes a new ComplianceLogger
func NewComplianceLogger() *ComplianceLogger {
	return &ComplianceLogger{
		records: make([]ComplianceRecord, 0),
	}
}

// LogCompliance logs a compliance record
func (cl *ComplianceLogger) LogCompliance(regulation, description, userID, status, reason string) {
	record := ComplianceRecord{
		Timestamp:   time.Now(),
		Regulation:  regulation,
		Description: description,
		UserID:      userID,
		Status:      status,
		Reason:      reason,
	}
	cl.records = append(cl.records, record)
}

// GetRecords retrieves all compliance records
func (cl *ComplianceLogger) GetRecords() []ComplianceRecord {
	return cl.records
}

// FindRecordsByUserID retrieves compliance records by user ID
func (cl *ComplianceLogger) FindRecordsByUserID(userID string) []ComplianceRecord {
	var userRecords []ComplianceRecord
	for _, record := range cl.records {
		if record.UserID == userID {
			userRecords = append(userRecords, record)
		}
	}
	return userRecords
}

// FindRecordsByRegulation retrieves compliance records by regulation
func (cl *ComplianceLogger) FindRecordsByRegulation(regulation string) []ComplianceRecord {
	var regulationRecords []ComplianceRecord
	for _, record := range cl.records {
		if record.Regulation == regulation {
			regulationRecords = append(regulationRecords, record)
		}
	}
	return regulationRecords
}

// SaveRecords serializes the compliance records to JSON
func (cl *ComplianceLogger) SaveRecords() (string, error) {
	data, err := json.Marshal(cl.records)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadRecords deserializes the compliance records from JSON
func (cl *ComplianceLogger) LoadRecords(data string) error {
	var records []ComplianceRecord
	err := json.Unmarshal([]byte(data), &records)
	if err != nil {
		return err
	}
	cl.records = records
	return nil
}

// ClearRecords clears all compliance records
func (cl *ComplianceLogger) ClearRecords() {
	cl.records = make([]ComplianceRecord, 0)
}

// Example usage of ComplianceLogger
func main() {
	logger := NewComplianceLogger()
	logger.LogCompliance("GDPR", "User data access request", "user1", "compliant", "")
	logger.LogCompliance("KYC", "User identification process", "user2", "non-compliant", "Insufficient documentation")

	records, err := logger.SaveRecords()
	if err != nil {
		fmt.Println("Error saving records:", err)
		return
	}

	err = logger.LoadRecords(records)
	if err != nil {
		fmt.Println("Error loading records:", err)
		return
	}

	user1Records := logger.FindRecordsByUserID("user1")
	for _, record := range user1Records {
		fmt.Printf("User1 Record: %+v\n", record)
	}

	gdprRecords := logger.FindRecordsByRegulation("GDPR")
	for _, record := range gdprRecords {
		fmt.Printf("GDPR Record: %+v\n", record)
	}

	// Clear all records
	logger.ClearRecords()
}
