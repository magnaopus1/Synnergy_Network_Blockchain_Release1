package assets

import (
	"encoding/json"
	"errors"
	"time"
)

// VerificationRecord represents a log entry for verification events
type VerificationRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	Status       string    `json:"status"`       // e.g., "verified", "failed"
	Method       string    `json:"method"`       // e.g., "document", "biometric"
	Verifier     string    `json:"verifier"`     // e.g., "self", "third-party service"
	Details      string    `json:"details"`      // Additional details about the verification
	TransactionID string   `json:"transaction_id"` // Associated transaction ID
}

// VerificationLogger provides functionalities to log and retrieve verification records
type VerificationLogger struct {
	records []VerificationRecord
}

// NewVerificationLogger initializes a new VerificationLogger
func NewVerificationLogger() *VerificationLogger {
	return &VerificationLogger{
		records: make([]VerificationRecord, 0),
	}
}

// LogVerification logs a verification event
func (vl *VerificationLogger) LogVerification(status, method, verifier, details, transactionID string) {
	record := VerificationRecord{
		Timestamp:    time.Now(),
		Status:       status,
		Method:       method,
		Verifier:     verifier,
		Details:      details,
		TransactionID: transactionID,
	}
	vl.records = append(vl.records, record)
}

// GetRecords retrieves all verification records
func (vl *VerificationLogger) GetRecords() []VerificationRecord {
	return vl.records
}

// FindRecordsByStatus retrieves verification records by status
func (vl *VerificationLogger) FindRecordsByStatus(status string) []VerificationRecord {
	var statusRecords []VerificationRecord
	for _, record := range vl.records {
		if record.Status == status {
			statusRecords = append(statusRecords, record)
		}
	}
	return statusRecords
}

// FindRecordsByMethod retrieves verification records by method
func (vl *VerificationLogger) FindRecordsByMethod(method string) []VerificationRecord {
	var methodRecords []VerificationRecord
	for _, record := range vl.records {
		if record.Method == method {
			methodRecords = append(methodRecords, record)
		}
	}
	return methodRecords
}

// FindRecordsByVerifier retrieves verification records by verifier
func (vl *VerificationLogger) FindRecordsByVerifier(verifier string) []VerificationRecord {
	var verifierRecords []VerificationRecord
	for _, record := range vl.records {
		if record.Verifier == verifier {
			verifierRecords = append(verifierRecords, record)
		}
	}
	return verifierRecords
}

// FindRecordsByTransactionID retrieves verification records by transaction ID
func (vl *VerificationLogger) FindRecordsByTransactionID(transactionID string) []VerificationRecord {
	var transactionRecords []VerificationRecord
	for _, record := range vl.records {
		if record.TransactionID == transactionID {
			transactionRecords = append(transactionRecords, record)
		}
	}
	return transactionRecords
}

// SaveRecords serializes the verification records to JSON
func (vl *VerificationLogger) SaveRecords() (string, error) {
	data, err := json.Marshal(vl.records)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadRecords deserializes the verification records from JSON
func (vl *VerificationLogger) LoadRecords(data string) error {
	var records []VerificationRecord
	err := json.Unmarshal([]byte(data), &records)
	if err != nil {
		return err
	}
	vl.records = records
	return nil
}

// ClearRecords clears all verification records
func (vl *VerificationLogger) ClearRecords() {
	vl.records = make([]VerificationRecord, 0)
}

// Example usage of VerificationLogger
func main() {
	logger := NewVerificationLogger()
	logger.LogVerification("verified", "document", "third-party service", "Document verified successfully", "tx123")
	logger.LogVerification("failed", "biometric", "self", "Biometric verification failed", "tx124")

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

	verifiedRecords := logger.FindRecordsByStatus("verified")
	for _, record := range verifiedRecords {
		fmt.Printf("Verified Record: %+v\n", record)
	}

	documentRecords := logger.FindRecordsByMethod("document")
	for _, record := range documentRecords {
		fmt.Printf("Document Method Record: %+v\n", record)
	}

	thirdPartyRecords := logger.FindRecordsByVerifier("third-party service")
	for _, record := range thirdPartyRecords {
		fmt.Printf("Third Party Verifier Record: %+v\n", record)
	}

	transactionRecords := logger.FindRecordsByTransactionID("tx123")
	for _, record := range transactionRecords {
		fmt.Printf("Transaction ID Record: %+v\n", record)
	}

	// Clear all records
	logger.ClearRecords()
}
