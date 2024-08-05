package assets

import (
    "encoding/json"
    "errors"
    "time"
)

// ComplianceRecord represents compliance documentation for regulatory requirements
type ComplianceRecord struct {
    EventID           string
    ComplianceDetails string
    Timestamp         time.Time
}

// ComplianceManager manages compliance records for SYN1700 tokens
type ComplianceManager struct {
    records map[string][]ComplianceRecord // EventID -> ComplianceRecords
}

// NewComplianceManager creates a new ComplianceManager
func NewComplianceManager() *ComplianceManager {
    return &ComplianceManager{
        records: make(map[string][]ComplianceRecord),
    }
}

// AddComplianceRecord adds a compliance record for a specific event
func (cm *ComplianceManager) AddComplianceRecord(eventID, details string) error {
    if eventID == "" || details == "" {
        return errors.New("event ID and compliance details are required")
    }

    record := ComplianceRecord{
        EventID:           eventID,
        ComplianceDetails: details,
        Timestamp:         time.Now(),
    }

    cm.records[eventID] = append(cm.records[eventID], record)
    return nil
}

// GetComplianceRecords retrieves all compliance records for a specific event
func (cm *ComplianceManager) GetComplianceRecords(eventID string) ([]ComplianceRecord, error) {
    records, exists := cm.records[eventID]
    if !exists {
        return nil, errors.New("no compliance records found for the specified event ID")
    }
    return records, nil
}

// GetAllComplianceRecords retrieves all compliance records
func (cm *ComplianceManager) GetAllComplianceRecords() map[string][]ComplianceRecord {
    return cm.records
}

// SerializeComplianceRecords serializes compliance records to JSON
func (cm *ComplianceManager) SerializeComplianceRecords(eventID string) (string, error) {
    records, err := cm.GetComplianceRecords(eventID)
    if err != nil {
        return "", err
    }

    data, err := json.Marshal(records)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeComplianceRecords deserializes compliance records from JSON
func (cm *ComplianceManager) DeserializeComplianceRecords(eventID, data string) error {
    var records []ComplianceRecord
    err := json.Unmarshal([]byte(data), &records)
    if err != nil {
        return err
    }

    cm.records[eventID] = records
    return nil
}
