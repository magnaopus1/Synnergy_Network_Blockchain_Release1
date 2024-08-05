package assets

import (
    "encoding/json"
    "errors"
    "time"
)

// OwnershipRecord represents the ownership record of a ticket
type OwnershipRecord struct {
    TicketID  string    `json:"ticket_id"`
    OwnerID   string    `json:"owner_id"`
    Timestamp time.Time `json:"timestamp"`
}

// OwnershipManager manages ownership records for SYN1700 tokens
type OwnershipManager struct {
    records map[string][]OwnershipRecord // TicketID -> OwnershipRecords
}

// NewOwnershipManager creates a new OwnershipManager
func NewOwnershipManager() *OwnershipManager {
    return &OwnershipManager{
        records: make(map[string][]OwnershipRecord),
    }
}

// AddOwnershipRecord adds a new ownership record for a ticket
func (om *OwnershipManager) AddOwnershipRecord(ticketID, ownerID string) error {
    if ticketID == "" || ownerID == "" {
        return errors.New("ticket ID and owner ID are required")
    }

    record := OwnershipRecord{
        TicketID:  ticketID,
        OwnerID:   ownerID,
        Timestamp: time.Now(),
    }

    om.records[ticketID] = append(om.records[ticketID], record)
    return nil
}

// GetOwnershipRecords retrieves ownership records for a specific ticket
func (om *OwnershipManager) GetOwnershipRecords(ticketID string) ([]OwnershipRecord, error) {
    records, exists := om.records[ticketID]
    if !exists {
        return nil, errors.New("no ownership records found for the specified ticket ID")
    }
    return records, nil
}

// GetCurrentOwner retrieves the current owner of a specific ticket
func (om *OwnershipManager) GetCurrentOwner(ticketID string) (string, error) {
    records, err := om.GetOwnershipRecords(ticketID)
    if err != nil {
        return "", err
    }
    if len(records) == 0 {
        return "", errors.New("no ownership records found")
    }
    return records[len(records)-1].OwnerID, nil
}

// SerializeOwnershipRecords serializes ownership records to JSON
func (om *OwnershipManager) SerializeOwnershipRecords(ticketID string) (string, error) {
    records, err := om.GetOwnershipRecords(ticketID)
    if err != nil {
        return "", err
    }

    data, err := json.Marshal(records)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeOwnershipRecords deserializes ownership records from JSON
func (om *OwnershipManager) DeserializeOwnershipRecords(ticketID, data string) error {
    var records []OwnershipRecord
    err := json.Unmarshal([]byte(data), &records)
    if err != nil {
        return err
    }

    om.records[ticketID] = records
    return nil
}

// VerifyOwnership verifies the ownership of a ticket
func (om *OwnershipManager) VerifyOwnership(ticketID, ownerID string) bool {
    currentOwner, err := om.GetCurrentOwner(ticketID)
    if err != nil {
        return false
    }
    return currentOwner == ownerID
}

// RevokeOwnership revokes the ownership of a ticket
func (om *OwnershipManager) RevokeOwnership(ticketID, reason string) error {
    currentOwner, err := om.GetCurrentOwner(ticketID)
    if err != nil {
        return err
    }

    om.records[ticketID] = append(om.records[ticketID], OwnershipRecord{
        TicketID:  ticketID,
        OwnerID:   "revoked",
        Timestamp: time.Now(),
    })

    return nil
}

// TransferOwnership transfers the ownership of a ticket to a new owner
func (om *OwnershipManager) TransferOwnership(ticketID, newOwnerID string) error {
    currentOwner, err := om.GetCurrentOwner(ticketID)
    if err != nil {
        return err
    }
    if currentOwner == newOwnerID {
        return errors.New("new owner is the same as the current owner")
    }

    return om.AddOwnershipRecord(ticketID, newOwnerID)
}
