package syn1900

import (
	"encoding/json"
	"time"
)

// Event types for educational credits
const (
	CreditIssued   = "CreditIssued"
	CreditRevoked  = "CreditRevoked"
	CreditTransferred = "CreditTransferred"
	CreditQueried = "CreditQueried"
)

// CreditEvent defines the structure of an event related to educational credits.
type CreditEvent struct {
	Type        string    `json:"type"`        // Type of the event
	Details     string    `json:"details"`     // Human-readable details about the event
	Timestamp   time.Time `json:"timestamp"`   // Timestamp of the event
}

// NewCreditEvent creates a new credit event.
func NewCreditEvent(eventType, details string) CreditEvent {
	return CreditEvent{
		Type:      eventType,
		Details:   details,
		Timestamp: time.Now(),
	}
}

// CreditIssuedEvent is triggered when a new credit is issued.
type CreditIssuedEvent struct {
	CreditEvent
	CreditID string `json:"creditId"`
	Owner    string `json:"owner"`
	Amount   float64 `json:"amount"`
}

// CreditRevokedEvent is triggered when a credit is revoked.
type CreditRevokedEvent struct {
	CreditEvent
	CreditID string `json:"creditId"`
}

// CreditTransferredEvent is triggered when a credit is transferred from one owner to another.
type CreditTransferredEvent struct {
	CreditEvent
	CreditID string `json:"creditId"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// CreditQueriedEvent is triggered when a credit's information is accessed.
type CreditQueriedEvent struct {
	CreditEvent
	CreditID string `json:"creditId"`
}

// EmitEvent logs an event to the event stream or audit log.
func EmitEvent(e CreditEvent) {
	// Here you might integrate with an external logging system or event stream.
	eventData, err := json.Marshal(e)
	if err != nil {
		// Handle error
		return
	}
	// Simulate logging the event data to a log file or sending it to a monitoring system.
	log.Printf("Event logged: %s", eventData)
}

// Usage of these structures and methods would be within the business logic handling each respective action on educational credits.
