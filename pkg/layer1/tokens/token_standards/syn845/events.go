package syn845

import (
	"encoding/json"
	"log"
	"time"
)

// EventType defines the type of event related to a debt instrument.
type EventType string

const (
	PaymentMade   EventType = "PaymentMade"
	Defaulted     EventType = "Defaulted"
	LoanClosed    EventType = "LoanClosed"
)

// Event represents a debt instrument event.
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Details   string    `json:"details"`
	Timestamp string    `json:"timestamp"`
}

// EventManager manages events related to debt instruments.
type EventManager struct {
	Events []Event
}

// NewEventManager initializes an EventManager.
func NewEventManager() *EventManager {
	return &EventManager{}
}

// LogEvent logs an event related to a debt instrument.
func (em *EventManager) LogEvent(event Event) {
	em.Events = append(em.Events, event)
	log.Printf("Event logged: %v", event)
}

// HandlePaymentEvent handles events triggered by payments.
func (em *EventManager) HandlePaymentEvent(debtID string, amount float64, balance float64) {
	event := Event{
		ID:        debtID,
		Type:      PaymentMade,
		Details:   marshalToString(map[string]interface{}{"amount": amount, "balance": balance}),
		Timestamp: time.Now().Format(time.RFC3339),
	}
	em.LogEvent(event)
}

// HandleDefaultEvent handles events when a debt instrument defaults.
func (em *EventManager) HandleDefaultEvent(debtID string) {
	event := Event{
		ID:        debtID,
		Type:      Defaulted,
		Details:   "Loan has defaulted due to non-payment.",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	em.LogEvent(event)
}

// HandleLoanClosureEvent handles events when a loan is fully paid and closed.
func (em *EventManager) HandleLoanClosureEvent(debtID string) {
	event := Event{
		ID:        debtID,
		Type:      LoanClosed,
		Details:   "Loan is fully paid and closed.",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	em.LogEvent(event)
}

// GetAllEvents returns all logged events for auditing.
func (em *EventManager) GetAllEvents() []Event {
	return em.Events
}

// marshalToString simplifies the JSON encoding for storing in event details.
func marshalToString(v interface{}) string {
	bytes, err := json.Marshal(v)
	if err != nil {
		log.Printf("Error marshalling to JSON: %v", err)
		return ""
	}
	return string(bytes)
}
