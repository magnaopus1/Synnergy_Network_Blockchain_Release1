package syn800

import (
	"log"
	"time"
)

// Event types in the SYN800 token standard
const (
	TokenCreated    = "TokenCreated"
	TokenTransferred = "TokenTransferred"
	TokenUpdated    = "TokenUpdated"
)

// Event represents a blockchain event for an SYN800 token.
type Event struct {
	Type      string
	Details   map[string]string
	Timestamp time.Time
}

// EventHandler manages events for SYN800 tokens.
type EventHandler struct {
	Events []Event
}

// NewEventHandler initializes an event handler.
func NewEventHandler() *EventHandler {
	return &EventHandler{}
}

// LogEvent records an event in the SYN800 token lifecycle.
func (h *EventHandler) LogEvent(eventType string, details map[string]string) {
	event := Event{
		Type:      eventType,
		Details:   details,
		Timestamp: time.Now(),
	}
	h.Events = append(h.Events, event)
	log.Printf("Event logged: %s at %s", eventType, event.Timestamp.String())
}

// TokenCreatedEvent triggers when a new token is created.
func (h *EventHandler) TokenCreatedEvent(tokenID, owner string) {
	details := map[string]string{
		"tokenID": tokenID,
		"owner":   owner,
	}
	h.LogEvent(TokenCreated, details)
	log.Printf("Token creation event: %s owned by %s", tokenID, owner)
}

// TokenTransferredEvent triggers when a token is transferred from one owner to another.
func (h *EventHandler) TokenTransferredEvent(tokenID, fromOwner, toOwner string) {
	details := map[string]string{
		"tokenID":   tokenID,
		"fromOwner": fromOwner,
		"toOwner":   toOwner,
	}
	h.LogEvent(TokenTransferred, details)
	log.Printf("Token transfer event: %s from %s to %s", tokenID, fromOwner, toOwner)
}

// TokenUpdatedEvent triggers when a token's asset value or other details are updated.
func (h *EventHandler) TokenUpdatedEvent(tokenID string, updates map[string]string) {
	h.LogEvent(TokenUpdated, updates)
	log.Printf("Token updated event for %s with changes: %v", tokenID, updates)
}

// GetAllEvents retrieves all logged events.
func (h *EventHandler) GetAllEvents() []Event {
	return h.Events
}

// Example usage
func ExampleUsage() {
	handler := NewEventHandler()
	handler.TokenCreatedEvent("1001", "Owner123")
	handler.TokenTransferredEvent("1001", "Owner123", "Owner456")
	handler.TokenUpdatedEvent("1001", map[string]string{"Value": "500000", "Location": "New York"})
	log.Println("All events:", handler.GetAllEvents())
}
