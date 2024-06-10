package syn1155

import (
	"encoding/json"
	"log"
	"time"
)

// Event represents a generic interface for events within the token lifecycle.
type Event interface {
	Data() string
}

// TokenEvent struct will be used to log and track actions taken on tokens.
type TokenEvent struct {
	Type      string    `json:"type"`      // Type of the event (Transfer, Approval, Mint, etc.)
	TokenID   string    `json:"token_id"`  // ID of the token involved in the event
	From      string    `json:"from"`      // Source of the token for transfers
	To        string    `json:"to"`        // Destination of the token for transfers
	Amount    uint64    `json:"amount"`    // Amount transferred
	Timestamp time.Time `json:"timestamp"` // When the event occurred
}

// NewTokenEvent creates a new token event and logs the creation.
func NewTokenEvent(eventType, tokenID, from, to string, amount uint64) *TokenEvent {
	event := &TokenEvent{
		Type:      eventType,
		TokenID:   tokenID,
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
	}
	log.Printf("New Event: %s for token %s from %s to %s amount %d", eventType, tokenID, from, to, amount)
	return event
}

// Data returns the JSON encoding of the event.
func (e *TokenEvent) Data() string {
	data, err := json.Marshal(e)
	if err != nil {
		log.Printf("Error marshaling event data: %v", err)
		return "{}"
	}
	return string(data)
}

// EventLogger handles the accumulation and dispatch of events.
type EventLogger struct {
	events []Event
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent adds a new event to the logger.
func (el *EventLogger) LogEvent(event Event) {
	el.events = append(el.events, event)
	log.Println("Event logged:", event.Data())
}

// GetEvents returns all logged events.
func (el *EventLogger) GetEvents() []Event {
	return el.events
}

// ExampleUsage of how to log and retrieve events.
func ExampleUsage() {
	logger := NewEventLogger()
	logger.LogEvent(NewTokenEvent("Transfer", "token123", "user1", "user2", 100))
	logger.LogEvent(NewTokenEvent("Approval", "token123", "user1", "user3", 0))

	for _, event := range logger.GetEvents() {
		log.Println(event.Data())
	}
}
