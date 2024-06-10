package syn700

import (
	"log"
	"time"
)

// Event types for SYN700 token standard
const (
	TokenCreated   = "TokenCreated"
	TokenTransferred = "TokenTransferred"
	TokenUpdated   = "TokenUpdated"
	TokenDeleted   = "TokenDeleted"
	RoyaltyAssigned = "RoyaltyAssigned"
)

// Event represents an event in the lifecycle of a SYN700 token.
type Event struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

// EventLogger manages the logging and dispatch of events related to SYN700 tokens.
type EventLogger struct {
	events []Event
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent logs a new event.
func (el *EventLogger) LogEvent(eventType, details string) {
	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   details,
	}
	el.events = append(el.events, event)
	log.Printf("Event logged: %s at %s with details: %s", eventType, event.Timestamp.String(), details)
}

// GetEvents returns a list of all logged events.
func (el *EventLogger) GetEvents() []Event {
	return el.events
}

// Example of how to log and retrieve events within the SYN700 token lifecycle.
func ExampleUsage(logger *EventLogger) {
	// Log creation of a new token
	logger.LogEvent(TokenCreated, "New token created with ID: token123")

	// Log transferring of a token
	logger.LogEvent(TokenTransferred, "Token token123 transferred from Alice to Bob")

	// Log updating of a token
	logger.LogEvent(TokenUpdated, "Token token123 updated with new royalty details")

	// Log deletion of a token
	logger.LogEvent(TokenDeleted, "Token token123 deleted from the registry")

	// Log assignment of royalty
	logger.LogEvent(RoyaltyAssigned, "Royalty of 5% assigned to user123 for token token123")

	// Retrieve and print all events
	events := logger.GetEvents()
	for _, event := range events {
		log.Printf("Event: %s, Time: %s, Details: %s", event.Type, event.Timestamp.String(), event.Details)
	}
}

// The EventLogger and Event struct provide a comprehensive mechanism to track and audit all relevant activities within the SYN700 token system, ensuring transparency and traceability.
