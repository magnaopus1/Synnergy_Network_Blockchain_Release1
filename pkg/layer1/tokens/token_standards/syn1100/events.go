package syn1100

import (
	"fmt"
	"log"
	"time"
)

// Event defines the structure of an event related to healthcare data tokens.
type Event struct {
	Type      string    // Type of the event (e.g., "Created", "AccessGranted", "AccessRevoked", "Audited")
	TokenID   string    // ID of the token associated with the event
	Timestamp time.Time // Time when the event occurred
	Details   string    // Additional details about the event
}

// EventLogger manages the logging of token events.
type EventLogger struct {
	events []Event
}

// NewEventLogger creates a new EventLogger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent logs a new event to the system.
func (el *EventLogger) LogEvent(eventType, tokenID, details string) {
	event := Event{
		Type:      eventType,
		TokenID:   tokenID,
		Timestamp: time.Now(),
		Details:   details,
	}
	el.events = append(el.events, event)
	log.Printf("Event logged: %v", event)
}

// GetEvents returns all logged events for a specific token.
func (el *EventLogger) GetEvents(tokenID string) []Event {
	var filteredEvents []Event
	for _, event := range el.events {
		if event.TokenID == tokenID {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// Example of how to use the EventLogger in practice.
func ExampleEventUsage() {
	logger := NewEventLogger()
	tokenID := "token1234"

	// Logging various token-related events
	logger.LogEvent("Created", tokenID, "Token created with initial details")
	logger.LogEvent("AccessGranted", tokenID, "Access granted to user123")
	logger.LogEvent("AccessRevoked", tokenID, "Access revoked from user123")
	logger.LogEvent("Audited", tokenID, "Token audited with outcome: compliant")

	// Retrieving and printing the events for a token
	events := logger.GetEvents(tokenID)
	for _, event := range events {
		fmt.Printf("Event: %s at %s, Details: %s\n", event.Type, event.Timestamp, event.Details)
	}
}

