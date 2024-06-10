package syn900

import (
	"log"
	"time"
)

// Event types for identity token operations.
const (
	EventCreate   = "CREATE"
	EventVerify   = "VERIFY"
	EventUpdate   = "UPDATE"
)

// Event represents an action taken on an identity token.
type Event struct {
	Type      string    // Type of the event (e.g., CREATE, VERIFY, UPDATE)
	Timestamp time.Time // Time at which the event occurred
	Details   string    // Description of the event
	TokenID   string    // Associated token ID
}

// EventLogger manages logging of events related to identity tokens.
type EventLogger struct {
	Events []Event
}

// NewEventLogger initializes a new EventLogger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent records an event to the logger.
func (el *EventLogger) LogEvent(eventType, details, tokenID string) {
	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   details,
		TokenID:   tokenID,
	}
	el.Events = append(el.Events, event)
	log.Printf("Event logged: %s for token %s at %s with details: %s", eventType, tokenID, event.Timestamp, details)
}

// GetEvents returns a list of all events, optionally filtered by token ID.
func (el *EventLogger) GetEvents(tokenID string) []Event {
	if tokenID == "" {
		return el.Events
	}
	var filteredEvents []Event
	for _, event := range el.Events {
		if event.TokenID == tokenID {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// Example of how to utilize the EventLogger in token operations.
func ExampleEventUsage(logger *EventLogger, tokenID string) {
	// Example usage of the EventLogger during token creation and verification
	logger.LogEvent(EventCreate, "Token created with initial details.", tokenID)
	logger.LogEvent(EventVerify, "Token verified as accurate.", tokenID)

	// Retrieve and print all events for a specific token
	events := logger.GetEvents(tokenID)
	for _, event := range events {
		log.Printf("Event: %s at %s - %s", event.Type, event.Timestamp, event.Details)
	}
}

// Setup for the above example would involve creating an EventLogger and a token ID.
func SetupAndExample() {
	logger := NewEventLogger()
	tokenID := "token123" // Assume this ID is generated or retrieved from token creation process.
	ExampleEventUsage(logger, tokenID)
}
