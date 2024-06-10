package syn1000

import (
	"log"
	"time"
)

// Event types for stablecoin operations.
const (
	EventMint   = "MINT"
	EventBurn   = "BURN"
	EventAudit  = "AUDIT"
)

// Event represents a recordable action taken on the stablecoin system.
type Event struct {
	Type      string    `json:"type"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
	TokenID   string    `json:"token_id"`
}

// EventLogger manages the logging of all stablecoin events.
type EventLogger struct {
	Events []Event
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent records an event to the log.
func (el *EventLogger) LogEvent(eventType, details, tokenID string) {
	event := Event{
		Type:      eventType,
		Details:   details,
		Timestamp: time.Now(),
		TokenID:   tokenID,
	}
	el.Events = append(el.Events, event)
	log.Printf("Event logged: %s - %s", eventType, details)
}

// GetEvents returns all logged events, optionally filtered by token ID.
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

// Example of how to use the event logger.
func ExampleEventUsage(logger *EventLogger) {
	logger.LogEvent(EventMint, "1000 stablecoins minted", "token123")
	logger.LogEvent(EventBurn, "500 stablecoins burned", "token123")
	logger.LogEvent(EventAudit, "Audit completed with outcome: Peg maintained", "token123")

	log.Println("All Events:")
	for _, event := range logger.GetEvents("token123") {
		log.Printf("Event: %s, Details: %s, Timestamp: %s", event.Type, event.Details, event.Timestamp)
	}
}

