package syn2600

import (
	"log"
	"time"
)

// Event types in the lifecycle of an investor token
const (
	EventTokenIssued    = "TokenIssued"
	EventTokenTransferred = "TokenTransferred"
	EventTokenRedeemed  = "TokenRedeemed"
	EventTokenUpdated   = "TokenUpdated"
)

// TokenEvent defines the structure of an event related to investor tokens.
type TokenEvent struct {
	Type      string    `json:"type"`      // Type of event
	TokenID   string    `json:"tokenId"`   // Identifier of the token
	Details   string    `json:"details"`   // Human-readable details about the event
	Timestamp time.Time `json:"timestamp"` // Timestamp of the event
}

// EventLogger handles logging of token events.
type EventLogger struct {
	events []TokenEvent
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent records an event in the token lifecycle.
func (el *EventLogger) LogEvent(eventType, tokenId, details string) {
	event := TokenEvent{
		Type:      eventType,
		TokenID:   tokenId,
		Details:   details,
		Timestamp: time.Now(),
	}
	el.events = append(el.events, event)

	// Log the event for monitoring or auditing purposes
	log.Printf("Event Logged: %s for TokenID: %s at %s with details: %s", event.Type, event.TokenID, event.Timestamp, event.Details)
}

// RetrieveEvents returns all logged events for auditing or display purposes.
func (el *EventLogger) RetrieveEvents() []TokenEvent {
	return el.events
}

// RetrieveEventsByToken filters and returns events for a specific token.
func (el *EventLogger) RetrieveEventsByToken(tokenId string) []TokenEvent {
	var filteredEvents []TokenEvent
	for _, event := range el.events {
		if event.TokenID == tokenId {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}
