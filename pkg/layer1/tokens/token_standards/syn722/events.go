package syn722

import (
	"encoding/json"
	"log"
	"time"
)

// TokenEvent defines the structure for events related to token actions.
type TokenEvent struct {
	Type      string            // Type of event (Create, Transfer, ModeChange)
	Timestamp time.Time         // Time at which the event occurred
	Details   map[string]string // Details about the event
}

// EventLogger manages the logging of token events.
type EventLogger struct {
	Events []TokenEvent
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{}
}

// LogEvent logs a new token-related event.
func (el *EventLogger) LogEvent(eventType string, details map[string]string) {
	event := TokenEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   details,
	}
	el.Events = append(el.Events, event)
	log.Printf("Logged new event: %s at %s with details %v", eventType, event.Timestamp, details)
}

// CreateTokenEvent logs the creation of a token.
func (el *EventLogger) CreateTokenEvent(tokenID, owner string) {
	details := map[string]string{
		"tokenID": tokenID,
		"owner":   owner,
	}
	el.LogEvent("Create", details)
}

// TransferTokenEvent logs the transfer of ownership of a token.
func (el *EventLogger) TransferTokenEvent(tokenID, fromOwner, toOwner string) {
	details := map[string]string{
		"tokenID":  tokenID,
		"from":     fromOwner,
		"to":       toOwner,
	}
	el.LogEvent("Transfer", details)
}

// ChangeModeEvent logs the change of mode of a token.
func (el *EventLogger) ChangeModeEvent(tokenID string, mode Mode) {
	details := map[string]string{
		"tokenID": tokenID,
		"newMode": mode.String(),
	}
	el.LogEvent("ModeChange", details)
}

// GetEvents returns a JSON representation of all logged events.
func (el *EventLogger) GetEvents() ([]byte, error) {
	data, err := json.Marshal(el.Events)
	if err != nil {
		log.Printf("Error marshalling events: %v", err)
		return nil, err
	}
	return data, nil
}

// ModeToString converts a Mode type to a string for logging purposes.
func (m Mode) String() string {
	switch m {
	case Fungible:
		return "Fungible"
	case NonFungible:
		return "NonFungible"
	default:
		return "Unknown"
	}
}
