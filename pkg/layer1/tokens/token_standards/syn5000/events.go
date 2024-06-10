package syn5000

import (
    "encoding/json"
    "log"
    "time"
)

// EventType categorizes the types of events that can occur within the gambling token lifecycle.
type EventType string

const (
    TokenIssued    EventType = "TokenIssued"
    TokenActivated EventType = "TokenActivated"
    TokenDeactivated EventType = "TokenDeactivated"
    TokenTransferred EventType = "TokenTransferred"
    TokenRetrieved EventType = "TokenRetrieved"
)

// Event represents an action or occurrence related to a gambling token.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// EventPublisher defines the interface for publishing events to external systems.
type EventPublisher interface {
    Publish(event Event) error
}

// LogEventPublisher uses the system log to publish events; it could be extended to support more complex event handling systems.
type LogEventPublisher struct{}

// Publish logs an event using the standard logging mechanism or another external system.
func (lep *LogEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshalling event data: %v", err)
        return err
    }
    log.Printf("Event Published: %s", eventData)
    return nil
}

// NewLogEventPublisher creates a new instance of LogEventPublisher.
func NewLogEventPublisher() *LogEventPublisher {
    return &LogEventPublisher{}
}

// EmitEvent creates and publishes an event using the given publisher.
func EmitEvent(publisher EventPublisher, eventType EventType, details interface{}) {
    event := Event{
        Type:      eventType,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to publish event: %v", err)
    }
}
