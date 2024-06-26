package syn3700

import (
    "encoding/json"
    "log"
    "time"
)

// EventType specifies the types of events associated with index tokens.
type EventType string

const (
    EventTypeTokenCreated   EventType = "TokenCreated"
    EventTypeTokenUpdated   EventType = "TokenUpdated"
    EventTypeTokenQueried   EventType = "TokenQueried"
)

// Event represents a generic event structure for logging and notification purposes.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// TokenCreatedDetails contains information when an index token is created.
type TokenCreatedDetails struct {
    TokenID     string  `json:"tokenId"`
    IndexName   string  `json:"indexName"`
    Components  []Component `json:"components"`
    Holder      string  `json:"holder"`
}

// TokenUpdatedDetails contains information when an index token is updated.
type TokenUpdatedDetails struct {
    TokenID     string  `json:"tokenId"`
    Components  []Component `json:"components"`
}

// TokenQueriedDetails contains information when an index token's details are queried.
type TokenQueriedDetails struct {
    TokenID     string  `json:"tokenId"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher implements EventPublisher to log events to the standard logging service.
type LoggerEventPublisher struct{}

// Publish logs the event to a standard output or logging system.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", string(eventData))
    return nil
}

// EmitTokenCreated publishes an event when a new index token is created.
func EmitTokenCreated(publisher EventPublisher, tokenId, indexName string, components []Component, holder string) {
    details := TokenCreatedDetails{
        TokenID:    tokenId,
        IndexName:  indexName,
        Components: components,
        Holder:     holder,
    }
    event := Event{
        Type:      EventTypeTokenCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit token created event: %v", err)
    }
}

// EmitTokenUpdated publishes an event when an index token is updated.
func EmitTokenUpdated(publisher EventPublisher, tokenId string, components []Component) {
    details := TokenUpdatedDetails{
        TokenID:    tokenId,
        Components: components,
    }
    event := Event{
        Type:      EventTypeTokenUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit token updated event: %v", err)
    }
}

// EmitTokenQueried publishes an event when an index token is queried.
func EmitTokenQueried(publisher EventPublisher, tokenId string) {
    details := TokenQueriedDetails{
        TokenID: tokenId,
    }
    event := Event{
        Type:      EventTypeTokenQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit token queried event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
