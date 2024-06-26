package syn4900

import (
    "encoding/json"
    "log"
    "time"
)

// EventType defines the type of events related to agricultural tokens.
type EventType string

const (
    TokenCreated EventType = "TokenCreated"
    TokenUpdated EventType = "TokenUpdated"
    TokenTransferred EventType = "TokenTransferred"
    TokenQueried EventType = "TokenQueried"
)

// Event represents an event in the lifecycle of an agricultural token.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// TokenCreatedDetails holds details for the TokenCreated event.
type TokenCreatedDetails struct {
    TokenID       string `json:"tokenId"`
    AssetType     string `json:"assetType"`
    Owner         string `json:"owner"`
}

// TokenUpdatedDetails holds details for the TokenUpdated event.
type TokenUpdatedDetails struct {
    TokenID       string `json:"tokenId"`
    NewStatus     string `json:"newStatus"`
}

// TokenTransferredDetails holds details for the TokenTransferred event.
type TokenTransferredDetails struct {
    TokenID       string `json:"tokenId"`
    FromOwner     string `json:"fromOwner"`
    ToOwner       string `json:"toOwner"`
}

// TokenQueriedDetails holds details for the TokenQueried event.
type TokenQueriedDetails struct {
    TokenID       string `json:"tokenId"`
}

// EventPublisher defines an interface to publish events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher implements EventPublisher using a logging system.
type LoggerEventPublisher struct{}

// Publish logs the event using a standard logger or an external system.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Failed to marshal event: %v", err)
        return err
    }
    log.Println("Event Published:", string(eventData))
    return nil
}

// EmitEvent creates and publishes an event.
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

// Example usage
func main() {
    publisher := &LoggerEventPublisher{}

    // Emitting a token created event
    details := TokenCreatedDetails{
        TokenID:   "12345",
        AssetType: "Corn",
        Owner:     "Farmer Joe",
    }
    EmitEvent(publisher, TokenCreated, details)

    // This pattern can be applied to emit other types of events
}
