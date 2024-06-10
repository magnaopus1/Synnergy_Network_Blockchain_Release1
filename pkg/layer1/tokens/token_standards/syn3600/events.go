package syn3600

import (
    "encoding/json"
    "log"
    "time"
)

// EventType defines the types of events associated with futures contracts.
type EventType string

const (
    EventTypeFutureCreated   EventType = "FutureCreated"
    EventTypeFutureSettled   EventType = "FutureSettled"
    EventTypeFutureExpired   EventType = "FutureExpired"
)

// Event encapsulates the details of a noteworthy occurrence within the system.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// FutureCreatedDetails includes information for a newly created futures contract.
type FutureCreatedDetails struct {
    TokenID       string  `json:"tokenId"`
    Asset         string  `json:"asset"`
    Quantity      float64 `json:"quantity"`
    StrikePrice   float64 `json:"strikePrice"`
    ExpiryDate    time.Time `json:"expiryDate"`
    Holder        string  `json:"holder"`
}

// FutureSettledDetails includes information when a futures contract is settled.
type FutureSettledDetails struct {
    TokenID          string  `json:"tokenId"`
    SettlementPrice  float64 `json:"settlementPrice"`
}

// FutureExpiredDetails is used when a futures contract reaches its expiry without being settled.
type FutureExpiredDetails struct {
    TokenID string `json:"tokenId"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher is an implementation of EventPublisher that logs events to the standard logger.
type LoggerEventPublisher struct{}

// Publish logs the event to the console.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", eventData)
    return nil
}

// EmitFutureCreated is triggered when a new futures contract is created.
func EmitFutureCreated(publisher EventPublisher, tokenID, asset string, quantity, strikePrice float64, expiryDate time.Time, holder string) {
    details := FutureCreatedDetails{
        TokenID:     tokenID,
        Asset:       asset,
        Quantity:    quantity,
        StrikePrice: strikePrice,
        ExpiryDate:  expiryDate,
        Holder:      holder,
    }
    event := Event{
        Type:      EventTypeFutureCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit future created event: %v", err)
    }
}

// EmitFutureSettled is triggered when a futures contract is settled.
func EmitFutureSettled(publisher EventPublisher, tokenID string, settlementPrice float64) {
    details := FutureSettledDetails{
        TokenID:        tokenID,
        SettlementPrice: settlementPrice,
    }
    event := Event{
        Type:      EventTypeFutureSettled,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit future settled event: %v", err)
    }
}

// EmitFutureExpired is triggered when a futures contract expires.
func EmitFutureExpired(publisher EventPublisher, tokenID string) {
    details := FutureExpiredDetails{
        TokenID: tokenID,
    }
    event := Event{
        Type:      EventTypeFutureExpired,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit future expired event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
