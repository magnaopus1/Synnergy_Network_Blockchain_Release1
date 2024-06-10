package syn3500

import (
    "encoding/json"
    "log"
    "time"
)

// EventType defines the different types of events for currency tokens.
type EventType string

const (
    EventTypeTokenCreated EventType = "TokenCreated"
    EventTypeTokenTransferred EventType = "TokenTransferred"
    EventTypeBalanceUpdated EventType = "BalanceUpdated"
)

// Event represents a basic event structure.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// TokenCreatedDetails contains details for when a currency token is issued.
type TokenCreatedDetails struct {
    TokenID     string  `json:"tokenId"`
    CurrencyCode string `json:"currencyCode"`
    Holder      string  `json:"holder"`
    InitialBalance float64 `json:"initialBalance"`
}

// TokenTransferredDetails contains details for when currency is transferred between tokens.
type TokenTransferredDetails struct {
    FromTokenID string  `json:"fromTokenId"`
    ToTokenID   string  `json:"toTokenId"`
    Amount      float64 `json:"amount"`
}

// BalanceUpdatedDetails contains details for when a token's balance is updated.
type BalanceUpdatedDetails struct {
    TokenID     string  `json:"tokenId"`
    NewBalance  float64 `json:"newBalance"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher publishes events by logging them.
type LoggerEventPublisher struct{}

// Publish logs the event to a standard logger.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", string(eventData))
    return nil
}

// EmitTokenCreated emits an event when a currency token is created.
func EmitTokenCreated(publisher EventPublisher, tokenID, currencyCode, holder string, initialBalance float64) {
    details := TokenCreatedDetails{
        TokenID: tokenID,
        CurrencyCode: currencyCode,
        Holder: holder,
        InitialBalance: initialBalance,
    }
    event := Event{
        Type: EventTypeTokenCreated,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit token created event: %v", err)
    }
}

// EmitTokenTransferred emits an event when a currency transfer occurs.
func EmitTokenTransferred(publisher EventPublisher, fromTokenID, toTokenID string, amount float64) {
    details := TokenTransferredDetails{
        FromTokenID: fromTokenID,
        ToTokenID: toTokenID,
        Amount: amount,
    }
    event := Event{
        Type: EventTypeTokenTransferred,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit token transferred event: %v", err)
    }
}

// EmitBalanceUpdated emits an event when a token's balance is updated.
func EmitBalanceUpdated(publisher EventPublisher, tokenID string, newBalance float64) {
    details := BalanceUpdatedDetails{
        TokenID: tokenID,
        NewBalance: newBalance,
    }
    event := Event{
        Type: EventTypeBalanceUpdated,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit balance updated event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
