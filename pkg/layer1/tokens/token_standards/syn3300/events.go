package syn3300

import (
    "encoding/json"
    "log"
    "time"
)

// EventType defines the type of events in the ETF token system.
type EventType string

const (
    EventTypeTokenIssued EventType = "TokenIssued"
    EventTypeTokenTransferred EventType = "TokenTransferred"
    EventTypePriceUpdated EventType = "PriceUpdated"
)

// Event represents a generic event in the ETF lifecycle.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// TokenIssuedDetails includes details for the token issuance event.
type TokenIssuedDetails struct {
    TokenID string  `json:"tokenId"`
    ETFID   string  `json:"etfId"`
    Shares  float64 `json:"shares"`
    Holder  string  `json:"holder"`
}

// TokenTransferredDetails includes details for the token transfer event.
type TokenTransferredDetails struct {
    TokenID     string  `json:"tokenId"`
    FromHolder  string  `json:"fromHolder"`
    ToHolder    string  `json:"toHolder"`
    Shares      float64 `json:"shares"`
}

// PriceUpdatedDetails includes details for the ETF price update event.
type PriceUpdatedDetails struct {
    ETFID       string  `json:"etfId"`
    NewPrice    float64 `json:"newPrice"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher publishes events by logging them.
type LoggerEventPublisher struct{}

// Publish logs the event to the standard logger.
func (p *LoggerEventPublisher) Publish(event Event) error {
    data, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", data)
    return nil
}

// EmitTokenIssued emits an event when a new ETF share token is issued.
func EmitTokenIssued(publisher EventPublisher, tokenID, etfID, holder string, shares float64) {
    details := TokenIssuedDetails{
        TokenID: tokenID,
        ETFID:   etfID,
        Shares:  shares,
        Holder:  holder,
    }
    event := Event{
        Type:      EventTypeTokenIssued,
        Timestamp: time.Now(),
        Details:   details,
    }
    err := publisher.Publish(event)
    if err != nil {
        log.Printf("Failed to publish token issued event: %v", err)
    }
}

// EmitTokenTransferred emits an event when a share token is transferred between holders.
func EmitTokenTransferred(publisher EventPublisher, tokenID, fromHolder, toHolder string, shares float64) {
    details := TokenTransferredDetails{
        TokenID:    tokenID,
        FromHolder: fromHolder,
        ToHolder:   toHolder,
        Shares:     shares,
    }
    event := Event{
        Type:      EventTypeTokenTransferred,
        Timestamp: time.Now(),
        Details:   details,
    }
    err := publisher.Publish(event)
    if err != nil {
        log.Printf("Failed to publish token transferred event: %v", err)
    }
}

// EmitPriceUpdated emits an event when the price of an ETF is updated.
func EmitPriceUpdated(publisher EventPublisher, etfID string, newPrice float64) {
    details := PriceUpdatedDetails{
        ETFID:    etfID,
        NewPrice: newPrice,
    }
    event := Event{
        Type:      EventTypePriceUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    err := publisher.Publish(event)
    if err != nil {
        log.Printf("Failed to publish price updated event: %v", err)
    }
}

// Ensure implementations fulfill the interface.
var _ EventPublisher = &LoggerEventPublisher{}
