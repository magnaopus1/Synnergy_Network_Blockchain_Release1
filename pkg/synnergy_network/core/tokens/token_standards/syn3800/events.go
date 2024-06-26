package syn3800

import (
    "encoding/json"
    "log"
    "time"
)

// EventType specifies the types of events associated with grant tokens.
type EventType string

const (
    EventTypeGrantCreated   EventType = "GrantCreated"
    EventTypeGrantUpdated   EventType = "GrantUpdated"
    EventTypeFundsDisbursed EventType = "FundsDisbursed"
    EventTypeGrantQueried   EventType = "GrantQueried"
)

// Event represents a generic structure for logging and monitoring purposes.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// GrantCreatedDetails holds information for when a grant token is created.
type GrantCreatedDetails struct {
    TokenID     string  `json:"tokenId"`
    GrantName   string  `json:"grantName"`
    Beneficiary string  `json:"beneficiary"`
    Amount      float64 `json:"amount"`
    Purpose     string  `json:"purpose"`
}

// GrantUpdatedDetails holds information for when a grant token's details are updated.
type GrantUpdatedDetails struct {
    TokenID         string  `json:"tokenId"`
    DisbursedAmount float64 `json:"disbursedAmount"`
}

// FundsDisbursedDetails holds information for when funds are disbursed from a grant token.
type FundsDisbursedDetails struct {
    TokenID         string  `json:"tokenId"`
    DisbursedAmount float64 `json:"disbursedAmount"`
}

// GrantQueriedDetails holds information for when a grant token is queried.
type GrantQueriedDetails struct {
    TokenID string `json:"tokenId"`
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

// EmitGrantCreated publishes an event when a new grant token is created.
func EmitGrantCreated(publisher EventPublisher, tokenId, grantName, beneficiary, purpose string, amount float64) {
    details := GrantCreatedDetails{
        TokenID:     tokenId,
        GrantName:   grantName,
        Beneficiary: beneficiary,
        Amount:      amount,
        Purpose:     purpose,
    }
    event := Event{
        Type:      EventTypeGrantCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit grant created event: %v", err)
    }
}

// EmitGrantUpdated publishes an event when a grant token is updated.
func EmitGrantUpdated(publisher EventPublisher, tokenId string, disbursedAmount float64) {
    details := GrantUpdatedDetails{
        TokenID:         tokenId,
        DisbursedAmount: disbursedAmount,
    }
    event := Event{
        Type:      EventTypeGrantUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit grant updated event: %v", err)
    }
}

// EmitFundsDisbursed publishes an event when funds are disbursed from a grant token.
func EmitFundsDisbursed(publisher EventPublisher, tokenId string, disbursedAmount float64) {
    details := FundsDisbursedDetails{
        TokenID:         tokenId,
        DisbursedAmount: disbursedAmount,
    }
    event := Event{
        Type:      EventTypeFundsDisbursed,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit funds disbursed event: %v", err)
    }
}

// EmitGrantQueried publishes an event when a grant token is queried.
func EmitGrantQueried(publisher EventPublisher, tokenId string) {
    details := GrantQueriedDetails{
        TokenID: tokenId,
    }
    event := Event{
        Type:      EventTypeGrantQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit grant queried event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
