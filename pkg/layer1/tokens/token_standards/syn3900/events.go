package syn3900

import (
    "encoding/json"
    "log"
    "time"
)

// EventType specifies the types of events associated with benefit tokens.
type EventType string

const (
    EventTypeBenefitCreated   EventType = "BenefitCreated"
    EventTypeBenefitUpdated   EventType = "BenefitUpdated"
    EventTypeBenefitQueried   EventType = "BenefitQueried"
)

// Event represents a structured format for logging actions taken on benefit tokens.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// BenefitCreatedDetails contains details for when a benefit token is created.
type BenefitCreatedDetails struct {
    TokenID     string  `json:"tokenId"`
    BenefitType string  `json:"benefitType"`
    Recipient   string  `json:"recipient"`
    Amount      float64 `json:"amount"`
}

// BenefitUpdatedDetails contains details for when a benefit token's status is updated.
type BenefitUpdatedDetails struct {
    TokenID string `json:"tokenId"`
    Status  string `json:"status"`
}

// BenefitQueriedDetails contains details for when a benefit token is queried.
type BenefitQueriedDetails struct {
    TokenID string `json:"tokenId"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher implements EventPublisher to log events using standard logging mechanisms.
type LoggerEventPublisher struct{}

// Publish logs the event to a standard output or logging system, formatted as JSON.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", string(eventData))
    return nil
}

// EmitBenefitCreated publishes an event when a new benefit token is created.
func EmitBenefitCreated(publisher EventPublisher, tokenID, benefitType, recipient string, amount float64) {
    details := BenefitCreatedDetails{
        TokenID:     tokenID,
        BenefitType: benefitType,
        Recipient:   recipient,
        Amount:      amount,
    }
    event := Event{
        Type:      EventTypeBenefitCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit benefit created event: %v", err)
    }
}

// EmitBenefitUpdated publishes an event when the status of a benefit token is updated.
func EmitBenefitUpdated(publisher EventPublisher, tokenID, status string) {
    details := BenefitUpdatedDetails{
        TokenID: tokenID,
        Status:  status,
    }
    event := Event{
        Type:      EventTypeBenefitUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit benefit updated event: %v", err)
    }
}

// EmitBenefitQueried publishes an event when a benefit token is queried.
func EmitBenefitQueried(publisher EventPublisher, tokenID string) {
    details := BenefitQueriedDetails{
        TokenID: tokenID,
    }
    event := Event{
        Type:      EventTypeBenefitQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit benefit queried event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
