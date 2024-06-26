package syn4200

import (
    "encoding/json"
    "log"
    "time"
)

// EventType specifies the types of events related to charity tokens.
type EventType string

const (
    EventTypeCharityTokenCreated   EventType = "CharityTokenCreated"
    EventTypeCharityTokenUpdated   EventType = "CharityTokenUpdated"
    EventTypeCharityTokenQueried   EventType = "CharityTokenQueried"
)

// Event represents a structured format for logging actions on charity tokens.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// CharityTokenCreatedDetails holds the details when a charity token is created.
type CharityTokenCreatedDetails struct {
    TokenID      string  `json:"tokenId"`
    CampaignName string  `json:"campaignName"`
    Donor        string  `json:"donor"`
    Amount       float64 `json:"amount"`
    Purpose      string  `json:"purpose"`
}

// CharityTokenUpdatedDetails holds the details when a charity token's status is updated.
type CharityTokenUpdatedDetails struct {
    TokenID string `json:"tokenId"`
    Status  string `json:"status"`
}

// CharityTokenQueriedDetails holds the details when a charity token is queried.
type CharityTokenQueriedDetails struct {
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

// EmitCharityTokenCreated publishes an event when a new charity token is created.
func EmitCharityTokenCreated(publisher EventPublisher, tokenID, campaignName, donor, purpose string, amount float64) {
    details := CharityTokenCreatedDetails{
        TokenID:      tokenID,
        CampaignName: campaignName,
        Donor:        donor,
        Amount:       amount,
        Purpose:      purpose,
    }
    event := Event{
        Type:      EventTypeCharityTokenCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit charity token created event: %v", err)
    }
}

// EmitCharityTokenUpdated publishes an event when the status of a charity token is updated.
func EmitCharityTokenUpdated(publisher EventPublisher, tokenID, status string) {
    details := CharityTokenUpdatedDetails{
        TokenID: tokenID,
        Status:  status,
    }
    event := Event{
        Type:      EventTypeCharityTokenUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit charity token updated event: %v", err)
    }
}

// EmitCharityTokenQueried publishes an event when a charity token is queried.
func EmitCharityTokenQueried(publisher EventPublisher, tokenID string) {
    details := CharityTokenQueriedDetails{
        TokenID: tokenID,
    }
    event := Event{
        Type:      EventTypeCharityTokenQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit charity token queried event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
