package syn4700

import (
    "encoding/json"
    "log"
    "time"
)

// EventType categorizes types of events related to legal tokens.
type EventType string

const (
    LegalTokenCreated   EventType = "LegalTokenCreated"
    LegalTokenUpdated   EventType = "LegalTokenUpdated"
    LegalTokenSigned    EventType = "LegalTokenSigned"
    LegalTokenQueried   EventType = "LegalTokenQueried"
)

// Event represents a structured log entry for events within the legal token lifecycle.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// LegalTokenCreatedDetails contains specifics for when a legal token is created.
type LegalTokenCreatedDetails struct {
    TokenID      string `json:"tokenId"`
    DocumentType string `json:"documentType"`
    Parties      []string `json:"parties"`
}

// LegalTokenUpdatedDetails contains specifics for when a legal token's status is updated.
type LegalTokenUpdatedDetails struct {
    TokenID string `json:"tokenId"`
    Status  string `json:"status"`
}

// LegalTokenSignedDetails contains specifics for when a legal token is signed.
type LegalTokenSignedDetails struct {
    TokenID string `json:"tokenId"`
    Party   string `json:"party"`
}

// LegalTokenQueriedDetails contains specifics when a legal token is accessed or queried.
type LegalTokenQueriedDetails struct {
    TokenID string `json:"tokenId"`
}

// EventPublisher defines an interface to publish events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher uses a logging system to publish events.
type LoggerEventPublisher struct{}

// Publish logs the event using standard or custom logging tools.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", eventData)
    return nil
}

// EmitLegalTokenCreated publishes an event when a legal token is created.
func EmitLegalTokenCreated(publisher EventPublisher, tokenID, documentType string, parties []string) {
    details := LegalTokenCreatedDetails{
        TokenID:      tokenID,
        DocumentType: documentType,
        Parties:      parties,
    }
    event := Event{
        Type:      LegalTokenCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit legal token created event: %v", err)
    }
}

// EmitLegalTokenUpdated publishes an event when a legal token's status is updated.
func EmitLegalTokenUpdated(publisher EventPublisher, tokenID, status string) {
    details := LegalTokenUpdatedDetails{
        TokenID: tokenID,
        Status:  status,
    }
    event := Event{
        Type:      LegalTokenUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit legal token updated event: %v", err)
    }
}

// EmitLegalTokenSigned publishes an event when a legal token is signed by a party.
func EmitLegalTokenSigned(publisher EventPublisher, tokenID, party string) {
    details := LegalTokenSignedDetails{
        TokenID: tokenID,
        Party:   party,
    }
    event := Event{
        Type:      LegalTokenSigned,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit legal token signed event: %v", err)
    }
}

// EmitLegalTokenQueried publishes an event when a legal token is queried.
func EmitLegalTokenQueried(publisher EventPublisher, tokenID string) {
    details := LegalTokenQueriedDetails{TokenID: tokenID}
    event := Event{
        Type:      LegalTokenQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit legal token queried event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
