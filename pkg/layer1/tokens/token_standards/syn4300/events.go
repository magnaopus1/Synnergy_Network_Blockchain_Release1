package syn4300

import (
    "encoding/json"
    "log"
    "time"
)

// EventType enumerates different types of events that can occur with energy tokens.
type EventType string

const (
    EnergyTokenCreated   EventType = "EnergyTokenCreated"
    EnergyTokenUpdated   EventType = "EnergyTokenUpdated"
    EnergyTokenQueried   EventType = "EnergyTokenQueried"
)

// Event represents a structured log entry for significant occurrences.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// EnergyTokenCreatedDetails includes information for energy token creation events.
type EnergyTokenCreatedDetails struct {
    TokenID      string  `json:"tokenId"`
    AssetType    string  `json:"assetType"`
    Owner        string  `json:"owner"`
    Quantity     float64 `json:"quantity"`
    ValidUntil   time.Time `json:"validUntil"`
}

// EnergyTokenUpdatedDetails includes information for energy token updates.
type EnergyTokenUpdatedDetails struct {
    TokenID string `json:"tokenId"`
    Status  string `json:"status"`
}

// EnergyTokenQueriedDetails includes information when an energy token is accessed.
type EnergyTokenQueriedDetails struct {
    TokenID string `json:"tokenId"`
}

// EventPublisher defines an interface for an event publishing mechanism.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher implements EventPublisher using standard logging.
type LoggerEventPublisher struct{}

// Publish logs events to the standard logger.
func (p *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Println("Event Published:", string(eventData))
    return nil
}

// EmitEnergyTokenCreated logs the creation of an energy token.
func EmitEnergyTokenCreated(publisher EventPublisher, tokenID, assetType, owner string, quantity float64, validUntil time.Time) {
    details := EnergyTokenCreatedDetails{
        TokenID:    tokenID,
        AssetType:  assetType,
        Owner:      owner,
        Quantity:   quantity,
        ValidUntil: validUntil,
    }
    event := Event{
        Type:      EnergyTokenCreated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit creation event: %v", err)
    }
}

// EmitEnergyTokenUpdated logs updates to an energy token, such as status changes.
func EmitEnergyTokenUpdated(publisher EventPublisher, tokenID, status string) {
    details := EnergyTokenUpdatedDetails{
        TokenID: tokenID,
        Status:  status,
    }
    event := Event{
        Type:      EnergyTokenUpdated,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit update event: %v", err)
    }
}

// EmitEnergyTokenQueried logs access to the details of an energy token.
func EmitEnergyTokenQueried(publisher EventPublisher, tokenID string) {
    details := EnergyTokenQueriedDetails{TokenID: tokenID}
    event := Event{
        Type:      EnergyTokenQueried,
        Timestamp: time.Now(),
        Details:   details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit queried event: %v", err)
    }
}

// Ensure that LoggerEventPublisher implements the EventPublisher interface.
var _ EventPublisher = &LoggerEventPublisher{}
