package syn3400

import (
    "encoding/json"
    "log"
    "time"
)

// EventType defines the types of events within the forex token ecosystem.
type EventType string

const (
    EventTypePositionOpened EventType = "PositionOpened"
    EventTypePositionClosed EventType = "PositionClosed"
    EventTypeRateUpdated    EventType = "RateUpdated"
)

// Event represents a general event structure.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// PositionOpenedDetails contains details for when a forex position is opened.
type PositionOpenedDetails struct {
    TokenID     string  `json:"tokenId"`
    PairID      string  `json:"pairId"`
    Holder      string  `json:"holder"`
    PositionSize float64 `json:"positionSize"`
    OpenRate    float64 `json:"openRate"`
    IsLong      bool    `json:"isLong"`
}

// PositionClosedDetails contains details for when a forex position is closed.
type PositionClosedDetails struct {
    TokenID     string  `json:"tokenId"`
    PairID      string  `json:"pairId"`
    ClosingRate float64 `json:"closingRate"`
    ProfitLoss  float64 `json:"profitLoss"`
}

// RateUpdatedDetails contains details for when the rate of a forex pair is updated.
type RateUpdatedDetails struct {
    PairID      string  `json:"pairId"`
    NewRate     float64 `json:"newRate"`
}

// EventPublisher defines an interface for publishing events.
type EventPublisher interface {
    Publish(event Event) error
}

// LoggerEventPublisher logs events to a standard output.
type LoggerEventPublisher struct{}

// Publish logs the event.
func (l *LoggerEventPublisher) Publish(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        log.Printf("Error marshaling event: %v", err)
        return err
    }
    log.Printf("Event Published: %s", string(eventData))
    return nil
}

// EmitPositionOpened emits an event when a forex position is opened.
func EmitPositionOpened(publisher EventPublisher, tokenID, pairID, holder string, size float64, openRate float64, isLong bool) {
    details := PositionOpenedDetails{
        TokenID: tokenID,
        PairID: pairID,
        Holder: holder,
        PositionSize: size,
        OpenRate: openRate,
        IsLong: isLong,
    }
    event := Event{
        Type: EventTypePositionOpened,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit position opened event: %v", err)
    }
}

// EmitPositionClosed emits an event when a forex position is closed.
func EmitPositionClosed(publisher EventPublisher, tokenID, pairID string, closingRate, profitLoss float64) {
    details := PositionClosedDetails{
        TokenID: tokenID,
        PairID: pairID,
        ClosingRate: closingRate,
        ProfitLoss: profitLoss,
    }
    event := Event{
        Type: EventTypePositionClosed,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit position closed event: %v", err)
    }
}

// EmitRateUpdated emits an event when the rate of a forex pair is updated.
func EmitRateUpdated(publisher EventPublisher, pairID string, newRate float64) {
    details := RateUpdatedDetails{
        PairID: pairID,
        NewRate: newRate,
    }
    event := Event{
        Type: EventTypeRateUpdated,
        Timestamp: time.Now(),
        Details: details,
    }
    if err := publisher.Publish(event); err != nil {
        log.Printf("Failed to emit rate updated event: %v", err)
    }
}

// Ensure LoggerEventPublisher implements EventPublisher.
var _ EventPublisher = &LoggerEventPublisher{}
