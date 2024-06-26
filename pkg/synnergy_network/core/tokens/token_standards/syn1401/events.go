package syn1401

import (
    "fmt"
    "log"
    "time"
)

// TokenEvent defines the type and description of operations performed on the tokens.
type TokenEvent struct {
    Type        string    `json:"type"`
    Description string    `json:"description"`
    Timestamp   time.Time `json:"timestamp"`
    TokenID     string    `json:"token_id"`
    Details     map[string]interface{} `json:"details"`
}

// EventLogger maintains a log of all token-related events.
type EventLogger struct {
    Events []TokenEvent
}

// NewEventLogger creates a new event logger instance.
func NewEventLogger() *EventLogger {
    return &EventLogger{}
}

// LogEvent records a new event in the event logger.
func (el *EventLogger) LogEvent(eventType, description, tokenID string, details map[string]interface{}) {
    event := TokenEvent{
        Type:        eventType,
        Description: description,
        Timestamp:   time.Now(),
        TokenID:     tokenID,
        Details:     details,
    }
    el.Events = append(el.Events, event)
    log.Printf("Event logged: %s - %s for token %s", eventType, description, tokenID)
}

// GetEvents returns a slice of all events logged.
func (el *EventLogger) GetEvents() []TokenEvent {
    return el.Events
}

// Example of how to use the event logger with investment tokens.
func ExampleEventLogging() {
    logger := NewEventLogger()
    tokenID := "token1234"
    details := map[string]interface{}{
        "owner": "user456",
        "yield": 5.0,
    }

    // Log the creation of a new token
    logger.LogEvent("Create", "Token created", tokenID, details)

    // Log a transfer of ownership
    details["previous_owner"] = "user456"
    details["new_owner"] = "user789"
    logger.LogEvent("TransferOwnership", "Ownership transferred", tokenID, details)

    // Log updating the investment yield
    details["new_yield"] = 6.0
    logger.LogEvent("UpdateYield", "Investment yield updated", tokenID, details)

    // Retrieve and print all events
    events := logger.GetEvents()
    for _, event := range events {
        fmt.Printf("Event: %s at %s, Details: %+v\n", event.Type, event.Timestamp, event.Details)
    }
}

