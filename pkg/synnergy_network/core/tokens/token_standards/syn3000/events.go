package syn3000

import (
    "fmt"
    "log"
    "sync"
    "time"
)

// Event represents an action or change related to a reputation token.
type Event struct {
    Timestamp time.Time
    TokenID   string
    ActionType string
    Details   string
}

// EventLogger manages the logging of all reputation token events.
type EventLogger struct {
    Events []Event
    mutex  sync.Mutex
}

// NewEventLogger initializes a new EventLogger.
func NewEventLogger() *EventLogger {
    return &EventLogger{
        Events: make([]Event, 0),
    }
}

// LogEvent records an event to the logger.
func (el *EventLogger) LogEvent(tokenID, actionType, details string) {
    el.mutex.Lock()
    defer el.mutex.Unlock()

    newEvent := Event{
        Timestamp: time.Now(),
        TokenID:   tokenID,
        ActionType: actionType,
        Details:   details,
    }
    el.Events = append(el.Events, newEvent)
    log.Printf("Event logged: %s - %s", tokenID, details)
}

// GetEvents returns a list of all events for a specific token.
func (el *EventLogger) GetEvents(tokenID string) []Event {
    el.mutex.Lock()
    defer el.mutex.Unlock()

    var filteredEvents []Event
    for _, event := range el.Events {
        if event.TokenID == tokenID {
            filteredEvents = append(filteredEvents, event)
        }
    }
    return filteredEvents
}

// Example of logging and retrieving events.
func ExampleEventLogging() {
    logger := NewEventLogger()
    tokenID := "token1234"

    // Simulating event logging
    logger.LogEvent(tokenID, "Create", "Token created with initial score 50")
    logger.LogEvent(tokenID, "Update", "Reputation score updated to 75")
    logger.LogEvent(tokenID, "Transfer", "Ownership transferred to user456")

    // Retrieving and displaying events
    events := logger.GetEvents(tokenID)
    for _, event := range events {
        fmt.Printf("%s - %s: %s\n", event.Timestamp, event.ActionType, event.Details)
    }
}
