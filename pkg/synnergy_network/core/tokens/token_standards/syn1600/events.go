package syn1600

import (
    "encoding/json"
    "fmt"
    "time"
)

// EventType defines the type of events that can occur with a RoyaltyToken.
type EventType string

const (
    TokenCreated    EventType = "TokenCreated"
    RevenueRecorded EventType = "RevenueRecorded"
    OwnershipTransferred EventType = "OwnershipTransferred"
)

// Event represents an action or occurrence related to a RoyaltyToken.
type Event struct {
    Type      EventType   `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Details   interface{} `json:"details"`
}

// EventLogger defines the interface for an event logging mechanism.
type EventLogger interface {
    LogEvent(event Event) error
}

// SimpleLogger is a basic logger that prints events to standard output or another logging system.
type SimpleLogger struct{}

// LogEvent logs an event using the standard logging mechanism.
func (l *SimpleLogger) LogEvent(event Event) error {
    eventData, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to marshal event: %v", err)
    }
    fmt.Printf("Event Logged at %v: %s\n", event.Timestamp, string(eventData))
    return nil
}

// NewEvent creates a new event and logs it using the provided logger.
func NewEvent(logger EventLogger, eventType EventType, details interface{}) error {
    event := Event{
        Type:      eventType,
        Timestamp: time.Now(),
        Details:   details,
    }
    return logger.LogEvent(event)
}

// Example of how to use the event system with a token.
func ExampleUsage(logger EventLogger) {
    // Creating a new token example
    tokenID := GenerateTokenID("Symphony No.5", "ComposerA")
    token := NewRoyaltyToken(tokenID, "ComposerA", "Symphony No.5")
    
    // Log token creation event
    creationDetails := map[string]string{
        "ID": token.ID,
        "Owner": token.Owner,
        "MusicTitle": token.MusicTitle,
    }
    if err := NewEvent(logger, TokenCreated, creationDetails); err != nil {
        fmt.Println("Error logging event:", err)
    }

    // Record revenue and log the event
    token.RecordRevenue("Streaming", 10000)
    revenueDetails := map[string]interface{}{
        "ID": token.ID,
        "StreamType": "Streaming",
        "Amount": 10000,
    }
    if err := NewEvent(logger, RevenueRecorded, revenueDetails); err != nil {
        fmt.Println("Error logging event:", err)
    }

    // Transfer ownership and log the event
    token.TransferOwnership("PublisherB")
    transferDetails := map[string]string{
        "ID": token.ID,
        "OldOwner": "ComposerA",
        "NewOwner": "PublisherB",
    }
    if err := NewEvent(logger, OwnershipTransferred, transferDetails); err != nil {
        fmt.Println("Error logging event:", err)
    }
}

