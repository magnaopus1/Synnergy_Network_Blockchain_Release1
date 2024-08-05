package events

import (
    "fmt"
    "time"

    "github.com/synnergy_network/blockchain/security"
    "github.com/synnergy_network/blockchain/storage"
)

// Event struct contains details about each event
type Event struct {
    EventID        string
    EventType      string
    Timestamp      time.Time
    Description    string
    Data           string
}

// EventLogger struct handles event logging and notifications
type EventLogger struct {
    Security security.Security
    Storage  storage.Storage
}

// NewEventLogger constructor
func NewEventLogger(security security.Security, storage storage.Storage) *EventLogger {
    return &EventLogger{
        Security: security,
        Storage:  storage,
    }
}

// LogEvent logs an event to the storage
func (el *EventLogger) LogEvent(eventType, description, data string) (string, error) {
    eventID := el.generateEventID(eventType)
    timestamp := time.Now()

    encryptedData, err := el.Security.EncryptData(data)
    if err != nil {
        return "", fmt.Errorf("error encrypting event data: %v", err)
    }

    event := Event{
        EventID:     eventID,
        EventType:   eventType,
        Timestamp:   timestamp,
        Description: description,
        Data:        encryptedData,
    }

    if err := el.Storage.SaveEvent(eventID, event); err != nil {
        return "", fmt.Errorf("error saving event: %v", err)
    }

    return eventID, nil
}

// GetEvent retrieves an event by its ID
func (el *EventLogger) GetEvent(eventID string) (Event, error) {
    event, err := el.Storage.GetEvent(eventID)
    if err != nil {
        return Event{}, fmt.Errorf("error retrieving event: %v", err)
    }

    decryptedData, err := el.Security.DecryptData(event.Data)
    if err != nil {
        return Event{}, fmt.Errorf("error decrypting event data: %v", err)
    }

    event.Data = decryptedData

    return event, nil
}

// generateEventID generates a unique ID for an event
func (el *EventLogger) generateEventID(eventType string) string {
    // Assuming a function that generates a unique ID based on eventType and current time
    return fmt.Sprintf("%s-%d", eventType, time.Now().UnixNano())
}

// NotifyUser sends a notification to the user about an event
func (el *EventLogger) NotifyUser(event Event, userID string) error {
    notification := fmt.Sprintf("Event Type: %s\nDescription: %s\nTimestamp: %s", event.EventType, event.Description, event.Timestamp.Format(time.RFC3339))

    // Assuming a function that sends a notification to the user
    if err := el.Storage.SendNotification(userID, notification); err != nil {
        return fmt.Errorf("error sending notification: %v", err)
    }

    return nil
}
