package syn1300

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// Event types for different stages of asset lifecycle within the supply chain.
const (
	EventAddAsset    = "ADD_ASSET"
	EventUpdateAsset = "UPDATE_ASSET"
	EventTransferAsset = "TRANSFER_ASSET"
)

// Event represents an event in the lifecycle of a supply chain asset.
type Event struct {
	Type      string    `json:"type"`
	AssetID   string    `json:"asset_id"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}

// EventLogger manages the logging of events to an external or internal log system.
type EventLogger struct {
	Events []Event
}

// NewEventLogger initializes a new event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{
		Events: make([]Event, 0),
	}
}

// LogEvent logs a new event in the supply chain token lifecycle.
func (el *EventLogger) LogEvent(eventType, assetID, details string) {
	event := Event{
		Type:      eventType,
		AssetID:   assetID,
		Timestamp: time.Now(),
		Details:   details,
	}
	el.Events = append(el.Events, event)
	log.Printf("Event logged: %s for asset %s - %s", eventType, assetID, details)
}

// GetEvents returns all events logged by the EventLogger.
func (el *EventLogger) GetEvents() []Event {
	return el.Events
}

// MarshalJSON is used to custom encode the event log to JSON, ensuring that timestamps are correctly formatted.
func (e *Event) MarshalJSON() ([]byte, error) {
	type Alias Event
	return json.Marshal(&struct {
		Timestamp string `json:"timestamp"`
		*Alias
	}{
		Timestamp: e.Timestamp.Format(time.RFC3339),
		Alias:     (*Alias)(e),
	})
}

// ExampleUsage shows how to use the EventLogger within the supply chain token system.
func ExampleUsage() {
	logger := NewEventLogger()
	logger.LogEvent(EventAddAsset, "Asset123", "New asset added to the system.")
	logger.LogEvent(EventUpdateAsset, "Asset123", "Asset location updated.")
	logger.LogEvent(EventTransferAsset, "Asset123", "Asset transferred to a new owner.")

	// Retrieve and print all events
	events := logger.GetEvents()
	for _, e := range events {
		fmt.Printf("Event: %s at %s - %s\n", e.Type, e.Timestamp.Format(time.RFC3339), e.Details)
	}
}

// Note: ExampleUsage would typically be removed in production and is just for demonstration purposes.
