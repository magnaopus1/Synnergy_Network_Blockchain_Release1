package syn2369

import (
	"encoding/json"
	"log"
	"time"
)

// Event types for different actions on virtual items
const (
	ItemCreatedEventType   = "ItemCreated"
	ItemUpdatedEventType   = "ItemUpdated"
	ItemDeletedEventType   = "ItemDeleted"
	ItemTransferredEventType = "ItemTransferred"
)

// Event represents a generic event related to virtual items.
type Event struct {
	Type      string    `json:"type"`      // Type of the event
	Timestamp time.Time `json:"timestamp"` // Time when the event occurred
	Payload   string    `json:"payload"`   // JSON-encoded string containing event-specific data
}

// ItemEventPayload holds data for events related to virtual items.
type ItemEventPayload struct {
	ItemID string `json:"itemId"`
	Owner  string `json:"owner,omitempty"` // Owner is included for transfer and creation events
}

// NewEvent creates a new event with the specified type and data.
func NewEvent(eventType string, data interface{}) Event {
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling event payload: %v", err)
		return Event{}
	}

	return Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   string(payloadBytes),
	}
}

// EmitEvent logs an event to the console or an event bus for external use.
func EmitEvent(event Event) {
	// In a production system, this would be sent to an event bus or logging system
	log.Printf("Event Emitted: %v", event)
}

// EmitItemCreated emits an event when a new virtual item is created.
func EmitItemCreated(itemID, owner string) {
	payload := ItemEventPayload{
		ItemID: itemID,
		Owner:  owner,
	}
	event := NewEvent(ItemCreatedEventType, payload)
	EmitEvent(event)
}

// EmitItemUpdated emits an event when a virtual item is updated.
func EmitItemUpdated(itemID string) {
	payload := ItemEventPayload{
		ItemID: itemID,
	}
	event := NewEvent(ItemUpdatedEventType, payload)
	EmitEvent(event)
}

// EmitItemDeleted emits an event when a virtual item is deleted.
func EmitItemDeleted(itemID string) {
	payload := ItemEventPayload{
		ItemID: itemID,
	}
	event := NewEvent(ItemDeletedEventType, payload)
	EmitEvent(event)
}

// EmitItemTransferred emits an event when the ownership of a virtual item changes.
func EmitItemTransferred(itemID, newOwner string) {
	payload := ItemEventPayload{
		ItemID: itemID,
		Owner:  newOwner,
	}
	event := NewEvent(ItemTransferredEventType, payload)
	EmitEvent(event)
}
