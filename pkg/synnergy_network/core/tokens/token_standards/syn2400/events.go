package syn2400

import (
	"encoding/json"
	"log"
	"time"
)

// Event defines the structure of a standard event in the data marketplace.
type Event struct {
	Type      string    `json:"type"`      // Type of event (e.g., "TokenCreated", "TokenTransferred", etc.)
	Timestamp time.Time `json:"timestamp"` // Timestamp of the event occurrence
	Payload   interface{} `json:"payload"` // Data relevant to the event
}

// EventManager handles publishing and subscribing to events.
type EventManager struct {
	subscribers map[string][]chan Event
}

// NewEventManager creates a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{
		subscribers: make(map[string][]chan Event),
	}
}

// Publish emits an event to all subscribers interested in that event type.
func (em *EventManager) Publish(event Event) {
	if channels, found := em.subscribers[event.Type]; found {
		for _, ch := range channels {
			// Non-blocking send with select
			select {
			case ch <- event:
			default:
				log.Printf("Dropping event, no receivers ready for event type: %s", event.Type)
			}
		}
	}
}

// Subscribe adds a new subscriber channel for a specific event type.
func (em *EventManager) Subscribe(eventType string, ch chan Event) {
	if _, found := em.subscribers[eventType]; !found {
		em.subscribers[eventType] = []chan Event{}
	}
	em.subscribers[eventType] = append(em.subscribers[eventType], ch)
}

// Unsubscribe removes a subscriber channel for a specific event type.
func (em *EventManager) Unsubscribe(eventType string, ch chan Event) {
	if channels, found := em.subscribers[eventType]; found {
		for i, channel := range channels {
			if channel == ch {
				em.subscribers[eventType] = append(channels[:i], channels[i+1:]...)
				break
			}
		}
	}
}

// buildEvent creates an event object from given parameters.
func buildEvent(eventType string, payload interface{}) Event {
	return Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

// SerializeEvent serializes an Event to JSON string for logging or networking.
func SerializeEvent(event Event) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeEvent deserializes a JSON string back to an Event object.
func DeserializeEvent(data string) (Event, error) {
	var event Event
	err := json.Unmarshal([]byte(data), &event)
	if err != nil {
		return Event{}, err
	}
	return event, nil
}
