package syn130

import (
	"encoding/json"
	"log"
)

// Event types for asset tokens
const (
	TokenCreated   = "TokenCreated"
	TokenUpdated   = "TokenUpdated"
	TokenDeleted   = "TokenDeleted"
	AssetValuationChanged = "AssetValuationChanged"
)

// Event represents a token-related event.
type Event struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// EventManager handles the emission and logging of events.
type EventManager struct {
	Subscribers map[string][]chan Event
}

// NewEventManager creates a new event manager.
func NewEventManager() *EventManager {
	return &EventManager{
		Subscribers: make(map[string][]chan Event),
	}
}

// Emit emits an event to all subscribers of the event type.
func (em *EventManager) Emit(event Event) {
	if subscribers, found := em.Subscribers[event.Type]; found {
		for _, subscriber := range subscribers {
			go func(sub chan Event) {
				sub <- event
				log.Printf("Event %s emitted to a subscriber.", event.Type)
			}(subscriber)
		}
	}
	logEvent(event)
}

// Subscribe allows a caller to subscribe to a specific type of event.
func (em *EventManager) Subscribe(eventType string, subscriber chan Event) {
	if _, found := em.Subscribers[eventType]; !found {
		em.Subscribers[eventType] = make([]chan Event, 0)
	}
	em.Subscribers[eventType] = append(em.Subscribers[eventType], subscriber)
	log.Printf("New subscriber added for event type: %s", eventType)
}

// Unsubscribe removes a subscriber from the event type.
func (em *EventManager) Unsubscribe(eventType string, subscriber chan Event) {
	if subscribers, found := em.Subscribers[eventType]; found {
		for i, sub := range subscribers {
			if sub == subscriber {
				em.Subscribers[eventType] = append(subscribers[:i], subscribers[i+1:]...)
				close(sub)
				log.Printf("Subscriber removed for event type: %s", eventType)
				break
			}
		}
	}
}

// logEvent logs the event details.
func logEvent(event Event) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal event: %v", err)
		return
	}
	log.Printf("Event logged: %s", eventJSON)
}

// Example usage and creation of events would go here.
