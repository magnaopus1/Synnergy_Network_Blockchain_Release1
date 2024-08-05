// Package events provides functionalities related to event management for the SYN3200 Token Standard.
package events

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Event represents a blockchain event.
type Event struct {
	EventID   string
	Timestamp time.Time
	EventType string
	Data      map[string]interface{}
}

// EventListener defines the method that must be implemented by any listener.
type EventListener interface {
	HandleEvent(event Event)
}

// EventManager manages blockchain events and listeners.
type EventManager struct {
	listeners map[string][]EventListener
	events    []Event
	mutex     sync.Mutex
}

// NewEventManager creates a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{
		listeners: make(map[string][]EventListener),
		events:    []Event{},
	}
}

// AddEventListener adds a listener for a specific event type.
func (em *EventManager) AddEventListener(eventType string, listener EventListener) {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	em.listeners[eventType] = append(em.listeners[eventType], listener)
}

// RemoveEventListener removes a listener for a specific event type.
func (em *EventManager) RemoveEventListener(eventType string, listener EventListener) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	listeners, exists := em.listeners[eventType]
	if !exists {
		return errors.New("no listeners for event type")
	}

	for i, l := range listeners {
		if l == listener {
			em.listeners[eventType] = append(listeners[:i], listeners[i+1:]...)
			return nil
		}
	}

	return errors.New("listener not found")
}

// EmitEvent emits an event to all listeners of the event type.
func (em *EventManager) EmitEvent(eventType string, data map[string]interface{}) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	event := Event{
		EventID:   generateEventID(),
		Timestamp: time.Now(),
		EventType: eventType,
		Data:      data,
	}
	em.events = append(em.events, event)

	listeners, exists := em.listeners[eventType]
	if exists {
		for _, listener := range listeners {
			go listener.HandleEvent(event)
		}
	}
}

// GetEvents retrieves all events.
func (em *EventManager) GetEvents() []Event {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	return em.events
}

// GetEventsByType retrieves all events of a specific type.
func (em *EventManager) GetEventsByType(eventType string) []Event {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	var filteredEvents []Event
	for _, event := range em.events {
		if event.EventType == eventType {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// SerializeEvent serializes an event to JSON.
func SerializeEvent(event Event) (string, error) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(eventJSON), nil
}

// DeserializeEvent deserializes an event from JSON.
func DeserializeEvent(eventJSON string) (Event, error) {
	var event Event
	err := json.Unmarshal([]byte(eventJSON), &event)
	if err != nil {
		return Event{}, err
	}
	return event, nil
}

// generateEventID generates a unique ID for an event.
func generateEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// ExampleEventListener is an example implementation of the EventListener interface.
type ExampleEventListener struct{}

// HandleEvent handles an event.
func (e *ExampleEventListener) HandleEvent(event Event) {
	// Handle the event (e.g., log it, process it, etc.)
	fmt.Printf("Event received: %+v\n", event)
}

