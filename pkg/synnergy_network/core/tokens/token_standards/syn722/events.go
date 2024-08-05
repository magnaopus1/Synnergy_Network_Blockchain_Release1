package syn722

import (
	"time"
	"sync"
)

// EventType represents different types of events
type EventType int

const (
	EventTypeTokenCreated EventType = iota
	EventTypeTokenTransferred
	EventTypeTokenBurned
	EventTypeTokenModeChanged
	EventTypeMetadataUpdated
)

// Event represents a blockchain event
type Event struct {
	ID        string
	Type      EventType
	Timestamp time.Time
	Data      map[string]interface{}
}

// EventManager manages blockchain events
type EventManager struct {
	mu       sync.RWMutex
	events   []Event
	listeners map[EventType][]chan Event
}

// NewEventManager creates a new EventManager
func NewEventManager() *EventManager {
	return &EventManager{
		events:    make([]Event, 0),
		listeners: make(map[EventType][]chan Event),
	}
}

// AddEvent adds a new event
func (em *EventManager) AddEvent(eventType EventType, data map[string]interface{}) string {
	em.mu.Lock()
	defer em.mu.Unlock()

	event := Event{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	em.events = append(em.events, event)
	em.notifyListeners(event)

	return event.ID
}

// GetEvents returns all events
func (em *EventManager) GetEvents() []Event {
	em.mu.RLock()
	defer em.mu.RUnlock()

	return em.events
}

// GetEventsByType returns events of a specific type
func (em *EventManager) GetEventsByType(eventType EventType) []Event {
	em.mu.RLock()
	defer em.mu.RUnlock()

	events := make([]Event, 0)
	for _, event := range em.events {
		if event.Type == eventType {
			events = append(events, event)
		}
	}

	return events
}

// AddListener adds a listener for a specific event type
func (em *EventManager) AddListener(eventType EventType, listener chan Event) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if _, exists := em.listeners[eventType]; !exists {
		em.listeners[eventType] = make([]chan Event, 0)
	}

	em.listeners[eventType] = append(em.listeners[eventType], listener)
}

// RemoveListener removes a listener for a specific event type
func (em *EventManager) RemoveListener(eventType EventType, listener chan Event) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if listeners, exists := em.listeners[eventType]; exists {
		for i, l := range listeners {
			if l == listener {
				em.listeners[eventType] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
	}
}

// notifyListeners notifies all listeners about an event
func (em *EventManager) notifyListeners(event Event) {
	if listeners, exists := em.listeners[event.Type]; exists {
		for _, listener := range listeners {
			go func(l chan Event) {
				l <- event
			}(listener)
		}
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return "event-" + time.Now().Format("20060102150405.000")
}
