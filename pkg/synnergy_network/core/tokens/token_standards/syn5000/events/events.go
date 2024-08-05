// events.go

package events

import (
	"errors"
	"sync"
	"time"
)

// EventType defines the type of events that can occur in the system
type EventType string

const (
	EventTokenCreation   EventType = "TokenCreation"
	EventTokenTransfer   EventType = "TokenTransfer"
	EventBetPlaced       EventType = "BetPlaced"
	EventBetResolved     EventType = "BetResolved"
	EventComplianceCheck EventType = "ComplianceCheck"
	EventFraudDetected   EventType = "FraudDetected"
)

// Event represents a system event
type Event struct {
	ID          string    // Unique identifier for the event
	Type        EventType // Type of the event
	Description string    // Description of the event
	Timestamp   time.Time // Time the event occurred
	Data        map[string]interface{} // Additional data related to the event
}

// EventListener represents an entity that listens to events
type EventListener interface {
	OnEvent(event *Event)
}

// EventManager manages the events and listeners in the system
type EventManager struct {
	mu           sync.RWMutex
	listeners    map[EventType][]EventListener
	eventHistory []*Event
}

// NewEventManager creates a new EventManager instance
func NewEventManager() *EventManager {
	return &EventManager{
		listeners:    make(map[EventType][]EventListener),
		eventHistory: make([]*Event, 0),
	}
}

// Subscribe allows an EventListener to subscribe to specific event types
func (manager *EventManager) Subscribe(eventType EventType, listener EventListener) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	manager.listeners[eventType] = append(manager.listeners[eventType], listener)
}

// Unsubscribe allows an EventListener to unsubscribe from specific event types
func (manager *EventManager) Unsubscribe(eventType EventType, listener EventListener) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	listeners, exists := manager.listeners[eventType]
	if !exists {
		return errors.New("event type not found")
	}

	for i, l := range listeners {
		if l == listener {
			manager.listeners[eventType] = append(listeners[:i], listeners[i+1:]...)
			return nil
		}
	}

	return errors.New("listener not found")
}

// PublishEvent publishes a new event to all subscribed listeners
func (manager *EventManager) PublishEvent(event *Event) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	event.Timestamp = time.Now()
	manager.eventHistory = append(manager.eventHistory, event)

	listeners, exists := manager.listeners[event.Type]
	if exists {
		for _, listener := range listeners {
			listener.OnEvent(event)
		}
	}
}

// GetEventHistory returns the history of events
func (manager *EventManager) GetEventHistory() []*Event {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return manager.eventHistory
}

// GenerateEventID generates a unique identifier for an event
func GenerateEventID(eventType EventType) string {
	return fmt.Sprintf("%s-%d", eventType, time.Now().UnixNano())
}
