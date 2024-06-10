package syn721

import (
	"log"
	"sync"
	"time"
)

// TokenEvent represents an event related to token activities.
type TokenEvent struct {
	Type      string    // Type of event (e.g., "Created", "Transferred", "MetadataUpdated")
	TokenID   string    // The ID of the token involved in the event
	Details   string    // Additional details about the event
	Timestamp time.Time // Timestamp of the event
}

// EventManager manages the dispatch and logging of token-related events.
type EventManager struct {
	subscribers []chan TokenEvent
	mutex       sync.RWMutex
}

// NewEventManager initializes a new event manager for handling token events.
func NewEventManager() *EventManager {
	return &EventManager{
		subscribers: make([]chan TokenEvent, 0),
	}
}

// Subscribe adds a new subscriber channel to receive events.
func (em *EventManager) Subscribe(ch chan TokenEvent) {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	em.subscribers = append(em.subscribers, ch)
	log.Println("New subscriber added for token events")
}

// Unsubscribe removes a subscriber channel.
func (em *EventManager) Unsubscribe(ch chan TokenEvent) {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	for i, subscriber := range em.subscribers {
		if subscriber == ch {
			em.subscribers = append(em.subscribers[:i], em.subscribers[i+1:]...)
			log.Println("Subscriber removed for token events")
			break
		}
	}
}

// Publish broadcasts an event to all subscribers.
func (em *EventManager) Publish(event TokenEvent) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	log.Printf("Publishing event: %s for token %s", event.Type, event.TokenID)
	for _, subscriber := range em.subscribers {
		go func(ch chan TokenEvent) {
			ch <- event
		}(subscriber)
	}
}

// CreateAndLogEvent creates an event and logs it internally.
func (em *EventManager) CreateAndLogEvent(eventType, tokenID, details string) {
	event := TokenEvent{
		Type:      eventType,
		TokenID:   tokenID,
		Details:   details,
		Timestamp: time.Now(),
	}
	em.Publish(event)
	log.Printf("Event logged: %s for token %s with details: %s", eventType, tokenID, details)
}

// Example of using the EventManager within the SYN721 token context
func ExampleEventManagerUsage(manager *EventManager) {
	// Creating a channel to receive events
	eventChannel := make(chan TokenEvent)
	manager.Subscribe(eventChannel)

	// Example of an async routine that handles incoming events
	go func() {
		for event := range eventChannel {
			log.Printf("Received event: %s for token %s at %s", event.Type, event.TokenID, event.Timestamp)
		}
	}()

	// Simulate event creation
	manager.CreateAndLogEvent("Created", "token1234", "Token created with initial attributes")
	manager.CreateAndLogEvent("Transferred", "token1234", "Token transferred to new owner")
}
