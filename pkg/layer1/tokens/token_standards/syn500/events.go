package syn500

import (
	"log"
	"fmt"
)

// EventType defines a type for event names in the SYN500 token system.
type EventType string

const (
	TokenCreated EventType = "TokenCreated"
	TokenTransferred EventType = "TokenTransferred"
	TokenBurned EventType = "TokenBurned"
	TokenMinted EventType = "TokenMinted"
)

// TokenEvent represents an event in the utility token lifecycle.
type TokenEvent struct {
	Type EventType `json:"type"`
	Details string `json:"details"`
}

// EventManager manages the dispatch and logging of token-related events.
type EventManager struct {
	Subscribers map[EventType][]func(*TokenEvent)
}

// NewEventManager creates a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{
		Subscribers: make(map[EventType][]func(*TokenEvent)),
	}
}

// Subscribe adds a new subscriber to a specific event type.
func (e *EventManager) Subscribe(eventType EventType, callback func(*TokenEvent)) {
	e.Subscribers[eventType] = append(e.Subscribers[eventType], callback)
	log.Printf("New subscriber added for event type: %s", eventType)
}

// Publish triggers an event and notifies all subscribers.
func (e *EventManager) Publish(event *TokenEvent) {
	if subscribers, found := e.Subscribers[event.Type]; found {
		for _, callback := range subscribers {
			go callback(event)  // Handle each subscriber in a separate goroutine for asynchronous processing
			log.Printf("Event published: %s with details: %s", event.Type, event.Details)
		}
	} else {
		log.Printf("No subscribers found for event type: %s", event.Type)
	}
}

// LogEvent creates and logs a basic event.
func (e *EventManager) LogEvent(eventType EventType, details string) {
	event := &TokenEvent{
		Type: eventType,
		Details: details,
	}
	e.Publish(event)
	log.Printf("Event logged: %s", details)
}

// Example usage within the token system
func (e *EventManager) onTokenCreated(tokenID string) {
	details := fmt.Sprintf("Token with ID %s created", tokenID)
	e.LogEvent(TokenCreated, details)
}

func (e *EventManager) onTokenTransferred(from, to string, amount float64) {
	details := fmt.Sprintf("Transferred %f SYNN from %s to %s", amount, from, to)
	e.LogEvent(TokenTransferred, details)
}

func (e *EventManager) onTokenBurned(tokenID string, amount float64) {
	details := fmt.Sprintf("Burned %f SYNN of token %s", amount, tokenID)
	e.LogEvent(TokenBurned, details)
}

func (e *EventManager) onTokenMinted(tokenID string, amount float64) {
	details := fmt.Sprintf("Minted %f SYNN of token %s", amount, tokenID)
	e.LogEvent(TokenMinted, details)
}
