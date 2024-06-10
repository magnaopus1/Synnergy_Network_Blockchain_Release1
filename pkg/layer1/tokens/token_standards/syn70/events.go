package syn70

import (
	"encoding/json"
	"log"
)

// Event types for SYN70 token operations
const (
	TokenCreated   = "TokenCreated"
	TokenUpdated   = "TokenUpdated"
	TokenDeleted   = "TokenDeleted"
	TokenTransferred = "TokenTransferred"
)

// TokenEvent defines the structure for token-related events.
type TokenEvent struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// EventBus manages the distribution of events in the SYN70 token environment.
type EventBus struct {
	subscribers map[string][]chan TokenEvent
}

// NewEventBus creates a new EventBus instance.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string][]chan TokenEvent),
	}
}

// Subscribe adds a new subscriber to a specific event type.
func (eb *EventBus) Subscribe(eventType string, channel chan TokenEvent) {
	eb.subscribers[eventType] = append(eb.subscribers[eventType], channel)
	log.Printf("New subscriber added for event type: %s", eventType)
}

// Publish broadcasts an event to all subscribers of the event type.
func (eb *EventBus) Publish(event TokenEvent) {
	subscribers, found := eb.subscribers[event.Type]
	if !found {
		log.Printf("No subscribers found for event type: %s", event.Type)
		return
	}

	log.Printf("Publishing event: %s", event.Type)
	for _, subscriber := range subscribers {
		// Send the event in a non-blocking way
		go func(ch chan TokenEvent) {
			ch <- event
			log.Printf("Event %s sent to channel", event.Type)
		}(subscriber)
	}
}

// createTokenEvent creates a TokenEvent and serializes it for logging or network transmission.
func createTokenEvent(eventType string, token Token) TokenEvent {
	event := TokenEvent{
		Type:    eventType,
		Payload: token,
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to serialize event: %v", err)
	} else {
		log.Printf("Event serialized: %s", string(data))
	}

	return event
}

// handleTokenCreation should be called whenever a new token is created.
func (eb *EventBus) handleTokenCreation(token Token) {
	event := createTokenEvent(TokenCreated, token)
	eb.Publish(event)
}

// handleTokenUpdate should be called whenever a token is updated.
func (eb *EventBus) handleTokenUpdate(token Token) {
	event := createTokenEvent(TokenUpdated, token)
	eb.Publish(event)
}

// handleTokenDeletion should be called whenever a token is deleted.
func (eb *EventBus) handleTokenDeletion(tokenID string) {
	event := createTokenEvent(TokenDeleted, struct{ ID string }{ID: tokenID})
	eb.Publish(event)
}

// handleTokenTransfer should be called to notify about a token transfer.
func (eb *EventBus) handleTokenTransfer(transaction TokenTransaction) {
	event := createTokenEvent(TokenTransferred, transaction)
	eb.Publish(event)
}
