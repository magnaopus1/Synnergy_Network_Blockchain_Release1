package syn131

import (
	"log"
	"sync"
)

// Event types for SYN131 token operations
const (
	TokenCreatedEventType   = "TokenCreated"
	TokenUpdatedEventType   = "TokenUpdated"
	TokenDeletedEventType   = "TokenDeleted"
	TokenTransferredEventType = "TokenTransferred"
)

// TokenEvent represents a token-related event.
type TokenEvent struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// EventListener is a function that handles an incoming token event.
type EventListener func(event TokenEvent)

// EventBroker manages subscriptions and broadcasting of token events.
type EventBroker struct {
	subscribers []EventListener
	mutex       sync.Mutex
}

// NewEventBroker creates a new EventBroker instance.
func NewEventBroker() *EventBroker {
	return &EventBroker{}
}

// Subscribe adds a new listener for token events.
func (eb *EventBroker) Subscribe(listener EventListener) {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()
	eb.subscribers = append(eb.subscribers, listener)
	log.Println("New subscriber added for token events.")
}

// Broadcast sends an event to all subscribed listeners.
func (eb *EventBroker) Broadcast(event TokenEvent) {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()
	log.Printf("Broadcasting event: %s", event.Type)
	for _, listener := range eb.subscribers {
		go listener(event)  // Handle each listener in a separate goroutine for non-blocking operation
	}
}

// EmitTokenCreated broadcasts a token creation event.
func EmitTokenCreated(token Token) {
	event := TokenEvent{
		Type:    TokenCreatedEventType,
		Payload: token,
	}
	GlobalEventBroker.Broadcast(event)
}

// EmitTokenUpdated broadcasts a token update event.
func EmitTokenUpdated(token Token) {
	event := TokenEvent{
		Type:    TokenUpdatedEventType,
		Payload: token,
	}
	GlobalEventBroker.Broadcast(event)
}

// EmitTokenDeleted broadcasts a token deletion event.
func EmitTokenDeleted(tokenID string) {
	event := TokenEvent{
		Type:    TokenDeletedEventType,
		Payload: tokenID,
	}
	GlobalEventBroker.Broadcast(event)
}

// EmitTokenTransferred broadcasts a token transfer event.
func EmitTokenTransferred(transfer TokenTransfer) {
	event := TokenEvent{
		Type:    TokenTransferredEventType,
		Payload: transfer,
	}
	GlobalEventBroker.Broadcast(event)
}

// GlobalEventBroker is the default event broker used across the system.
var GlobalEventBroker = NewEventBroker()

// TokenTransfer defines the payload for a token transfer event.
type TokenTransfer struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    float64 `json:"amount"`
	TokenID   string `json:"token_id"`
}
