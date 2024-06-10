package syn600

import (
	"log"
)

// TokenEvent represents the data transmitted when a token-related event occurs.
type TokenEvent struct {
	Type    string  // Type of event, e.g., "Created", "Transferred", "Deleted"
	TokenID string  // ID of the token involved in the event
	From    string  // Sender's address (empty for creation)
	To      string  // Recipient's address (empty for deletion)
	Amount  float64 // Amount transferred
}

// EventManager manages token events.
type EventManager struct {
	subscribers []chan TokenEvent
}

// NewEventManager initializes a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{
		subscribers: make([]chan TokenEvent, 0),
	}
}

// Subscribe adds a new subscriber to token events.
func (em *EventManager) Subscribe(sub chan TokenEvent) {
	em.subscribers = append(em.subscribers, sub)
	log.Println("New subscriber added for token events")
}

// Unsubscribe removes a subscriber from token events.
func (em *EventManager) Unsubscribe(sub chan TokenEvent) {
	for i, subscriber := range em.subscribers {
		if subscriber == sub {
			em.subscribers = append(em.subscribers[:i], em.subscribers[i+1:]...)
			close(sub)
			log.Println("Subscriber removed from token events")
			return
		}
	}
}

// BroadcastEvent sends the event to all subscribers.
func (em *EventManager) BroadcastEvent(event TokenEvent) {
	log.Printf("Broadcasting event: Type=%s, TokenID=%s, From=%s, To=%s, Amount=%f\n",
		event.Type, event.TokenID, event.From, event.To, event.Amount)
	for _, sub := range em.subscribers {
		sub <- event
	}
}

// EmitCreationEvent notifies subscribers of a new token creation.
func (em *EventManager) EmitCreationEvent(tokenID string, to string, amount float64) {
	event := TokenEvent{
		Type:    "Created",
		TokenID: tokenID,
		To:      to,
		Amount:  amount,
	}
	em.BroadcastEvent(event)
}

// EmitTransferEvent notifies subscribers of a token transfer.
func (em *EventManager) EmitTransferEvent(tokenID, from, to string, amount float64) {
	event := TokenEvent{
		Type:    "Transferred",
		TokenID: tokenID,
		From:    from,
		To:      to,
		Amount:  amount,
	}
	em.BroadcastEvent(event)
}

// EmitDeletionEvent notifies subscribers of a token deletion.
func (em *EventManager) EmitDeletionEvent(tokenID string) {
	event := TokenEvent{
		Type:    "Deleted",
		TokenID: tokenID,
	}
	em.BroadcastEvent(event)
}
