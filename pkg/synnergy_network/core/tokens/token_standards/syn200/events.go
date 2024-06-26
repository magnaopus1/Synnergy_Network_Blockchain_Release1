package syn200

import (
	"log"
)

// CarbonCreditEvent defines the structure for carbon credit events
type CarbonCreditEvent struct {
	Type    string        // Type of event: "created", "updated", "deleted"
	Credit  CarbonCredit  // The carbon credit involved in the event
}

// EventManager manages carbon credit events
type EventManager struct {
	subscribers []chan CarbonCreditEvent
}

// NewEventManager initializes a new EventManager
func NewEventManager() *EventManager {
	return &EventManager{
		subscribers: make([]chan CarbonCreditEvent, 0),
	}
}

// Subscribe adds a new subscriber to the event notifications
func (em *EventManager) Subscribe(ch chan CarbonCreditEvent) {
	em.subscribers = append(em.subscribers, ch)
	log.Println("A new subscriber has been added to the carbon credit events.")
}

// Unsubscribe removes a subscriber from the event notifications
func (em *EventManager) Unsubscribe(ch chan CarbonCreditEvent) {
	for i, subscriber := range em.subscribers {
		if subscriber == ch {
			em.subscribers = append(em.subscribers[:i], em.subscribers[i+1:]...)
			close(ch)
			log.Println("A subscriber has been removed from the carbon credit events.")
			break
		}
	}
}

// Publish broadcasts an event to all subscribers
func (em *EventManager) Publish(event CarbonCreditEvent) {
	for _, ch := range em.subscribers {
		go func(ch chan CarbonCreditEvent) {
			ch <- event
			log.Printf("Event published for type '%s' involving credit ID '%s'.", event.Type, event.Credit.ID)
		}(ch)
	}
}

