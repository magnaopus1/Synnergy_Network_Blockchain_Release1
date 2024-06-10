package syn2800

import (
	"fmt"
	"log"
	"time"
)

// InsuranceTokenEvent defines the structure for events related to insurance tokens.
type InsuranceTokenEvent struct {
	Type       string          // Type of event (e.g., "Issued", "Activated", "Deactivated", "Transferred")
	Token      LifeInsuranceToken // The token associated with the event
	Timestamp  time.Time       // Time at which the event occurred
}

// EventManager manages the dispatch and handling of events within the insurance token ledger.
type EventManager struct {
	Subscribers []func(InsuranceTokenEvent) // Slice of subscribers who listen to token events
}

// NewEventManager creates a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{
		Subscribers: make([]func(InsuranceTokenEvent), 0),
	}
}

// PublishEvent publishes an event to all registered subscribers.
func (em *EventManager) PublishEvent(event InsuranceTokenEvent) {
	for _, subscriber := range em.Subscribers {
		go subscriber(event) // Launch each subscriber as a goroutine for non-blocking event handling
	}
	log.Printf("Event published: %s for TokenID %s at %s", event.Type, event.Token.TokenID, event.Timestamp)
}

// Subscribe allows a new subscriber to register for events.
func (em *EventManager) Subscribe(subscriber func(InsuranceTokenEvent)) {
	em.Subscribers = append(em.Subscribers, subscriber)
}

// SetupDefaultSubscribers sets up default event handling such as logging and notification.
func (em *EventManager) SetupDefaultSubscribers() {
	em.Subscribe(func(event InsuranceTokenEvent) {
		// Log event to a file or external logging system
		log.Printf("Handling event: %v", event)
	})

	em.Subscribe(func(event InsuranceTokenEvent) {
		// Send notifications to relevant parties, e.g., the token owner or issuer
		fmt.Printf("Notification: Event %s occurred for Token %s with ID %s\n", event.Type, event.Token.TokenID, event.Timestamp)
	})
}

// Example usage within the ledger operations
var globalEventManager = NewEventManager()

func init() {
	globalEventManager.SetupDefaultSubscribers() // Set up default subscribers when the package is initialized
}

// After performing actions like issuing, activating, or deactivating tokens,
// the respective functions will call globalEventManager.PublishEvent with the relevant event data.
