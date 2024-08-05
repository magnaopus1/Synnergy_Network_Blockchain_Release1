package events

import (
	"errors"
	"sync"
)

// Event represents a blockchain event.
type Event struct {
	ID        string
	Type      string
	Timestamp int64
	Data      map[string]interface{}
}

// EventListener defines the interface for an event listener.
type EventListener interface {
	HandleEvent(event Event) error
}

// EventDispatcher is responsible for managing and dispatching events.
type EventDispatcher struct {
	listeners map[string][]EventListener
	mu        sync.RWMutex
}

// NewEventDispatcher creates a new EventDispatcher instance.
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		listeners: make(map[string][]EventListener),
	}
}

// RegisterListener registers an event listener for a specific event type.
func (ed *EventDispatcher) RegisterListener(eventType string, listener EventListener) {
	ed.mu.Lock()
	defer ed.mu.Unlock()

	if _, ok := ed.listeners[eventType]; !ok {
		ed.listeners[eventType] = []EventListener{}
	}
	ed.listeners[eventType] = append(ed.listeners[eventType], listener)
}

// UnregisterListener unregisters an event listener for a specific event type.
func (ed *EventDispatcher) UnregisterListener(eventType string, listener EventListener) error {
	ed.mu.Lock()
	defer ed.mu.Unlock()

	if _, ok := ed.listeners[eventType]; !ok {
		return errors.New("no listeners registered for this event type")
	}

	for i, l := range ed.listeners[eventType] {
		if l == listener {
			ed.listeners[eventType] = append(ed.listeners[eventType][:i], ed.listeners[eventType][i+1:]...)
			return nil
		}
	}
	return errors.New("listener not found")
}

// DispatchEvent dispatches an event to all registered listeners.
func (ed *EventDispatcher) DispatchEvent(event Event) {
	ed.mu.RLock()
	defer ed.mu.RUnlock()

	if listeners, ok := ed.listeners[event.Type]; ok {
		for _, listener := range listeners {
			go listener.HandleEvent(event)
		}
	}
}

// Example implementations of event listeners for SYN130

// OwnershipChangeListener listens for ownership change events.
type OwnershipChangeListener struct{}

// HandleEvent handles ownership change events.
func (ocl *OwnershipChangeListener) HandleEvent(event Event) error {
	// Implement the business logic for handling ownership change events.
	// For example, updating the ownership records in the blockchain ledger.
	return nil
}

// AssetValuationChangeListener listens for asset valuation change events.
type AssetValuationChangeListener struct{}

// HandleEvent handles asset valuation change events.
func (avcl *AssetValuationChangeListener) HandleEvent(event Event) error {
	// Implement the business logic for handling asset valuation change events.
	// For example, updating the valuation records and notifying stakeholders.
	return nil
}

// LeaseExpirationListener listens for lease expiration events.
type LeaseExpirationListener struct{}

// HandleEvent handles lease expiration events.
func (lel *LeaseExpirationListener) HandleEvent(event Event) error {
	// Implement the business logic for handling lease expiration events.
	// For example, sending notifications to lessors and lessees and updating lease status.
	return nil
}

// Example usage of the event dispatcher in the SYN130 context
func main() {
	dispatcher := NewEventDispatcher()

	ownershipChangeListener := &OwnershipChangeListener{}
	assetValuationChangeListener := &AssetValuationChangeListener{}
	leaseExpirationListener := &LeaseExpirationListener{}

	dispatcher.RegisterListener("ownership_change", ownershipChangeListener)
	dispatcher.RegisterListener("valuation_change", assetValuationChangeListener)
	dispatcher.RegisterListener("lease_expiration", leaseExpirationListener)

	// Simulate dispatching an event
	event := Event{
		ID:        "evt1",
		Type:      "ownership_change",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"asset_id":   "asset123",
			"new_owner":  "owner456",
			"prev_owner": "owner789",
		},
	}
	dispatcher.DispatchEvent(event)
}
