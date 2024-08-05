package events

import (
	"time"
	"fmt"
	"sync"
)

// EventType defines the type of events that can be emitted or listened for.
type EventType string

const (
	// EventAssetValuationUpdated is emitted when the valuation of an asset is updated.
	EventAssetValuationUpdated EventType = "AssetValuationUpdated"
	// EventOwnershipTransferred is emitted when the ownership of an asset is transferred.
	EventOwnershipTransferred EventType = "OwnershipTransferred"
	// EventSaleTransaction is emitted when a sale transaction is completed.
	EventSaleTransaction EventType = "SaleTransaction"
	// EventRentalAgreementCreated is emitted when a rental agreement is created.
	EventRentalAgreementCreated EventType = "RentalAgreementCreated"
	// EventLicensingAgreementUpdated is emitted when a licensing agreement is updated.
	EventLicensingAgreementUpdated EventType = "LicensingAgreementUpdated"
	// EventSmartContractDeployed is emitted when a smart contract is deployed.
	EventSmartContractDeployed EventType = "SmartContractDeployed"
)

// Event defines the structure of an event in the system.
type Event struct {
	Type      EventType
	Timestamp time.Time
	Payload   map[string]interface{}
}

// EventListener defines the interface for listening to events.
type EventListener interface {
	HandleEvent(event Event)
}

// EventDispatcher is responsible for dispatching events to listeners.
type EventDispatcher struct {
	listeners map[EventType][]EventListener
	mutex     sync.RWMutex
}

// NewEventDispatcher creates a new EventDispatcher.
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		listeners: make(map[EventType][]EventListener),
	}
}

// RegisterListener registers a listener for a specific event type.
func (ed *EventDispatcher) RegisterListener(eventType EventType, listener EventListener) {
	ed.mutex.Lock()
	defer ed.mutex.Unlock()

	if _, exists := ed.listeners[eventType]; !exists {
		ed.listeners[eventType] = []EventListener{}
	}
	ed.listeners[eventType] = append(ed.listeners[eventType], listener)
}

// UnregisterListener unregisters a listener for a specific event type.
func (ed *EventDispatcher) UnregisterListener(eventType EventType, listener EventListener) {
	ed.mutex.Lock()
	defer ed.mutex.Unlock()

	if listeners, exists := ed.listeners[eventType]; exists {
		for i, l := range listeners {
			if l == listener {
				ed.listeners[eventType] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
	}
}

// DispatchEvent dispatches an event to all registered listeners.
func (ed *EventDispatcher) DispatchEvent(eventType EventType, payload map[string]interface{}) {
	ed.mutex.RLock()
	defer ed.mutex.RUnlock()

	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	if listeners, exists := ed.listeners[eventType]; exists {
		for _, listener := range listeners {
			go listener.HandleEvent(event)
		}
	}
}

// ConcreteEventListener is an example implementation of an EventListener.
type ConcreteEventListener struct {
	ID string
}

// NewConcreteEventListener creates a new instance of ConcreteEventListener.
func NewConcreteEventListener(id string) *ConcreteEventListener {
	return &ConcreteEventListener{
		ID: id,
	}
}

// HandleEvent handles an incoming event.
func (listener *ConcreteEventListener) HandleEvent(event Event) {
	// Implement the business logic for handling the event here.
	fmt.Printf("Listener %s received event: %v at %v with payload: %v\n", listener.ID, event.Type, event.Timestamp, event.Payload)
}

