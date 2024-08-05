package events

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
)

// EventType defines the type of events that can be dispatched.
type EventType string

const (
	// EventSmartContractDeployed is dispatched when a smart contract is deployed.
	EventSmartContractDeployed EventType = "SmartContractDeployed"
	// EventSmartContractExecuted is dispatched when a smart contract is executed.
	EventSmartContractExecuted EventType = "SmartContractExecuted"
	// EventSmartContractUpdated is dispatched when a smart contract is updated.
	EventSmartContractUpdated EventType = "SmartContractUpdated"
	// EventSmartContractTerminated is dispatched when a smart contract is terminated.
	EventSmartContractTerminated EventType = "SmartContractTerminated"
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
	security  *security.SecurityManager
}

// NewEventDispatcher creates a new EventDispatcher.
func NewEventDispatcher(security *security.SecurityManager) *EventDispatcher {
	return &EventDispatcher{
		listeners: make(map[EventType][]EventListener),
		security:  security,
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
func (ed *EventDispatcher) DispatchEvent(eventType EventType, payload map[string]interface{}) error {
	ed.mutex.RLock()
	defer ed.mutex.RUnlock()

	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	// Encrypt event payload for security before dispatching
	encryptedPayload, err := ed.security.EncryptPayload(event.Payload)
	if err != nil {
		return fmt.Errorf("failed to encrypt event payload: %v", err)
	}
	event.Payload = encryptedPayload

	if listeners, exists := ed.listeners[eventType]; exists {
		for _, listener := range listeners {
			listener.HandleEvent(event)
		}
	}
	return nil
}

// ExampleListener is an example implementation of an EventListener.
type ExampleListener struct{}

// HandleEvent handles an event.
func (el *ExampleListener) HandleEvent(event Event) {
	// Decrypt the event payload for handling
	decryptedPayload, err := ed.security.DecryptPayload(event.Payload)
	if err != nil {
		fmt.Printf("failed to decrypt event payload: %v\n", err)
		return
	}
	event.Payload = decryptedPayload

	fmt.Printf("Received event: %v at %v with payload: %v\n", event.Type, event.Timestamp, event.Payload)
}
