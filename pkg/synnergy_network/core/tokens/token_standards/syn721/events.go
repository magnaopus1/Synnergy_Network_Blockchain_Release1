package syn721

import (
	"fmt"
	"sync"
	"time"
)

// EventType represents the type of an event in the SYN721 system
type EventType string

const (
	TokenMinted    EventType = "TokenMinted"
	TokenTransferred EventType = "TokenTransferred"
	TokenBurned     EventType = "TokenBurned"
	MetadataUpdated EventType = "MetadataUpdated"
	ValuationUpdated EventType = "ValuationUpdated"
	ApprovalGranted EventType = "ApprovalGranted"
	ApprovalRevoked EventType = "ApprovalRevoked"
	EscrowCreated   EventType = "EscrowCreated"
	EscrowReleased  EventType = "EscrowReleased"
)

// Event represents an event in the SYN721 system
type Event struct {
	ID        string
	Type      EventType
	Timestamp time.Time
	Data      map[string]interface{}
}

// EventManager manages events in the SYN721 system
type EventManager struct {
	events       map[string][]Event
	mutex        sync.Mutex
	subscribers  map[EventType][]chan Event
}

// NewEventManager initializes a new EventManager
func NewEventManager() *EventManager {
	return &EventManager{
		events:      make(map[string][]Event),
		subscribers: make(map[EventType][]chan Event),
	}
}

// LogEvent logs a new event in the system
func (em *EventManager) LogEvent(event Event) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	em.events[event.ID] = append(em.events[event.ID], event)
	em.notifySubscribers(event)
}

// GetEvents retrieves events by ID
func (em *EventManager) GetEvents(id string) ([]Event, error) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	events, exists := em.events[id]
	if !exists {
		return nil, fmt.Errorf("no events found for ID %s", id)
	}

	return events, nil
}

// Subscribe allows a subscriber to listen for specific event types
func (em *EventManager) Subscribe(eventType EventType, ch chan Event) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	em.subscribers[eventType] = append(em.subscribers[eventType], ch)
}

// notifySubscribers notifies all subscribers of a specific event type
func (em *EventManager) notifySubscribers(event Event) {
	for _, ch := range em.subscribers[event.Type] {
		ch <- event
	}
}

// MintTokenEvent creates an event for minting a token
func MintTokenEvent(tokenID, owner string, metadata map[string]interface{}) Event {
	return Event{
		ID:        tokenID,
		Type:      TokenMinted,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"owner":    owner,
			"metadata": metadata,
		},
	}
}

// TransferTokenEvent creates an event for transferring a token
func TransferTokenEvent(tokenID, from, to string) Event {
	return Event{
		ID:        tokenID,
		Type:      TokenTransferred,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"from": from,
			"to":   to,
		},
	}
}

// BurnTokenEvent creates an event for burning a token
func BurnTokenEvent(tokenID string) Event {
	return Event{
		ID:        tokenID,
		Type:      TokenBurned,
		Timestamp: time.Now(),
	}
}

// MetadataUpdateEvent creates an event for updating token metadata
func MetadataUpdateEvent(tokenID string, newMetadata map[string]interface{}) Event {
	return Event{
		ID:        tokenID,
		Type:      MetadataUpdated,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"newMetadata": newMetadata,
		},
	}
}

// ValuationUpdateEvent creates an event for updating token valuation
func ValuationUpdateEvent(tokenID string, newValuation map[string]interface{}) Event {
	return Event{
		ID:        tokenID,
		Type:      ValuationUpdated,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"newValuation": newValuation,
		},
	}
}

// ApprovalGrantedEvent creates an event for granting approval
func ApprovalGrantedEvent(tokenID, approvedAddress string) Event {
	return Event{
		ID:        tokenID,
		Type:      ApprovalGranted,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"approvedAddress": approvedAddress,
		},
	}
}

// ApprovalRevokedEvent creates an event for revoking approval
func ApprovalRevokedEvent(tokenID, revokedAddress string) Event {
	return Event{
		ID:        tokenID,
		Type:      ApprovalRevoked,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"revokedAddress": revokedAddress,
		},
	}
}

// EscrowCreatedEvent creates an event for creating an escrow
func EscrowCreatedEvent(tokenID, escrowAddress string, amount float64) Event {
	return Event{
		ID:        tokenID,
		Type:      EscrowCreated,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"escrowAddress": escrowAddress,
			"amount":        amount,
		},
	}
}

// EscrowReleasedEvent creates an event for releasing an escrow
func EscrowReleasedEvent(tokenID, escrowAddress string, amount float64) Event {
	return Event{
		ID:        tokenID,
		Type:      EscrowReleased,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"escrowAddress": escrowAddress,
			"amount":        amount,
		},
	}
}
