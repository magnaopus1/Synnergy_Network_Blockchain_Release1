package syn2700

import (
	"encoding/json"
	"log"
	"time"
)

// Event types for the pension token lifecycle
const (
	TokenIssued      = "TokenIssued"
	TokenRedeemed    = "TokenRedeemed"
	TokenTransferred = "TokenTransferred"
)

// Event defines the structure for an event message in the pension token system.
type Event struct {
	Type      string    `json:"type"`      // Type of the event
	Details   string    `json:"details"`   // JSON string containing event details
	Timestamp time.Time `json:"timestamp"` // Timestamp of the event
}

// EventService handles the creation and dispatching of events.
type EventService struct {
	listeners []chan Event
}

// NewEventService creates a new event service.
func NewEventService() *EventService {
	return &EventService{}
}

// RegisterListener adds a new channel to receive events.
func (e *EventService) RegisterListener(listener chan Event) {
	e.listeners = append(e.listeners, listener)
}

// UnregisterListener removes a listener from the service.
func (e *EventService) UnregisterListener(listener chan Event) {
	for i, l := range e.listeners {
		if l == listener {
			e.listeners = append(e.listeners[:i], e.listeners[i+1:]...)
			break
		}
	}
}

// PublishEvent creates and distributes an event to all registered listeners.
func (e *EventService) PublishEvent(eventType string, details interface{}) {
	detailBytes, err := json.Marshal(details)
	if err != nil {
		log.Printf("Error marshalling event details: %v", err)
		return
	}

	event := Event{
		Type:      eventType,
		Details:   string(detailBytes),
		Timestamp: time.Now(),
	}

	for _, listener := range e.listeners {
		go func(l chan Event) {
			l <- event
		}(listener)
	}
}

// Example usage of the EventService in the ledger methods
func (pl *PensionLedger) IssueToken(token PensionToken) error {
	if _, exists := pl.Tokens[token.TokenID]; exists {
		return fmt.Errorf("token with ID %s already exists", token.TokenID)
	}

	token.IssuedDate = time.Now()
	token.IsActive = true
	pl.Tokens[token.TokenID] = token

	// Publish event after issuing a token
	globalEventService.PublishEvent(TokenIssued, token)
	return nil
}

// Initialize a global event service
var globalEventService = NewEventService()

