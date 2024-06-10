package syn300

import (
	"log"
)

// Event defines the structure for blockchain events in the SYN300 token standard.
type Event struct {
	Type    string      `json:"type"`    // Type of the event e.g., "Transfer", "Vote", "ProposalCreated"
	Data    interface{} `json:"data"`    // Data containing event specifics
}

// EventManager manages the broadcasting and logging of governance-related events.
type EventManager struct {
	Subscribers []chan Event
}

// NewEventManager initializes a new event manager for SYN300 tokens.
func NewEventManager() *EventManager {
	return &EventManager{
		Subscribers: make([]chan Event, 0),
	}
}

// Subscribe adds a new subscriber to the event manager.
func (e *EventManager) Subscribe() chan Event {
	newChannel := make(chan Event, 10) // Buffered channel
	e.Subscribers = append(e.Subscribers, newChannel)
	log.Println("New subscriber added for SYN300 token events")
	return newChannel
}

// Unsubscribe removes a subscriber from the event manager.
func (e *EventManager) Unsubscribe(ch chan Event) {
	for i, subscriber := range e.Subscribers {
		if subscriber == ch {
			e.Subscribers = append(e.Subscribers[:i], e.Subscribers[i+1:]...)
			close(ch)
			log.Println("Subscriber removed for SYN300 token events")
			break
		}
	}
}

// BroadcastEvent sends out an event to all subscribers.
func (e *EventManager) BroadcastEvent(event Event) {
	for _, subscriber := range e.Subscribers {
		select {
		case subscriber <- event:
			// Event sent successfully to subscriber
		default:
			// Prevent blocking if subscriber is not ready to receive
			log.Printf("Dropped event for subscriber due to full channel: %v", event)
		}
	}
	log.Printf("Event broadcasted: Type=%s, Data=%v", event.Type, event.Data)
}

// LogEvent logs an event to standard logging systems or external monitoring services.
func (e *EventManager) LogEvent(event Event) {
	log.Printf("Event logged: Type=%s, Data=%v", event.Type, event.Data)
}

// Example usage of event creation and broadcasting.
func ExampleUsageOfEvents(manager *EventManager) {
	transferEvent := Event{
		Type: "Transfer",
		Data: map[string]string{
			"from":   "0x123",
			"to":     "0x456",
			"amount": "100 SYNN",
		},
	}
	manager.BroadcastEvent(transferEvent)
	manager.LogEvent(transferEvent)

	voteEvent := Event{
		Type: "Vote",
		Data: map[string]string{
			"voterID":    "0x789",
			"proposalID": "42",
			"vote":       "Yes",
		},
	}
	manager.BroadcastEvent(voteEvent)
	manager.LogEvent(voteEvent)
}
