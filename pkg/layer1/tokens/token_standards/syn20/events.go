package syn20

import (
	"fmt"
	"log"
	"sync"
)

// EventType defines the type of events that can be emitted by the SYN20 token standard.
type EventType string

const (
	TransferEvent EventType = "Transfer"
	ApprovalEvent EventType = "Approval"
)

// Event defines the structure of an event message in the SYN20 token system.
type Event struct {
	Type    EventType
	Payload interface{}
}

// TransferPayload defines data for transfer events.
type TransferPayload struct {
	From   string
	To     string
	Amount float64
}

// ApprovalPayload defines data for approval events.
type ApprovalPayload struct {
	Owner   string
	Spender string
	Amount  float64
}

// EventHandler is a function that handles events.
type EventHandler func(Event)

// EventManager manages events and provides a subscription mechanism.
type EventManager struct {
	subscribers []EventHandler
	mutex       sync.Mutex
}

// NewEventManager creates a new EventManager.
func NewEventManager() *EventManager {
	return &EventManager{}
}

// Subscribe adds a new subscriber to the event notifications.
func (e *EventManager) Subscribe(handler EventHandler) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.subscribers = append(e.subscribers, handler)
	log.Println("New subscriber added for SYN20 token events")
}

// Emit emits an event to all subscribers.
func (e *EventManager) Emit(event Event) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	for _, handler := range e.subscribers {
		go func(handler EventHandler) {
			handler(event)
			log.Printf("Event emitted: %s", fmt.Sprintf("%v", event))
		}(handler)
	}
}

// EmitTransferEvent emits a transfer event.
func (e *EventManager) EmitTransferEvent(from, to string, amount float64) {
	e.Emit(Event{
		Type: TransferEvent,
		Payload: TransferPayload{
			From:   from,
			To:     to,
			Amount: amount,
		},
	})
}

// EmitApprovalEvent emits an approval event.
func (e *EventManager) EmitApprovalEvent(owner, spender string, amount float64) {
	e.Emit(Event{
		Type: ApprovalEvent,
		Payload: ApprovalPayload{
			Owner:   owner,
			Spender: spender,
			Amount:  amount,
		},
	})
}
