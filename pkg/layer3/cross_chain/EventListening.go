package cross_chain

import (
    "fmt"
    "sync"
)

// Event represents a generic event that might affect cross-chain operations.
type Event struct {
    Type    string      // Type of event, e.g., "TransactionCompleted", "ContractUpdated"
    Details interface{} // Detailed data about the event
    Chain   string      // Which blockchain the event is related to
}

// EventHandler defines the functionality to handle different types of events.
type EventHandler interface {
    Handle(event Event) error
}

// EventListener listens to events from different blockchains and dispatches them to the appropriate handlers.
type EventListener struct {
    mu        sync.Mutex
    handlers  map[string][]EventHandler // Handlers registered for each type of event
    eventQueue chan Event               // Queue for incoming events to handle
}

// NewEventListener creates a new event listener with initialized properties.
func NewEventListener() *EventListener {
    return &EventListener{
        handlers:  make(map[string][]EventHandler),
        eventQueue: make(chan Event, 100), // Buffer up to 100 events
    }
}

// RegisterHandler registers a new handler for a specific type of event.
func (el *EventListener) RegisterHandler(eventType string, handler EventHandler) {
    el.mu.Lock()
    defer el.mu.Unlock()
    el.handlers[eventType] = append(el.handlers[eventType], handler)
}

// UnregisterAllHandlers removes all handlers for a specific event type.
func (el *EventListener) UnregisterAllHandlers(eventType string) {
    el.mu.Lock()
    defer el.mu.Unlock()
    delete(el.handlers, eventType)
}

// StartListening starts the listener to process events.
func (el *EventListener) StartListening() {
    go func() {
        for event := range el.eventQueue {
            el.handleEvent(event)
        }
    }()
}

// StopListening stops the listener from processing events.
func (el *EventListener) StopListening() {
    close(el.eventQueue)
}

// handleEvent dispatches an event to all registered handlers for its type.
func (el *EventListener) handleEvent(event Event) {
    el.mu.Lock()
    handlers, exists := el.handlers[event.Type]
    el.mu.Unlock()
    if !exists {
        fmt.Printf("No handlers registered for event type: %s\n", event.Type)
        return
    }

    for _, handler := range handlers {
        if err := handler.Handle(event); err != nil {
            fmt.Printf("Error handling event: %s\n", err)
        }
    }
}

// PushEvent adds an event to the queue for processing.
func (el *EventListener) PushEvent(event Event) {
    el.eventQueue <- event
}
