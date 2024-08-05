package syn845

import (
    "sync"
    "time"
)

// Event types for SYN845 token standard
type EventType string

const (
    IssuanceEvent       EventType = "Issuance"
    RepaymentEvent      EventType = "Repayment"
    RefinancingEvent    EventType = "Refinancing"
    OwnershipTransferEvent EventType = "OwnershipTransfer"
    PenaltyEvent        EventType = "Penalty"
    DefaultEvent        EventType = "Default"
    InterestAdjustmentEvent EventType = "InterestAdjustment"
)

// Event represents a blockchain event for SYN845 tokens
type Event struct {
    ID          string
    Type        EventType
    Timestamp   time.Time
    Data        map[string]interface{}
}

// EventLog handles logging of events
type EventLog struct {
    events []Event
    mu     sync.RWMutex
}

// NewEventLog creates a new event log
func NewEventLog() *EventLog {
    return &EventLog{
        events: make([]Event, 0),
    }
}

// LogEvent logs an event to the event log
func (el *EventLog) LogEvent(eventType EventType, data map[string]interface{}) {
    el.mu.Lock()
    defer el.mu.Unlock()

    event := Event{
        ID:        generateUniqueID(), // Function to generate a unique ID for the event
        Type:      eventType,
        Timestamp: time.Now(),
        Data:      data,
    }

    el.events = append(el.events, event)
}

// GetEvents returns all logged events
func (el *EventLog) GetEvents() []Event {
    el.mu.RLock()
    defer el.mu.RUnlock()

    return el.events
}

// GetEventsByType returns all events of a specific type
func (el *EventLog) GetEventsByType(eventType EventType) []Event {
    el.mu.RLock()
    defer el.mu.RUnlock()

    var filteredEvents []Event
    for _, event := range el.events {
        if event.Type == eventType {
            filteredEvents = append(filteredEvents, event)
        }
    }
    return filteredEvents
}

// GetEventsByDateRange returns all events within a specific date range
func (el *EventLog) GetEventsByDateRange(startDate, endDate time.Time) []Event {
    el.mu.RLock()
    defer el.mu.RUnlock()

    var filteredEvents []Event
    for _, event := range el.events {
        if event.Timestamp.After(startDate) && event.Timestamp.Before(endDate) {
            filteredEvents = append(filteredEvents, event)
        }
    }
    return filteredEvents
}

// generateUniqueID generates a unique ID for an event
func generateUniqueID() string {
    // Implement a function to generate a unique ID, for example using UUID
    return "unique-id"
}
