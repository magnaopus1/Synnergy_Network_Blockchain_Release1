package assets

import (
    "encoding/json"
    "errors"
    "time"
)

// EventMetadata represents the metadata for an event
type EventMetadata struct {
    EventID      string    `json:"event_id"`
    Name         string    `json:"name"`
    Description  string    `json:"description"`
    Location     string    `json:"location"`
    StartTime    time.Time `json:"start_time"`
    EndTime      time.Time `json:"end_time"`
    TicketSupply int       `json:"ticket_supply"`
}

// EventManager manages event metadata for SYN1700 tokens
type EventManager struct {
    events map[string]EventMetadata // EventID -> EventMetadata
}

// NewEventManager creates a new EventManager
func NewEventManager() *EventManager {
    return &EventManager{
        events: make(map[string]EventMetadata),
    }
}

// AddEvent adds a new event
func (em *EventManager) AddEvent(event EventMetadata) error {
    if event.EventID == "" || event.Name == "" {
        return errors.New("event ID and name are required")
    }

    em.events[event.EventID] = event
    return nil
}

// UpdateEvent updates an existing event's metadata
func (em *EventManager) UpdateEvent(event EventMetadata) error {
    if event.EventID == "" {
        return errors.New("event ID is required")
    }

    _, exists := em.events[event.EventID]
    if !exists {
        return errors.New("event not found")
    }

    em.events[event.EventID] = event
    return nil
}

// GetEvent retrieves metadata for a specific event
func (em *EventManager) GetEvent(eventID string) (EventMetadata, error) {
    event, exists := em.events[eventID]
    if !exists {
        return EventMetadata{}, errors.New("event not found")
    }
    return event, nil
}

// GetAllEvents retrieves metadata for all events
func (em *EventManager) GetAllEvents() map[string]EventMetadata {
    return em.events
}

// DeleteEvent deletes an event's metadata
func (em *EventManager) DeleteEvent(eventID string) error {
    _, exists := em.events[eventID]
    if !exists {
        return errors.New("event not found")
    }

    delete(em.events, eventID)
    return nil
}

// SerializeEvent serializes event metadata to JSON
func (em *EventManager) SerializeEvent(eventID string) (string, error) {
    event, err := em.GetEvent(eventID)
    if err != nil {
        return "", err
    }

    data, err := json.Marshal(event)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeEvent deserializes event metadata from JSON
func (em *EventManager) DeserializeEvent(data string) (EventMetadata, error) {
    var event EventMetadata
    err := json.Unmarshal([]byte(data), &event)
    if err != nil {
        return EventMetadata{}, err
    }

    return event, nil
}

// SerializeAllEvents serializes all event metadata to JSON
func (em *EventManager) SerializeAllEvents() (string, error) {
    data, err := json.Marshal(em.events)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeAllEvents deserializes all event metadata from JSON
func (em *EventManager) DeserializeAllEvents(data string) error {
    var events map[string]EventMetadata
    err := json.Unmarshal([]byte(data), &events)
    if err != nil {
        return err
    }

    em.events = events
    return nil
}
