package events

import (
    "encoding/json"
    "errors"
    "time"
    "../assets"
)

// Event represents the core structure of an event in the SYN1700 token standard
type Event struct {
    Metadata assets.EventMetadata `json:"metadata"`
    Logs     []assets.EventLog    `json:"logs"`
    Tickets  []assets.TicketMetadata `json:"tickets"`
}

// EventManager manages the events for SYN1700 tokens
type EventManager struct {
    events map[string]Event // EventID -> Event
    eventLogsManager   *assets.EventLogManager
    ticketManager      *assets.TicketManager
    complianceManager  *assets.ComplianceManager
}

// NewEventManager creates a new EventManager
func NewEventManager() *EventManager {
    return &EventManager{
        events: make(map[string]Event),
        eventLogsManager: assets.NewEventLogManager(),
        ticketManager: assets.NewTicketManager(),
        complianceManager: assets.NewComplianceManager(),
    }
}

// CreateEvent creates a new event
func (em *EventManager) CreateEvent(metadata assets.EventMetadata) (string, error) {
    if metadata.EventID == "" || metadata.Name == "" {
        return "", errors.New("event ID and name are required")
    }
    
    event := Event{
        Metadata: metadata,
        Logs:     []assets.EventLog{},
        Tickets:  []assets.TicketMetadata{},
    }
    
    em.events[metadata.EventID] = event
    
    return metadata.EventID, nil
}

// UpdateEvent updates an existing event's metadata
func (em *EventManager) UpdateEvent(metadata assets.EventMetadata) error {
    if metadata.EventID == "" {
        return errors.New("event ID is required")
    }
    
    event, exists := em.events[metadata.EventID]
    if !exists {
        return errors.New("event not found")
    }
    
    event.Metadata = metadata
    em.events[metadata.EventID] = event
    
    return nil
}

// GetEvent retrieves an event by its ID
func (em *EventManager) GetEvent(eventID string) (Event, error) {
    event, exists := em.events[eventID]
    if !exists {
        return Event{}, errors.New("event not found")
    }
    
    return event, nil
}

// DeleteEvent deletes an event by its ID
func (em *EventManager) DeleteEvent(eventID string) error {
    _, exists := em.events[eventID]
    if !exists {
        return errors.New("event not found")
    }
    
    delete(em.events, eventID)
    return nil
}

// AddEventLog adds a log to a specific event
func (em *EventManager) AddEventLog(eventID, activity string) error {
    err := em.eventLogsManager.AddEventLog(eventID, activity)
    if err != nil {
        return err
    }
    
    event, err := em.GetEvent(eventID)
    if err != nil {
        return err
    }
    
    log := assets.EventLog{
        EventID:   eventID,
        Activity:  activity,
        Timestamp: time.Now(),
    }
    event.Logs = append(event.Logs, log)
    em.events[eventID] = event
    
    return nil
}

// GetEventLogs retrieves logs for a specific event
func (em *EventManager) GetEventLogs(eventID string) ([]assets.EventLog, error) {
    return em.eventLogsManager.GetEventLogs(eventID)
}

// AddTicket adds a new ticket to an event
func (em *EventManager) AddTicket(eventID string, ticket assets.TicketMetadata) error {
    if eventID == "" || ticket.TicketID == "" {
        return errors.New("event ID and ticket ID are required")
    }
    
    err := em.ticketManager.AddTicket(ticket)
    if err != nil {
        return err
    }
    
    event, err := em.GetEvent(eventID)
    if err != nil {
        return err
    }
    
    event.Tickets = append(event.Tickets, ticket)
    em.events[eventID] = event
    
    return nil
}

// GetTickets retrieves all tickets for a specific event
func (em *EventManager) GetTickets(eventID string) ([]assets.TicketMetadata, error) {
    event, err := em.GetEvent(eventID)
    if err != nil {
        return nil, err
    }
    
    return event.Tickets, nil
}

// AddComplianceRecord adds a compliance record to a specific event
func (em *EventManager) AddComplianceRecord(eventID, details string) error {
    return em.complianceManager.AddComplianceRecord(eventID, details)
}

// GetComplianceRecords retrieves compliance records for a specific event
func (em *EventManager) GetComplianceRecords(eventID string) ([]assets.ComplianceRecord, error) {
    return em.complianceManager.GetComplianceRecords(eventID)
}

// SerializeEvent serializes an event to JSON
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

// DeserializeEvent deserializes an event from JSON
func (em *EventManager) DeserializeEvent(data string) (Event, error) {
    var event Event
    err := json.Unmarshal([]byte(data), &event)
    if err != nil {
        return Event{}, err
    }
    
    em.events[event.Metadata.EventID] = event
    return event, nil
}

// SerializeAllEvents serializes all events to JSON
func (em *EventManager) SerializeAllEvents() (string, error) {
    data, err := json.Marshal(em.events)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeAllEvents deserializes all events from JSON
func (em *EventManager) DeserializeAllEvents(data string) error {
    var events map[string]Event
    err := json.Unmarshal([]byte(data), &events)
    if err != nil {
        return err
    }
    
    em.events = events
    return nil
}
