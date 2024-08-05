package assets

import (
    "encoding/json"
    "errors"
    "time"
)

// TicketMetadata represents the metadata for a ticket
type TicketMetadata struct {
    EventID           string    `json:"event_id"`
    TicketID          string    `json:"ticket_id"`
    EventName         string    `json:"event_name"`
    Date              time.Time `json:"date"`
    TicketPrice       float64   `json:"ticket_price"`
    TicketClass       string    `json:"ticket_class"`
    TicketType        string    `json:"ticket_type"`
    SpecialConditions string    `json:"special_conditions"`
}

// TicketManager manages ticket metadata for SYN1700 tokens
type TicketManager struct {
    tickets map[string]TicketMetadata // TicketID -> TicketMetadata
}

// NewTicketManager creates a new TicketManager
func NewTicketManager() *TicketManager {
    return &TicketManager{
        tickets: make(map[string]TicketMetadata),
    }
}

// AddTicket adds a new ticket
func (tm *TicketManager) AddTicket(ticket TicketMetadata) error {
    if ticket.TicketID == "" || ticket.EventID == "" {
        return errors.New("ticket ID and event ID are required")
    }

    tm.tickets[ticket.TicketID] = ticket
    return nil
}

// UpdateTicket updates an existing ticket's metadata
func (tm *TicketManager) UpdateTicket(ticket TicketMetadata) error {
    if ticket.TicketID == "" {
        return errors.New("ticket ID is required")
    }

    _, exists := tm.tickets[ticket.TicketID]
    if !exists {
        return errors.New("ticket not found")
    }

    tm.tickets[ticket.TicketID] = ticket
    return nil
}

// GetTicket retrieves metadata for a specific ticket
func (tm *TicketManager) GetTicket(ticketID string) (TicketMetadata, error) {
    ticket, exists := tm.tickets[ticketID]
    if !exists {
        return TicketMetadata{}, errors.New("ticket not found")
    }
    return ticket, nil
}

// GetAllTickets retrieves metadata for all tickets
func (tm *TicketManager) GetAllTickets() map[string]TicketMetadata {
    return tm.tickets
}

// DeleteTicket deletes a ticket's metadata
func (tm *TicketManager) DeleteTicket(ticketID string) error {
    _, exists := tm.tickets[ticketID]
    if !exists {
        return errors.New("ticket not found")
    }

    delete(tm.tickets, ticketID)
    return nil
}

// SerializeTicket serializes ticket metadata to JSON
func (tm *TicketManager) SerializeTicket(ticketID string) (string, error) {
    ticket, err := tm.GetTicket(ticketID)
    if err != nil {
        return "", err
    }

    data, err := json.Marshal(ticket)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeTicket deserializes ticket metadata from JSON
func (tm *TicketManager) DeserializeTicket(data string) (TicketMetadata, error) {
    var ticket TicketMetadata
    err := json.Unmarshal([]byte(data), &ticket)
    if err != nil {
        return TicketMetadata{}, err
    }

    return ticket, nil
}

// SerializeAllTickets serializes all ticket metadata to JSON
func (tm *TicketManager) SerializeAllTickets() (string, error) {
    data, err := json.Marshal(tm.tickets)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// DeserializeAllTickets deserializes all ticket metadata from JSON
func (tm *TicketManager) DeserializeAllTickets(data string) error {
    var tickets map[string]TicketMetadata
    err := json.Unmarshal([]byte(data), &tickets)
    if err != nil {
        return err
    }

    tm.tickets = tickets
    return nil
}

// ValidateTicket checks if a ticket is valid
func (tm *TicketManager) ValidateTicket(ticketID string) (bool, error) {
    ticket, err := tm.GetTicket(ticketID)
    if err != nil {
        return false, err
    }

    // Add any additional validation logic here
    if ticket.SpecialConditions == "revoked" {
        return false, errors.New("ticket is revoked")
    }

    return true, nil
}

// RevokeTicket revokes a ticket, making it invalid for future use
func (tm *TicketManager) RevokeTicket(ticketID, reason string) error {
    ticket, err := tm.GetTicket(ticketID)
    if err != nil {
        return err
    }

    ticket.SpecialConditions = "revoked"
    return tm.UpdateTicket(ticket)
}
