package factory

import (
    "errors"
    "time"
    "../assets"
    "../events"
    "../transactions"
)

// TokenFactory is responsible for creating and managing SYN1700 tokens
type TokenFactory struct {
    eventManager      *events.EventManager
    transactionManager *transactions.TransactionManager
}

// NewTokenFactory creates a new TokenFactory
func NewTokenFactory() *TokenFactory {
    return &TokenFactory{
        eventManager:      events.NewEventManager(),
        transactionManager: transactions.NewTransactionManager(),
    }
}

// CreateEvent creates a new event with metadata
func (tf *TokenFactory) CreateEvent(metadata assets.EventMetadata) (string, error) {
    if metadata.Name == "" || metadata.Location == "" || metadata.StartTime.After(metadata.EndTime) {
        return "", errors.New("invalid event metadata")
    }
    return tf.eventManager.CreateEvent(metadata)
}

// AddTicket adds a new ticket to an existing event
func (tf *TokenFactory) AddTicket(eventID string, ticketMetadata assets.TicketMetadata) error {
    if eventID == "" || ticketMetadata.TicketID == "" || ticketMetadata.EventName == "" {
        return errors.New("invalid ticket metadata")
    }
    return tf.eventManager.AddTicket(eventID, ticketMetadata)
}

// TransferTicket transfers a ticket from one owner to another
func (tf *TokenFactory) TransferTicket(ticketID, fromOwnerID, toOwnerID string) error {
    if ticketID == "" || fromOwnerID == "" || toOwnerID == "" {
        return errors.New("invalid transfer details")
    }

    ticket, err := tf.eventManager.ticketManager.GetTicket(ticketID)
    if err != nil {
        return err
    }

    if tf.eventManager.ticketManager.ValidateTicket(ticketID) {
        err := tf.eventManager.ticketManager.TransferOwnership(ticketID, toOwnerID)
        if err != nil {
            return err
        }

        err = tf.eventManager.AddEventLog(ticket.EventID, "Ticket transferred from "+fromOwnerID+" to "+toOwnerID)
        if err != nil {
            return err
        }

        return tf.transactionManager.RecordTransaction(ticketID, fromOwnerID, toOwnerID, time.Now())
    }
    return errors.New("ticket is not valid for transfer")
}

// RevokeTicket revokes a ticket, making it invalid for future use
func (tf *TokenFactory) RevokeTicket(ticketID, reason string) error {
    if ticketID == "" || reason == "" {
        return errors.New("invalid revocation details")
    }

    ticket, err := tf.eventManager.ticketManager.GetTicket(ticketID)
    if err != nil {
        return err
    }

    err = tf.eventManager.ticketManager.RevokeTicket(ticketID, reason)
    if err != nil {
        return err
    }

    return tf.eventManager.AddEventLog(ticket.EventID, "Ticket revoked for reason: "+reason)
}

// VerifyOwnership verifies the ownership of a ticket
func (tf *TokenFactory) VerifyOwnership(ticketID, ownerID string) (bool, error) {
    if ticketID == "" || ownerID == "" {
        return false, errors.New("invalid ownership details")
    }

    return tf.eventManager.ticketManager.VerifyOwnership(ticketID, ownerID), nil
}

// SerializeEvent serializes event metadata to JSON
func (tf *TokenFactory) SerializeEvent(eventID string) (string, error) {
    if eventID == "" {
        return "", errors.New("invalid event ID")
    }
    return tf.eventManager.SerializeEvent(eventID)
}

// DeserializeEvent deserializes event metadata from JSON
func (tf *TokenFactory) DeserializeEvent(data string) (assets.EventMetadata, error) {
    if data == "" {
        return assets.EventMetadata{}, errors.New("invalid data")
    }
    event, err := tf.eventManager.DeserializeEvent(data)
    if err != nil {
        return assets.EventMetadata{}, err
    }
    return event.Metadata, nil
}

// GetEvent retrieves event metadata by its ID
func (tf *TokenFactory) GetEvent(eventID string) (assets.EventMetadata, error) {
    if eventID == "" {
        return assets.EventMetadata{}, errors.New("invalid event ID")
    }
    event, err := tf.eventManager.GetEvent(eventID)
    if err != nil {
        return assets.EventMetadata{}, err
    }
    return event.Metadata, nil
}

// GetTickets retrieves all tickets for a specific event
func (tf *TokenFactory) GetTickets(eventID string) ([]assets.TicketMetadata, error) {
    if eventID == "" {
        return nil, errors.New("invalid event ID")
    }
    return tf.eventManager.GetTickets(eventID)
}

// GetAllEvents retrieves all events
func (tf *TokenFactory) GetAllEvents() (map[string]assets.EventMetadata, error) {
    events := tf.eventManager.GetAllEvents()
    eventMetadata := make(map[string]assets.EventMetadata)
    for id, event := range events {
        eventMetadata[id] = event.Metadata
    }
    return eventMetadata, nil
}
