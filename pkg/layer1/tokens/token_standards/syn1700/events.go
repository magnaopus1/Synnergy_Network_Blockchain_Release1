package syn1700

import (
	"time"
)

// EventCreated is used to signal that a new event has been created within the system.
type EventCreated struct {
	EventID      string    `json:"eventId"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Location     string    `json:"location"`
	StartTime    time.Time `json:"startTime"`
	EndTime      time.Time `json:"endTime"`
	TicketSupply int       `json:"ticketSupply"`
	Creator      string    `json:"creator"` // The creator or owner of the event.
	Timestamp    time.Time `json:"timestamp"`
}

// TicketSold is used to indicate a ticket sale.
type TicketSold struct {
	EventID   string    `json:"eventId"`
	TicketID  string    `json:"ticketId"`
	Buyer     string    `json:"buyer"`     // The identifier of the buyer.
	Price     float64   `json:"price"`     // The price at which the ticket was sold.
	Timestamp time.Time `json:"timestamp"`
}

// EventDataUpdated is used to indicate updates to an event's details.
type EventDataUpdated struct {
	EventID     string    `json:"eventId"`
	UpdatedInfo string    `json:"updatedInfo"` // Description of what information was updated.
	Timestamp   time.Time `json:"timestamp"`
}

// GenerateEventCreated creates an instance of EventCreated.
func GenerateEventCreated(event Event, creator string) EventCreated {
	return EventCreated{
		EventID:      event.ID,
		Name:         event.Name,
		Description:  event.Description,
		Location:     event.Location,
		StartTime:    event.StartTime,
		EndTime:      event.EndTime,
		TicketSupply: len(event.Tickets),
		Creator:      creator,
		Timestamp:    time.Now(),
	}
}

// GenerateTicketSold creates an instance of TicketSold.
func GenerateTicketSold(eventID, ticketID, buyer string, price float64) TicketSold {
	return TicketSold{
		EventID:   eventID,
		TicketID:  ticketID,
		Buyer:     buyer,
		Price:     price,
		Timestamp: time.Now(),
	}
}

// GenerateEventDataUpdated creates an instance of EventDataUpdated.
func GenerateEventDataUpdated(eventID, info string) EventDataUpdated {
	return EventDataUpdated{
		EventID:     eventID,
		UpdatedInfo: info,
		Timestamp:   time.Now(),
	}
}
