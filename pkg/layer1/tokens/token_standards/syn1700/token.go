package syn1700

import (
	"errors"
	"fmt"
	"time"
)

// Ticket represents a single ticket's data structure
type Ticket struct {
	EventID     string    `json:"event_id"`
	TicketID    string    `json:"ticket_id"`
	EventName   string    `json:"event_name"`
	Date        time.Time `json:"date"`
	TicketPrice float64   `json:"ticket_price"`
	TicketClass string    `json:"ticket_class"` // e.g., Standard, VIP
	TicketType  string    `json:"ticket_type"`  // e.g., Early-bird, Standard, Late release
	IsAdult     bool      `json:"is_adult"`
	IsDisabled  bool      `json:"is_disabled"`
	Sold        bool      `json:"sold"`
}

// Event represents the structure of an event, containing multiple tickets
type Event struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Location    string    `json:"location"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Tickets     []Ticket  `json:"tickets"`
	Supply      int       `json:"supply"`
	Sold        int       `json:"sold"`
}

// SYN1700Token implements methods for managing event tickets
type SYN1700Token struct {
	Events map[string]Event `json:"events"`
}

// NewSYN1700Token initializes a new SYN1700 token
func NewSYN1700Token() *SYN1700Token {
	return &SYN1700Token{
		Events: make(map[string]Event),
	}
}

// CreateEvent initializes a new event with a set of tickets
func (t *SYN1700Token) CreateEvent(event Event) error {
	if _, exists := t.Events[event.ID]; exists {
		return fmt.Errorf("event with ID %s already exists", event.ID)
	}
	if event.Supply != len(event.Tickets) {
		return errors.New("mismatch between declared supply and number of tickets")
	}
	t.Events[event.ID] = event
	return nil
}

// SellTicket marks a ticket as sold, adjusting the available supply
func (t *SYN1700Token) SellTicket(eventID, ticketID string) error {
	event, exists := t.Events[eventID]
	if !exists {
		return fmt.Errorf("no event found with ID %s", eventID)
	}

	for i, ticket := range event.Tickets {
		if ticket.TicketID == ticketID && !ticket.Sold {
			if event.Sold >= event.Supply {
				return fmt.Errorf("no more tickets available for event %s", event.Name)
			}
			ticket.Sold = true
			event.Tickets[i] = ticket
			event.Sold++
			t.Events[eventID] = event
			return nil
		}
	}

	return fmt.Errorf("no ticket found with ID %s in event %s, or ticket already sold", ticketID, eventID)
}

// GetEventInfo returns details about an event, including tickets
func (t *SYN1700Token) GetEventInfo(eventID string) (Event, error) {
	event, exists := t.Events[eventID]
	if !exists {
		return Event{}, fmt.Errorf("no event found with ID %s", eventID)
	}
	return event, nil
}
