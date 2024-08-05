package syn223

import (
	"fmt"
	"log"
	"time"
)

// Event Types
const (
	TransferEvent   = "Transfer"
	RevertEvent     = "Revert"
	WhitelistEvent  = "WhitelistUpdate"
	BlacklistEvent  = "BlacklistUpdate"
)

// Event represents a blockchain event
type Event struct {
	Type      string
	Timestamp time.Time
	Details   string
}

// EventLog stores and manages blockchain events
type EventLog struct {
	events []Event
}

// NewEventLog initializes a new EventLog
func NewEventLog() *EventLog {
	return &EventLog{
		events: make([]Event, 0),
	}
}

// LogEvent logs a new event to the EventLog
func (el *EventLog) LogEvent(eventType, details string) {
	event := Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   details,
	}
	el.events = append(el.events, event)
	el.printEvent(event)
}

// GetEvents retrieves all logged events
func (el *EventLog) GetEvents() []Event {
	return el.events
}

// GetEventsByType retrieves events filtered by type
func (el *EventLog) GetEventsByType(eventType string) []Event {
	var filteredEvents []Event
	for _, event := range el.events {
		if event.Type == eventType {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// GetEventsByTimestamp retrieves events filtered by timestamp range
func (el *EventLog) GetEventsByTimestamp(start, end time.Time) []Event {
	var filteredEvents []Event
	for _, event := range el.events {
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// printEvent prints the event details to the console or log file
func (el *EventLog) printEvent(event Event) {
	log.Printf("Event Type: %s, Timestamp: %s, Details: %s\n", event.Type, event.Timestamp, event.Details)
}

// TransferEventDetails creates a detailed message for a transfer event
func TransferEventDetails(from, to string, amount float64) string {
	return fmt.Sprintf("Transfer from %s to %s of amount %f", from, to, amount)
}

// RevertEventDetails creates a detailed message for a revert event
func RevertEventDetails(from, to string, amount float64, reason string) string {
	return fmt.Sprintf("Revert transfer from %s to %s of amount %f due to %s", from, to, amount, reason)
}

// WhitelistUpdateEventDetails creates a detailed message for a whitelist update event
func WhitelistUpdateEventDetails(address string, action string) string {
	return fmt.Sprintf("Whitelist %s: %s", action, address)
}

// BlacklistUpdateEventDetails creates a detailed message for a blacklist update event
func BlacklistUpdateEventDetails(address string, action string) string {
	return fmt.Sprintf("Blacklist %s: %s", action, address)
}

// Example usage:

func main() {
	eventLog := NewEventLog()

	// Log a transfer event
	eventLog.LogEvent(TransferEvent, TransferEventDetails("0xSender", "0xReceiver", 100.5))

	// Log a revert event
	eventLog.LogEvent(RevertEvent, RevertEventDetails("0xSender", "0xReceiver", 100.5, "Contract not supported"))

	// Log a whitelist update event
	eventLog.LogEvent(WhitelistEvent, WhitelistUpdateEventDetails("0xAddress", "added"))

	// Log a blacklist update event
	eventLog.LogEvent(BlacklistEvent, BlacklistUpdateEventDetails("0xAddress", "removed"))

	// Retrieve and print all events
	allEvents := eventLog.GetEvents()
	for _, event := range allEvents {
		fmt.Println(event)
	}

	// Retrieve and print events by type
	transferEvents := eventLog.GetEventsByType(TransferEvent)
	for _, event := range transferEvents {
		fmt.Println(event)
	}

	// Retrieve and print events by timestamp range
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()
	timeFilteredEvents := eventLog.GetEventsByTimestamp(startTime, endTime)
	for _, event := range timeFilteredEvents {
		fmt.Println(event)
	}
}
