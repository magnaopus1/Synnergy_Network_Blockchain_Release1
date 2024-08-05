package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Event represents an event in the SYN900 token lifecycle
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	Actor       string    `json:"actor"`
}

// EventLogger manages logging of events
type EventLogger struct {
	events []Event
}

// NewEventLogger initializes a new EventLogger
func NewEventLogger() *EventLogger {
	return &EventLogger{
		events: make([]Event, 0),
	}
}

// LogEvent logs an event
func (el *EventLogger) LogEvent(eventType, description, actor string) {
	event := Event{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Description: description,
		Actor:       actor,
	}
	el.events = append(el.events, event)
}

// GetEvents retrieves all logged events
func (el *EventLogger) GetEvents() []Event {
	return el.events
}

// FindEventsByType retrieves events by their type
func (el *EventLogger) FindEventsByType(eventType string) []Event {
	var filteredEvents []Event
	for _, event := range el.events {
		if event.EventType == eventType {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// FindEventsByActor retrieves events by the actor who performed them
func (el *EventLogger) FindEventsByActor(actor string) []Event {
	var filteredEvents []Event
	for _, event := range el.events {
		if event.Actor == actor {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents
}

// SaveEvents serializes the logged events to JSON
func (el *EventLogger) SaveEvents() (string, error) {
	data, err := json.Marshal(el.events)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// LoadEvents deserializes the logged events from JSON
func (el *EventLogger) LoadEvents(data string) error {
	var events []Event
	err := json.Unmarshal([]byte(data), &events)
	if err != nil {
		return err
	}
	el.events = events
	return nil
}

// Example usage of EventLogger
func main() {
	logger := NewEventLogger()
	logger.LogEvent("verification", "User identity verified", "user123")
	logger.LogEvent("transfer", "Token transferred to new owner", "user123")
	logger.LogEvent("compliance", "Compliance check passed", "admin456")

	events := logger.GetEvents()
	for _, event := range events {
		fmt.Printf("Event: %+v\n", event)
	}

	verificationEvents := logger.FindEventsByType("verification")
	for _, event := range verificationEvents {
		fmt.Printf("Verification Event: %+v\n", event)
	}

	userEvents := logger.FindEventsByActor("user123")
	for _, event := range userEvents {
		fmt.Printf("User Event: %+v\n", event)
	}

	data, err := logger.SaveEvents()
	if err != nil {
		fmt.Println("Error saving events:", err)
		return
	}

	err = logger.LoadEvents(data)
	if err != nil {
		fmt.Println("Error loading events:", err)
		return
	}

	fmt.Println("Events successfully loaded from saved data")
}
