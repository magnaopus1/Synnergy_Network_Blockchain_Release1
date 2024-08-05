package events

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// EventType defines the type of events that can occur in the system.
type EventType string

const (
	// IssuanceEvent represents an event where new tokens are issued.
	IssuanceEvent EventType = "ISSUANCE_EVENT"

	// RedemptionEvent represents an event where tokens are redeemed.
	RedemptionEvent EventType = "REDEMPTION_EVENT"

	// TransferEvent represents an event where tokens are transferred between owners.
	TransferEvent EventType = "TRANSFER_EVENT"

	// ComplianceEvent represents an event related to compliance activities.
	ComplianceEvent EventType = "COMPLIANCE_EVENT"
)

// Event represents a loggable event in the system.
type Event struct {
	Timestamp   time.Time // Time when the event occurred
	Type        EventType // Type of the event
	Description string    // Description of the event
	Details     string    // Additional details about the event
}

// EventManager handles the logging and management of events in the system.
type EventManager struct {
	eventLogDirectory string      // Directory where events are logged
	mutex             sync.Mutex  // Mutex for thread-safe operations
	eventLogFile      *os.File    // File for logging events
}

// NewEventManager creates a new EventManager.
func NewEventManager(directory string) (*EventManager, error) {
	if directory == "" {
		return nil, errors.New("event log directory cannot be empty")
	}

	// Ensure the directory exists
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		if err := os.Mkdir(directory, 0755); err != nil {
			return nil, fmt.Errorf("failed to create event log directory: %w", err)
		}
	}

	logFile, err := os.OpenFile(fmt.Sprintf("%s/events.log", directory), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log file: %w", err)
	}

	return &EventManager{
		eventLogDirectory: directory,
		eventLogFile:      logFile,
	}, nil
}

// LogEvent logs an event to the event log file.
func (em *EventManager) LogEvent(event Event) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if event.Type == "" || event.Description == "" {
		return errors.New("event type and description cannot be empty")
	}

	logEntry := fmt.Sprintf("%s | %s | %s | %s\n", event.Timestamp.Format(time.RFC3339), event.Type, event.Description, event.Details)
	if _, err := em.eventLogFile.WriteString(logEntry); err != nil {
		return fmt.Errorf("failed to write event log: %w", err)
	}

	log.Printf("Event logged: %s\n", event.Description)
	return nil
}

// Close closes the event log file.
func (em *EventManager) Close() error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if err := em.eventLogFile.Close(); err != nil {
		return fmt.Errorf("failed to close event log file: %w", err)
	}
	return nil
}

// AnalyzeEvents analyzes logged events for patterns and insights.
func (em *EventManager) AnalyzeEvents() ([]Event, error) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	file, err := os.Open(fmt.Sprintf("%s/events.log", em.eventLogDirectory))
	if err != nil {
		return nil, fmt.Errorf("failed to open event log file: %w", err)
	}
	defer file.Close()

	var events []Event
	var timestamp, eventType, description, details string
	for {
		_, err := fmt.Fscanf(file, "%s | %s | %s | %s\n", &timestamp, &eventType, &description, &details)
		if err != nil {
			break
		}
		parsedTime, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse event timestamp: %w", err)
		}
		event := Event{
			Timestamp:   parsedTime,
			Type:        EventType(eventType),
			Description: description,
			Details:     details,
		}
		events = append(events, event)
	}

	return events, nil
}
