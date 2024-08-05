package events

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Event represents a blockchain event
type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Data        string    `json:"data"`
}

// EventLogger is responsible for logging blockchain events
type EventLogger struct {
	mu       sync.Mutex
	logFile  *os.File
	events   map[string]Event
	encryptKey string
}

// NewEventLogger initializes a new EventLogger
func NewEventLogger(logFilePath string, encryptKey string) (*EventLogger, error) {
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &EventLogger{
		logFile:  logFile,
		events:   make(map[string]Event),
		encryptKey: encryptKey,
	}, nil
}

// LogEvent logs a new event to the event log
func (el *EventLogger) LogEvent(eventType, description string, data interface{}) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	eventID := uuid.New().String()
	timestamp := time.Now()
	eventData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	encryptedData, err := el.encryptData(eventData)
	if err != nil {
		return err
	}

	event := Event{
		ID:          eventID,
		Timestamp:   timestamp,
		Type:        eventType,
		Description: description,
		Data:        encryptedData,
	}

	el.events[eventID] = event

	logEntry, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := el.logFile.Write(logEntry); err != nil {
		return err
	}
	if _, err := el.logFile.WriteString("\n"); err != nil {
		return err
	}

	return nil
}

// GetEvent retrieves a logged event by its ID
func (el *EventLogger) GetEvent(eventID string) (*Event, error) {
	el.mu.Lock()
	defer el.mu.Unlock()

	event, exists := el.events[eventID]
	if !exists {
		return nil, errors.New("event not found")
	}

	decryptedData, err := el.decryptData(event.Data)
	if err != nil {
		return nil, err
	}

	event.Data = string(decryptedData)
	return &event, nil
}

// GetEventsByType retrieves all events of a specific type
func (el *EventLogger) GetEventsByType(eventType string) ([]Event, error) {
	el.mu.Lock()
	defer el.mu.Unlock()

	var events []Event
	for _, event := range el.events {
		if event.Type == eventType {
			decryptedData, err := el.decryptData(event.Data)
			if err != nil {
				return nil, err
			}
			event.Data = string(decryptedData)
			events = append(events, event)
		}
	}
	return events, nil
}

// Close closes the event log file
func (el *EventLogger) Close() error {
	return el.logFile.Close()
}

func (el *EventLogger) encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher([]byte(el.encryptKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (el *EventLogger) decryptData(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(el.encryptKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Setup a default logger for demonstration purposes
func setupDefaultLogger() (*EventLogger, error) {
	encryptKey := "your-32-byte-long-key-here!"
	return NewEventLogger("blockchain_events.log", encryptKey)
}

func main() {
	logger, err := setupDefaultLogger()
	if err != nil {
		log.Fatalf("Failed to setup logger: %v", err)
	}
	defer logger.Close()

	// Example usage of logging an event
	err = logger.LogEvent("TRANSFER", "Token transfer event", map[string]interface{}{
		"from":   "address1",
		"to":     "address2",
		"amount": 1000,
	})
	if err != nil {
		log.Fatalf("Failed to log event: %v", err)
	}

	// Example usage of retrieving an event
	eventID := "your-event-id"
	event, err := logger.GetEvent(eventID)
	if err != nil {
		log.Fatalf("Failed to get event: %v", err)
	}
	log.Printf("Retrieved event: %+v", event)
}
