package compliance_tracking

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

// ComplianceEvent represents an individual compliance-related event or action.
type ComplianceEvent struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"`
	EntityID       string    `json:"entity_id"`
	Timestamp      time.Time `json:"timestamp"`
	ComplianceData string    `json:"compliance_data"`
}

// ComplianceTracker manages the lifecycle and storage of compliance events.
type ComplianceTracker struct {
	events        map[string]ComplianceEvent
	encryptionKey []byte
}

// NewComplianceTracker initializes a new ComplianceTracker with an AES encryption key.
func NewComplianceTracker(key []byte) *ComplianceTracker {
	return &ComplianceTracker{
		events:        make(map[string]ComplianceEvent),
		encryptionKey: key,
	}
}

// LogEvent captures and logs a compliance event securely.
func (ct *ComplianceTracker) LogEvent(eventType, entityID, data string) error {
	eventID := generateEventID()
	encryptedData, err := ct.encryptData([]byte(data))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt compliance data")
	}

	event := ComplianceEvent{
		EventID:        eventID,
		EventType:      eventType,
		EntityID:       entityID,
		Timestamp:      time.Now(),
		ComplianceData: encryptedData,
	}

	ct.events[eventID] = event
	log.Printf("Compliance event logged: %s", eventID)
	return nil
}

// RetrieveEvent fetches a compliance event by its ID.
func (ct *ComplianceTracker) RetrieveEvent(eventID string) (ComplianceEvent, error) {
	event, exists := ct.events[eventID]
	if !exists {
		return ComplianceEvent{}, errors.New("event not found")
	}

	decryptedData, err := ct.decryptData(event.ComplianceData)
	if err != nil {
		return ComplianceEvent{}, errors.Wrap(err, "failed to decrypt compliance data")
	}

	event.ComplianceData = decryptedData
	return event, nil
}

// encryptData encrypts compliance data using AES-GCM.
func (ct *ComplianceTracker) encryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(ct.encryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return string(encrypted), nil
}

// decryptData decrypts the encrypted compliance data.
func (ct *ComplianceTracker) decryptData(encryptedData string) (string, error) {
	data := []byte(encryptedData)
	block, err := aes.NewCipher(ct.encryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher block")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "failed to create GCM")
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt data")
	}

	return string(decrypted), nil
}

// generateEventID creates a unique ID for each compliance event.
func generateEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Println("Error generating event ID:", err)
		return ""
	}
	return fmt.Sprintf("%x", b)
}

