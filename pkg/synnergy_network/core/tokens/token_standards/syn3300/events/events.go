package events

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// ETFEvent represents an event related to an ETF
type ETFEvent struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"`
	ETFID          string    `json:"etf_id"`
	ShareTokenID   string    `json:"share_token_id"`
	Owner          string    `json:"owner"`
	Timestamp      time.Time `json:"timestamp"`
	EventDetails   string    `json:"event_details"`
}

// ETFEventService provides methods to handle ETF-related events
type ETFEventService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewETFEventService creates a new instance of ETFEventService
func NewETFEventService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *ETFEventService {
	return &ETFEventService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// RecordEvent records a new event related to an ETF share
func (s *ETFEventService) RecordEvent(eventType, etfID, shareTokenID, owner, eventDetails string) (*ETFEvent, error) {
	if eventType == "" || etfID == "" || shareTokenID == "" || owner == "" || eventDetails == "" {
		return nil, errors.New("invalid input parameters")
	}

	event := &ETFEvent{
		EventID:      generateEventID(etfID, shareTokenID, owner),
		EventType:    eventType,
		ETFID:        etfID,
		ShareTokenID: shareTokenID,
		Owner:        owner,
		Timestamp:    time.Now(),
		EventDetails: eventDetails,
	}

	encryptedEvent, err := s.encryptionService.EncryptData(event)
	if err != nil {
		return nil, err
	}

	if err := s.ledgerService.RecordETFEvent(encryptedEvent); err != nil {
		return nil, err
	}

	return event, nil
}

// GetEvent retrieves an event by its ID
func (s *ETFEventService) GetEvent(eventID string) (*ETFEvent, error) {
	if eventID == "" {
		return nil, errors.New("invalid input parameters")
	}

	encryptedEvent, err := s.ledgerService.GetETFEvent(eventID)
	if err != nil {
		return nil, err
	}

	event, err := s.encryptionService.DecryptData(encryptedEvent)
	if err != nil {
		return nil, err
	}

	return event, nil
}

// ListAllEvents retrieves all events related to ETFs
func (s *ETFEventService) ListAllEvents() ([]*ETFEvent, error) {
	encryptedEvents, err := s.ledgerService.GetAllETFEvents()
	if err != nil {
		return nil, err
	}

	var events []*ETFEvent
	for _, encryptedEvent := range encryptedEvents {
		event, err := s.encryptionService.DecryptData(encryptedEvent)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

// generateEventID generates a unique event ID based on the ETF ID, share token ID, and owner
func generateEventID(etfID, shareTokenID, owner string) string {
	data := etfID + shareTokenID + owner + time.Now().String()
	return hash(data)
}

// hash generates a hash of the given data
func hash(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data interface{}) (string, error) {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData, err := encryption.Argon2Encrypt(serializedData)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (*ETFEvent, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var event ETFEvent
	if err := json.Unmarshal([]byte(decryptedData), &event); err != nil {
		return nil, err
	}

	return &event, nil
}
