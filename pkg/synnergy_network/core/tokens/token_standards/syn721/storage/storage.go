package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/assets"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
)

// Storage represents a persistent storage system for SYN721 tokens
type Storage struct {
	db      *Database
	mutex   sync.Mutex
	logFile string
}

// NewStorage initializes a new Storage
func NewStorage(storageFile, logFile string) *Storage {
	return &Storage{
		db:      NewDatabase(storageFile),
		logFile: logFile,
	}
}

// AddToken adds a new SYN721 token to the storage
func (s *Storage) AddToken(token assets.Syn721Token) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.db.AddToken(token)
	if err != nil {
		return err
	}

	s.logEvent("AddToken", token.ID, token.Owner)
	return nil
}

// GetToken retrieves a SYN721 token by its ID
func (s *Storage) GetToken(tokenID string) (assets.Syn721Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, err := s.db.GetToken(tokenID)
	if err != nil {
		return assets.Syn721Token{}, err
	}

	s.logEvent("GetToken", tokenID, token.Owner)
	return token, nil
}

// RemoveToken removes a SYN721 token from the storage
func (s *Storage) RemoveToken(tokenID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.db.RemoveToken(tokenID)
	if err != nil {
		return err
	}

	s.logEvent("RemoveToken", tokenID, "")
	return nil
}

// UpdateTokenMetadata updates the metadata of a SYN721 token
func (s *Storage) UpdateTokenMetadata(tokenID string, newMetadata assets.Metadata) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.db.UpdateTokenMetadata(tokenID, newMetadata)
	if err != nil {
		return err
	}

	s.logEvent("UpdateTokenMetadata", tokenID, "")
	return nil
}

// UpdateTokenValuation updates the valuation of a SYN721 token
func (s *Storage) UpdateTokenValuation(tokenID string, newValuation assets.Valuation) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.db.UpdateTokenValuation(tokenID, newValuation)
	if err != nil {
		return err
	}

	s.logEvent("UpdateTokenValuation", tokenID, "")
	return nil
}

// TransferOwnership transfers ownership of a SYN721 token to a new owner
func (s *Storage) TransferOwnership(tokenID, newOwner string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.db.TransferOwnership(tokenID, newOwner)
	if err != nil {
		return err
	}

	s.logEvent("TransferOwnership", tokenID, newOwner)
	return nil
}

// GetOwnershipHistory retrieves the ownership history of a SYN721 token
func (s *Storage) GetOwnershipHistory(tokenID string) ([]ledger.OwnershipChange, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	history, err := s.db.GetOwnershipHistory(tokenID)
	if err != nil {
		return nil, err
	}

	s.logEvent("GetOwnershipHistory", tokenID, "")
	return history, nil
}

// GetValuationHistory retrieves the valuation history of a SYN721 token
func (s *Storage) GetValuationHistory(tokenID string) ([]ledger.ValuationChange, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	history, err := s.db.GetValuationHistory(tokenID)
	if err != nil {
		return nil, err
	}

	s.logEvent("GetValuationHistory", tokenID, "")
	return history, nil
}

// logEvent logs an event to the log file
func (s *Storage) logEvent(eventType, tokenID, owner string) {
	logEntry := struct {
		EventType string    `json:"eventType"`
		TokenID   string    `json:"tokenID"`
		Owner     string    `json:"owner"`
		Timestamp time.Time `json:"timestamp"`
	}{
		EventType: eventType,
		TokenID:   tokenID,
		Owner:     owner,
		Timestamp: time.Now(),
	}

	file, err := os.OpenFile(s.logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Warning: could not open log file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(logEntry); err != nil {
		fmt.Println("Warning: could not write log entry:", err)
	}
}
