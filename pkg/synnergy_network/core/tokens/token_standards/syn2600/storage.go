package syn2600

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
)

// Storage represents the interface to the storage layer for SYN2600 tokens.
type Storage struct {
	ledger      *InvestmentLedger
	filePath    string
	mutex       sync.Mutex
}

// NewStorage initializes a new storage system for the Investment Ledger.
func NewStorage(filePath string) (*Storage, error) {
	s := &Storage{
		filePath: filePath,
		ledger:   NewInvestmentLedger(),
	}

	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load retrieves the ledger from the file system.
func (s *Storage) load() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No data yet, start with an empty ledger
		}
		return err
	}

	return json.Unmarshal(data, s.ledger)
}

// save writes the current state of the ledger to the file system.
func (s *Storage) save() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := json.Marshal(s.ledger)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.filePath, data, 0644)
}

// SaveToken persists a new or updated token to the storage.
func (s *Storage) SaveToken(token InvestorToken) error {
	if err := s.ledger.IssueToken(token); err != nil {
		return err
	}
	return s.save()
}

// GetToken retrieves a token from storage.
func (s *Storage) GetToken(tokenID string) (InvestorToken, error) {
	token, err := s.ledger.GetToken(tokenID)
	if err != nil {
		return InvestorToken{}, err
	}
	return token, nil
}

// DeleteToken removes a token from storage and updates the ledger.
func (s *Storage) DeleteToken(tokenID string) error {
	if err := s.ledger.RedeemToken(tokenID); err != nil {
		return err
	}
	return s.save()
}

// ListTokensByOwner retrieves all tokens for a specific owner.
func (s *Storage) ListTokensByOwner(owner string) ([]InvestorToken, error) {
	tokens, err := s.ledger.ListTokensByOwner(owner)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// UpdateToken modifies an existing token in the storage.
func (s *Storage) UpdateToken(tokenID string, updates map[string]interface{}) error {
	if err := s.ledger.UpdateToken(tokenID, updates); err != nil {
		return err
	}
	return s.save()
}

// TransferOwnership changes the owner of a specific token.
func (s *Storage) TransferOwnership(tokenID, newOwner string) error {
	if err := s.ledger.TransferToken(tokenID, newOwner); err != nil {
		return err
	}
	return s.save()
}
