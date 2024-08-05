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

// Database represents a simple in-memory database for storing SYN721 tokens
type Database struct {
	tokens           map[string]assets.Syn721Token
	ownershipHistory map[string][]ledger.OwnershipChange
	valuationHistory map[string][]ledger.ValuationChange
	mutex            sync.Mutex
	storageFile      string
}

// NewDatabase initializes a new Database
func NewDatabase(storageFile string) *Database {
	db := &Database{
		tokens:           make(map[string]assets.Syn721Token),
		ownershipHistory: make(map[string][]ledger.OwnershipChange),
		valuationHistory: make(map[string][]ledger.ValuationChange),
		storageFile:      storageFile,
	}

	if err := db.loadFromFile(); err != nil {
		fmt.Println("Warning: could not load data from storage file:", err)
	}

	return db
}

// AddToken adds a new SYN721 token to the database
func (db *Database) AddToken(token assets.Syn721Token) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, exists := db.tokens[token.ID]; exists {
		return fmt.Errorf("token with ID %s already exists", token.ID)
	}

	db.tokens[token.ID] = token
	db.ownershipHistory[token.ID] = append(db.ownershipHistory[token.ID], ledger.OwnershipChange{
		TokenID: token.ID,
		Owner:   token.Owner,
		Time:    token.CreatedAt,
	})
	db.saveToFile()

	return nil
}

// GetToken retrieves a SYN721 token by its ID
func (db *Database) GetToken(tokenID string) (assets.Syn721Token, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	token, exists := db.tokens[tokenID]
	if !exists {
		return assets.Syn721Token{}, fmt.Errorf("token with ID %s not found", tokenID)
	}

	return token, nil
}

// RemoveToken removes a SYN721 token from the database
func (db *Database) RemoveToken(tokenID string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, exists := db.tokens[tokenID]; !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	delete(db.tokens, tokenID)
	delete(db.ownershipHistory, tokenID)
	delete(db.valuationHistory, tokenID)
	db.saveToFile()

	return nil
}

// UpdateTokenMetadata updates the metadata of a SYN721 token
func (db *Database) UpdateTokenMetadata(tokenID string, newMetadata assets.Metadata) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	token, exists := db.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	token.Metadata = newMetadata
	token.UpdatedAt = time.Now()
	db.tokens[tokenID] = token
	db.saveToFile()

	return nil
}

// UpdateTokenValuation updates the valuation of a SYN721 token
func (db *Database) UpdateTokenValuation(tokenID string, newValuation assets.Valuation) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	token, exists := db.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	token.Valuation = newValuation
	token.UpdatedAt = time.Now()
	db.tokens[tokenID] = token
	db.valuationHistory[tokenID] = append(db.valuationHistory[tokenID], ledger.ValuationChange{
		TokenID:   tokenID,
		Valuation: newValuation,
		Time:      time.Now(),
	})
	db.saveToFile()

	return nil
}

// TransferOwnership transfers ownership of a SYN721 token to a new owner
func (db *Database) TransferOwnership(tokenID, newOwner string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	token, exists := db.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	token.Owner = newOwner
	token.UpdatedAt = time.Now()
	db.tokens[tokenID] = token
	db.ownershipHistory[tokenID] = append(db.ownershipHistory[tokenID], ledger.OwnershipChange{
		TokenID: tokenID,
		Owner:   newOwner,
		Time:    time.Now(),
	})
	db.saveToFile()

	return nil
}

// GetOwnershipHistory retrieves the ownership history of a SYN721 token
func (db *Database) GetOwnershipHistory(tokenID string) ([]ledger.OwnershipChange, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	history, exists := db.ownershipHistory[tokenID]
	if !exists {
		return nil, fmt.Errorf("ownership history for token ID %s not found", tokenID)
	}

	return history, nil
}

// GetValuationHistory retrieves the valuation history of a SYN721 token
func (db *Database) GetValuationHistory(tokenID string) ([]ledger.ValuationChange, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	history, exists := db.valuationHistory[tokenID]
	if !exists {
		return nil, fmt.Errorf("valuation history for token ID %s not found", tokenID)
	}

	return history, nil
}

// saveToFile saves the database to the file
func (db *Database) saveToFile() error {
	data := struct {
		Tokens           map[string]assets.Syn721Token
		OwnershipHistory map[string][]ledger.OwnershipChange
		ValuationHistory map[string][]ledger.ValuationChange
	}{
		Tokens:           db.tokens,
		OwnershipHistory: db.ownershipHistory,
		ValuationHistory: db.valuationHistory,
	}

	file, err := os.OpenFile(db.storageFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		return err
	}

	return nil
}

// loadFromFile loads the database from the file
func (db *Database) loadFromFile() error {
	file, err := os.Open(db.storageFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	data := struct {
		Tokens           map[string]assets.Syn721Token
		OwnershipHistory map[string][]ledger.OwnershipChange
		ValuationHistory map[string][]ledger.ValuationChange
	}{}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	db.tokens = data.Tokens
	db.ownershipHistory = data.OwnershipHistory
	db.valuationHistory = data.ValuationHistory

	return nil
}
