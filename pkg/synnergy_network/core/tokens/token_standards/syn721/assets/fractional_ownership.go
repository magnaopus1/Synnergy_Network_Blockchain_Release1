package assets

import (
	"fmt"
	"sync"
	"time"
)

// FractionalOwnership represents the fractional ownership details of a SYN721 token
type FractionalOwnership struct {
	TokenID     string
	Owner       string
	Percentage  float64
	CreatedAt   time.Time
}

// Syn721Token represents a SYN721 token with its metadata, ownership, valuation, and fractional ownership details
type Syn721Token struct {
	ID                  string
	Owner               string
	Metadata            Metadata
	Valuation           Valuation
	Collection          string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	FractionalOwners    []FractionalOwnership
}

// Valuation represents the valuation details of a SYN721 token
type Valuation struct {
	Value       float64
	Currency    string
	Timestamp   time.Time
	AppraisedBy string
}

// Metadata represents the metadata associated with a SYN721 token
type Metadata struct {
	Name        string
	Description string
	Image       string
	Attributes  map[string]interface{}
}

// ValuationChange represents a change in the valuation of a SYN721 token
type ValuationChange struct {
	Timestamp   time.Time
	OldValue    float64
	NewValue    float64
	Currency    string
	AppraisedBy string
}

// OwnershipChange represents a change in the ownership of a SYN721 token
type OwnershipChange struct {
	Timestamp time.Time
	From      string
	To        string
}

// Collection represents a collection of SYN721 tokens
type Collection struct {
	Name       string
	Owner      string
	Tokens     []string
	FloorPrice float64
	Currency   string
}

// Syn721TokenTracker manages SYN721 tokens and tracks their metadata, ownership, valuation changes, and fractional ownership
type Syn721TokenTracker struct {
	tokens             map[string]Syn721Token
	valuationHistories map[string][]ValuationChange
	ownershipHistories map[string][]OwnershipChange
	collections        map[string]Collection
	mutex              sync.Mutex
}

// NewSyn721TokenTracker initializes a new Syn721TokenTracker
func NewSyn721TokenTracker() *Syn721TokenTracker {
	return &Syn721TokenTracker{
		tokens:             make(map[string]Syn721Token),
		valuationHistories: make(map[string][]ValuationChange),
		ownershipHistories: make(map[string][]OwnershipChange),
		collections:        make(map[string]Collection),
	}
}

// AddToken adds a new token to the tracker
func (tt *Syn721TokenTracker) AddToken(id, owner, collection string, metadata Metadata, initialValuation Valuation) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	if _, exists := tt.tokens[id]; exists {
		return fmt.Errorf("token with ID %s already exists", id)
	}

	token := Syn721Token{
		ID:         id,
		Owner:      owner,
		Metadata:   metadata,
		Valuation:  initialValuation,
		Collection: collection,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	tt.tokens[id] = token
	tt.valuationHistories[id] = []ValuationChange{
		{
			Timestamp:   time.Now(),
			OldValue:    0,
			NewValue:    initialValuation.Value,
			Currency:    initialValuation.Currency,
			AppraisedBy: initialValuation.AppraisedBy,
		},
	}

	if collection != "" {
		tt.addTokenToCollection(collection, id, initialValuation.Value, initialValuation.Currency)
	}

	return nil
}

// UpdateTokenMetadata updates the metadata of an existing token
func (tt *Syn721TokenTracker) UpdateTokenMetadata(id string, metadata Metadata) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	token, exists := tt.tokens[id]
	if !exists {
		return fmt.Errorf("token with ID %s not found", id)
	}

	token.Metadata = metadata
	token.UpdatedAt = time.Now()

	tt.tokens[id] = token

	return nil
}

// UpdateTokenValuation updates the valuation of an existing token
func (tt *Syn721TokenTracker) UpdateTokenValuation(id string, newValuation Valuation) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	token, exists := tt.tokens[id]
	if !exists {
		return fmt.Errorf("token with ID %s not found", id)
	}

	oldValuation := token.Valuation
	token.Valuation = newValuation
	token.UpdatedAt = time.Now()

	tt.tokens[id] = token
	tt.valuationHistories[id] = append(tt.valuationHistories[id], ValuationChange{
		Timestamp:   time.Now(),
		OldValue:    oldValuation.Value,
		NewValue:    newValuation.Value,
		Currency:    newValuation.Currency,
		AppraisedBy: newValuation.AppraisedBy,
	})

	if token.Collection != "" {
		tt.updateCollectionFloorPrice(token.Collection)
	}

	return nil
}

// TransferOwnership transfers the ownership of a token
func (tt *Syn721TokenTracker) TransferOwnership(id, newOwner string) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	token, exists := tt.tokens[id]
	if !exists {
		return fmt.Errorf("token with ID %s not found", id)
	}

	ownershipChange := OwnershipChange{
		Timestamp: time.Now(),
		From:      token.Owner,
		To:        newOwner,
	}

	token.Owner = newOwner
	token.UpdatedAt = time.Now()

	tt.tokens[id] = token
	tt.ownershipHistories[id] = append(tt.ownershipHistories[id], ownershipChange)

	return nil
}

// AddFractionalOwner adds a fractional owner to a token
func (tt *Syn721TokenTracker) AddFractionalOwner(id, owner string, percentage float64) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	token, exists := tt.tokens[id]
	if !exists {
		return fmt.Errorf("token with ID %s not found", id)
	}

	if percentage <= 0 || percentage > 100 {
		return fmt.Errorf("invalid percentage value")
	}

	token.FractionalOwners = append(token.FractionalOwners, FractionalOwnership{
		TokenID:    id,
		Owner:      owner,
		Percentage: percentage,
		CreatedAt:  time.Now(),
	})

	tt.tokens[id] = token

	return nil
}

// GetToken retrieves a token by its ID
func (tt *Syn721TokenTracker) GetToken(id string) (Syn721Token, error) {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	token, exists := tt.tokens[id]
	if !exists {
		return Syn721Token{}, fmt.Errorf("token with ID %s not found", id)
	}

	return token, nil
}

// GetOwnershipHistory retrieves the ownership history of a token
func (tt *Syn721TokenTracker) GetOwnershipHistory(id string) ([]OwnershipChange, error) {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	history, exists := tt.ownershipHistories[id]
	if !exists {
		return nil, fmt.Errorf("ownership history for token with ID %s not found", id)
	}

	return history, nil
}

// GetValuationHistory retrieves the valuation history of a token
func (tt *Syn721TokenTracker) GetValuationHistory(id string) ([]ValuationChange, error) {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	history, exists := tt.valuationHistories[id]
	if !exists {
		return nil, fmt.Errorf("valuation history for token with ID %s not found", id)
	}

	return history, nil
}

// CreateCollection creates a new collection
func (tt *Syn721TokenTracker) CreateCollection(name, owner string) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	if _, exists := tt.collections[name]; exists {
		return fmt.Errorf("collection with name %s already exists", name)
	}

	collection := Collection{
		Name:   name,
		Owner:  owner,
		Tokens: []string{},
	}

	tt.collections[name] = collection

	return nil
}

// GetCollection retrieves a collection by its name
func (tt *Syn721TokenTracker) GetCollection(name string) (Collection, error) {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	collection, exists := tt.collections[name]
	if !exists {
		return Collection{}, fmt.Errorf("collection with name %s not found", name)
	}

	return collection, nil
}

// addTokenToCollection adds a token to a collection
func (tt *Syn721TokenTracker) addTokenToCollection(collectionName, tokenID string, value float64, currency string) {
	collection, exists := tt.collections[collectionName]
	if !exists {
		return
	}

	collection.Tokens = append(collection.Tokens, tokenID)
	tt.collections[collectionName] = collection
	tt.updateCollectionFloorPrice(collectionName)
}

// updateCollectionFloorPrice updates the floor price of a collection
func (tt *Syn721TokenTracker) updateCollectionFloorPrice(collectionName string) {
	collection, exists := tt.collections[collectionName]
	if !exists {
		return
	}

	minValue := float64(0)
	for i, tokenID := range collection.Tokens {
		token := tt.tokens[tokenID]
		if i == 0 || token.Valuation.Value < minValue {
			minValue = token.Valuation.Value
		}
	}

	collection.FloorPrice = minValue
	collection.Currency = tt.tokens[collection.Tokens[0]].Valuation.Currency
	tt.collections[collectionName] = collection
}
