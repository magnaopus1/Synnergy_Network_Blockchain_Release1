package assets

import (
	"fmt"
	"sync"
	"time"
)

// Metadata represents the metadata associated with a SYN721 token
type Metadata struct {
	Name        string
	Description string
	Image       string
	Attributes  map[string]string
}

// Syn721Token represents a SYN721 token with its metadata and ownership details
type Syn721Token struct {
	ID          string
	Owner       string
	Metadata    Metadata
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// OwnershipChange represents a change in the ownership of a SYN721 token
type OwnershipChange struct {
	Timestamp time.Time
	From      string
	To        string
}

// Syn721TokenTracker manages SYN721 tokens and tracks their ownership and metadata
type Syn721TokenTracker struct {
	tokens            map[string]Syn721Token
	ownershipHistories map[string][]OwnershipChange
	mutex             sync.Mutex
}

// NewSyn721TokenTracker initializes a new Syn721TokenTracker
func NewSyn721TokenTracker() *Syn721TokenTracker {
	return &Syn721TokenTracker{
		tokens:            make(map[string]Syn721Token),
		ownershipHistories: make(map[string][]OwnershipChange),
	}
}

// AddToken adds a new token to the tracker
func (tt *Syn721TokenTracker) AddToken(id, owner string, metadata Metadata) error {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	if _, exists := tt.tokens[id]; exists {
		return fmt.Errorf("token with ID %s already exists", id)
	}

	token := Syn721Token{
		ID:        id,
		Owner:     owner,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tt.tokens[id] = token
	tt.ownershipHistories[id] = []OwnershipChange{
		{
			Timestamp: time.Now(),
			From:      "",
			To:        owner,
		},
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
