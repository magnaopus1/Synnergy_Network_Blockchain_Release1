package factory

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/tokens/token_standards/syn721/assets"
)

// TokenFactory is responsible for creating and managing SYN721 tokens
type TokenFactory struct {
	tokenTracker *assets.Syn721TokenTracker
	mutex        sync.Mutex
}

// NewTokenFactory initializes a new TokenFactory
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{
		tokenTracker: assets.NewSyn721TokenTracker(),
	}
}

// CreateToken creates a new SYN721 token and adds it to the token tracker
func (tf *TokenFactory) CreateToken(id, owner, collection, name, description, image string, attributes map[string]interface{}, value float64, currency, appraisedBy string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	metadata := assets.Metadata{
		Name:        name,
		Description: description,
		Image:       image,
		Attributes:  attributes,
	}

	initialValuation := assets.Valuation{
		Value:       value,
		Currency:    currency,
		Timestamp:   time.Now(),
		AppraisedBy: appraisedBy,
	}

	err := tf.tokenTracker.AddToken(id, owner, collection, metadata, initialValuation)
	if err != nil {
		return fmt.Errorf("failed to create token: %v", err)
	}

	return nil
}

// UpdateTokenMetadata updates the metadata of an existing SYN721 token
func (tf *TokenFactory) UpdateTokenMetadata(id, name, description, image string, attributes map[string]interface{}) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	metadata := assets.Metadata{
		Name:        name,
		Description: description,
		Image:       image,
		Attributes:  attributes,
	}

	err := tf.tokenTracker.UpdateTokenMetadata(id, metadata)
	if err != nil {
		return fmt.Errorf("failed to update token metadata: %v", err)
	}

	return nil
}

// UpdateTokenValuation updates the valuation of an existing SYN721 token
func (tf *TokenFactory) UpdateTokenValuation(id string, value float64, currency, appraisedBy string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	newValuation := assets.Valuation{
		Value:       value,
		Currency:    currency,
		Timestamp:   time.Now(),
		AppraisedBy: appraisedBy,
	}

	err := tf.tokenTracker.UpdateTokenValuation(id, newValuation)
	if err != nil {
		return fmt.Errorf("failed to update token valuation: %v", err)
	}

	return nil
}

// TransferTokenOwnership transfers the ownership of a SYN721 token
func (tf *TokenFactory) TransferTokenOwnership(id, newOwner string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	err := tf.tokenTracker.TransferOwnership(id, newOwner)
	if err != nil {
		return fmt.Errorf("failed to transfer token ownership: %v", err)
	}

	return nil
}

// AddFractionalOwner adds a fractional owner to a SYN721 token
func (tf *TokenFactory) AddFractionalOwner(id, owner string, percentage float64) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	err := tf.tokenTracker.AddFractionalOwner(id, owner, percentage)
	if err != nil {
		return fmt.Errorf("failed to add fractional owner: %v", err)
	}

	return nil
}

// CreateCollection creates a new collection
func (tf *TokenFactory) CreateCollection(name, owner string) error {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	err := tf.tokenTracker.CreateCollection(name, owner)
	if err != nil {
		return fmt.Errorf("failed to create collection: %v", err)
	}

	return nil
}

// GetToken retrieves a SYN721 token by its ID
func (tf *TokenFactory) GetToken(id string) (assets.Syn721Token, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	token, err := tf.tokenTracker.GetToken(id)
	if err != nil {
		return assets.Syn721Token{}, fmt.Errorf("failed to get token: %v", err)
	}

	return token, nil
}

// GetOwnershipHistory retrieves the ownership history of a SYN721 token
func (tf *TokenFactory) GetOwnershipHistory(id string) ([]assets.OwnershipChange, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	history, err := tf.tokenTracker.GetOwnershipHistory(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get ownership history: %v", err)
	}

	return history, nil
}

// GetValuationHistory retrieves the valuation history of a SYN721 token
func (tf *TokenFactory) GetValuationHistory(id string) ([]assets.ValuationChange, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	history, err := tf.tokenTracker.GetValuationHistory(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get valuation history: %v", err)
	}

	return history, nil
}

// GetCollection retrieves a collection by its name
func (tf *TokenFactory) GetCollection(name string) (assets.Collection, error) {
	tf.mutex.Lock()
	defer tf.mutex.Unlock()

	collection, err := tf.tokenTracker.GetCollection(name)
	if err != nil {
		return assets.Collection{}, fmt.Errorf("failed to get collection: %v", err)
	}

	return collection, nil
}

