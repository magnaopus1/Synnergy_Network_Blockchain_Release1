package syn130

import (
	"errors"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// AssetToken represents a tangible asset on the Synthron Blockchain.
type AssetToken struct {
	TokenID       string    `json:"token_id"`
	Owner         string    `json:"owner"`
	AssetValue    float64   `json:"asset_value"`
	LastSalePrice float64   `json:"last_sale_price"`
	AssetType     string    `json:"asset_type"`
	Description   string    `json:"description"`
	LeaseTerms    string    `json:"lease_terms"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TokenManager manages SYN130 tokens, facilitating creation, updates, and management.
type TokenManager struct {
	tokens map[string]*AssetToken
	mutex  sync.RWMutex
}

// NewTokenManager initializes a new TokenManager.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens: make(map[string]*AssetToken),
	}
}

// CreateToken creates a new asset token with detailed descriptions and classifications.
func (tm *TokenManager) CreateToken(tokenID, owner, assetType, description, leaseTerms string, assetValue, salePrice float64) (*AssetToken, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.tokens[tokenID]; exists {
		log.Printf("Attempt to create a duplicate token with ID: %s", tokenID)
		return nil, errors.New("token already exists")
	}

	token := &AssetToken{
		TokenID:       tokenID,
		Owner:         owner,
		AssetValue:    assetValue,
		LastSalePrice: salePrice,
		AssetType:     assetType,
		Description:   description,
		LeaseTerms:    leaseTerms,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	tm.tokens[tokenID] = token

	log.Printf("New asset token created: %+v", token)
	return token, nil
}

// UpdateToken updates properties of an existing asset token.
func (tm *TokenManager) UpdateToken(tokenID, newOwner, assetType, description, leaseTerms string, newSalePrice float64) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		log.Printf("Attempt to update a non-existent token with ID: %s", tokenID)
		return errors.New("token does not exist")
	}

	token.Owner = newOwner
	token.LastSalePrice = newSalePrice
	token.AssetType = assetType
	token.Description = description
	token.LeaseTerms = leaseTerms
	token.UpdatedAt = time.Now()

	log.Printf("Asset token updated: %+v", token)
	return nil
}

// GetToken retrieves a token by its ID.
func (tm *TokenManager) GetToken(tokenID string) (*AssetToken, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		log.Printf("Attempt to retrieve a non-existent token with ID: %s", tokenID)
		return nil, errors.New("token does not exist")
	}

	log.Printf("Asset token retrieved: %+v", token)
	return token, nil
}

// DeleteToken removes a token from the manager.
func (tm *TokenManager) DeleteToken(tokenID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.tokens[tokenID]; !exists {
		log.Printf("Attempt to delete a non-existent token with ID: %s", tokenID)
		return errors.New("token does not exist")
	}

	delete(tm.tokens, tokenID)
	log.Printf("Asset token deleted with ID: %s", tokenID)
	return nil
}
