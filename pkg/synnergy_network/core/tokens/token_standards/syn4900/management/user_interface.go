// Package management provides functionality for managing user interactions with agricultural tokens in the SYN4900 Token Standard.
package management

import (
	"errors"
	"fmt"
	"time"
	"sync"
)

// TokenManager defines the methods for managing agricultural tokens through the user interface.
type TokenManager struct {
	tokens map[string]AgriculturalToken
	mutex  sync.Mutex
}

// AgriculturalToken represents a tokenized agricultural asset.
type AgriculturalToken struct {
	TokenID       string
	AssetType     string
	Quantity      float64
	Owner         string
	Origin        string
	HarvestDate   time.Time
	ExpiryDate    time.Time
	Status        string
	Certification string
	TransactionHistory []TransactionRecord
}

// TransactionRecord represents a record of a transaction involving an agricultural token.
type TransactionRecord struct {
	TransactionID string
	Timestamp     time.Time
	From          string
	To            string
	Quantity      float64
	Description   string
}

// NewTokenManager initializes and returns a new TokenManager.
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens: make(map[string]AgriculturalToken),
	}
}

// CreateToken allows the creation of a new agricultural token.
func (tm *TokenManager) CreateToken(assetType, owner, origin, certification string, quantity float64, harvestDate, expiryDate time.Time) (AgriculturalToken, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if assetType == "" || owner == "" || origin == "" || quantity <= 0 {
		return AgriculturalToken{}, errors.New("invalid token details")
	}

	tokenID := generateTokenID(assetType, owner, time.Now())
	token := AgriculturalToken{
		TokenID:       tokenID,
		AssetType:     assetType,
		Quantity:      quantity,
		Owner:         owner,
		Origin:        origin,
		HarvestDate:   harvestDate,
		ExpiryDate:    expiryDate,
		Status:        "Active",
		Certification: certification,
		TransactionHistory: []TransactionRecord{},
	}

	tm.tokens[tokenID] = token
	return token, nil
}

// TransferToken allows transferring ownership of a token to another user.
func (tm *TokenManager) TransferToken(tokenID, newOwner string, quantity float64) (AgriculturalToken, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return AgriculturalToken{}, errors.New("token not found")
	}

	if quantity <= 0 || quantity > token.Quantity {
		return AgriculturalToken{}, errors.New("invalid quantity for transfer")
	}

	token.Quantity -= quantity
	newToken := token
	newToken.TokenID = generateTokenID(token.AssetType, newOwner, time.Now())
	newToken.Owner = newOwner
	newToken.Quantity = quantity
	newToken.TransactionHistory = append(newToken.TransactionHistory, TransactionRecord{
		TransactionID: generateTransactionID(tokenID, newOwner, time.Now()),
		Timestamp:     time.Now(),
		From:          token.Owner,
		To:            newOwner,
		Quantity:      quantity,
		Description:   "Transfer",
	})

	tm.tokens[tokenID] = token
	tm.tokens[newToken.TokenID] = newToken

	return newToken, nil
}

// GetToken retrieves the details of a specific agricultural token by its ID.
func (tm *TokenManager) GetToken(tokenID string) (AgriculturalToken, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return AgriculturalToken{}, errors.New("token not found")
	}

	return token, nil
}

// ListTokens returns all agricultural tokens managed by the system.
func (tm *TokenManager) ListTokens() []AgriculturalToken {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tokens := make([]AgriculturalToken, 0)
	for _, token := range tm.tokens {
		tokens = append(tokens, token)
	}

	return tokens
}

// generateTokenID generates a unique ID for an agricultural token.
func generateTokenID(assetType, owner string, createdAt time.Time) string {
	return fmt.Sprintf("%s-%s-%d", assetType, owner, createdAt.Unix())
}

// generateTransactionID generates a unique ID for a transaction.
func generateTransactionID(tokenID, newOwner string, timestamp time.Time) string {
	return fmt.Sprintf("%s-%s-%d", tokenID, newOwner, timestamp.Unix())
}
