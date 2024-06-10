package syn1967

import (
	"errors"
	"fmt"
	"time"
)

// Commodity represents a specific type of commodity.
type Commodity struct {
	Name         string  `json:"name"`         // Name of the commodity, e.g., Gold, Oil
	Unit         string  `json:"unit"`         // Measurement unit, e.g., kilograms, barrels
	PerUnitPrice float64 `json:"perUnitPrice"` // Current price per unit in USD
	Description  string  `json:"description"`  // Description of the commodity for better understanding
}

// Token represents the blockchain representation of a physical commodity.
type Token struct {
	TokenID       string    `json:"tokenId"`       // Unique identifier for the token
	Commodity     Commodity `json:"commodity"`     // Commodity details
	Amount        float64   `json:"amount"`        // Amount of commodity represented by the token
	IssuedDate    time.Time `json:"issuedDate"`    // Date when the token was issued
	Owner         string    `json:"owner"`         // Owner of the token
	Certification string    `json:"certification"` // Certification or standard compliance information
	Traceability  string    `json:"traceability"`  // Information for tracing the commodity's origin
}

// CommodityLedger holds all tokens and provides methods to manage them.
type CommodityLedger struct {
	Tokens map[string]Token
}

// NewCommodityLedger creates a new instance of a CommodityLedger.
func NewCommodityLedger() *CommodityLedger {
	return &CommodityLedger{
		Tokens: make(map[string]Token),
	}
}

// IssueToken creates a new commodity token.
func (cl *CommodityLedger) IssueToken(token Token) error {
	if _, exists := cl.Tokens[token.TokenID]; exists {
		return fmt.Errorf("token with ID %s already exists", token.TokenID)
	}

	token.IssuedDate = time.Now()
	cl.Tokens[token.TokenID] = token
	return nil
}

// TransferToken transfers ownership of a commodity token to a new owner.
func (cl *CommodityLedger) TransferToken(tokenID, newOwner string) error {
	token, exists := cl.Tokens[tokenID]
	if !exists {
		return errors.New("token does not exist")
	}

	token.Owner = newOwner
	cl.Tokens[tokenID] = token
	return nil
}

// GetToken retrieves a token by its ID.
func (cl *CommodityLedger) GetToken(tokenID string) (Token, error) {
	token, exists := cl.Tokens[tokenID]
	if !exists {
		return Token{}, fmt.Errorf("token with ID %s not found", tokenID)
	}
	return token, nil
}

// UpdateMarketPrice updates the price per unit of a commodity.
func (cl *CommodityLedger) UpdateMarketPrice(tokenID string, newPrice float64) error {
	token, exists := cl.Tokens[tokenID]
	if !exists {
		return errors.New("token does not exist")
	}

	token.Commodity.PerUnitPrice = newPrice
	cl.Tokens[tokenID] = token
	return nil
}

// EvaluateTokenValue calculates the current market value of a token based on its commodity amount and per unit price.
func (cl *CommodityLedger) EvaluateTokenValue(tokenID string) (float64, error) {
	token, exists := cl.Tokens[tokenID]
	if !exists {
		return 0, errors.New("token does not exist")
	}

	return token.Amount * token.Commodity.PerUnitPrice, nil
}
