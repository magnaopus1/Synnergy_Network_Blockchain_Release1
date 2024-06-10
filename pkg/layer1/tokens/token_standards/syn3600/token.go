package syn3600

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// FutureToken represents a futures contract for commodities, currencies, or other financial instruments.
type FutureToken struct {
    TokenID          string    `json:"tokenId"`
    Asset            string    `json:"asset"`            // Asset underlying the future (e.g., Gold, Oil, EURUSD)
    Quantity         float64   `json:"quantity"`         // Amount of the asset in the contract
    StrikePrice      float64   `json:"strikePrice"`      // Price per unit of asset agreed upon
    ExpiryDate       time.Time `json:"expiryDate"`       // When the contract expires
    Holder           string    `json:"holder"`           // Who holds the contract
    IssuedDate       time.Time `json:"issuedDate"`       // When the contract was issued
    Settled          bool      `json:"settled"`          // Whether the contract has been settled
    SettlementPrice  float64   `json:"settlementPrice"`  // Price at which the contract was settled
    MarketConditions string    `json:"marketConditions"` // Description of market conditions at settlement
}

// FuturesRegistry handles the lifecycle of all futures tokens.
type FuturesRegistry struct {
    Tokens map[string]*FutureToken
    mutex  sync.Mutex
}

// NewFuturesRegistry initializes a new registry for futures tokens.
func NewFuturesRegistry() *FuturesRegistry {
    return &FuturesRegistry{
        Tokens: make(map[string]*FutureToken),
    }
}

// GenerateTokenID creates a unique identifier for a future token.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit random ID
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateFutureToken creates a new futures contract token.
func (fr *FuturesRegistry) CreateFutureToken(asset string, quantity, strikePrice float64, expiryDate time.Time, holder string) (string, error) {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    if quantity <= 0 {
        return "", errors.New("quantity must be positive")
    }

    future := &FutureToken{
        TokenID:      tokenID,
        Asset:        asset,
        Quantity:     quantity,
        StrikePrice:  strikePrice,
        ExpiryDate:   expiryDate,
        Holder:       holder,
        IssuedDate:   time.Now(),
        Settled:      false,
    }

    fr.Tokens[tokenID] = future
    return tokenID, nil
}

// SettleFuture marks a future as settled, records the settlement price, and optionally the market conditions.
func (fr *FuturesRegistry) SettleFuture(tokenID string, settlementPrice float64, marketConditions string) error {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    future, exists := fr.Tokens[tokenID]
    if !exists {
        return errors.New("future token not found")
    }

    if future.Settled {
        return errors.New("future already settled")
    }

    future.SettlementPrice = settlementPrice
    future.MarketConditions = marketConditions
    future.Settled = true
    return nil
}

// GetFutureDetails retrieves details for a specified futures token.
func (fr *FuturesRegistry) GetFutureDetails(tokenID string) (*FutureToken, error) {
    fr.mutex.Lock()
    defer fr.mutex.Unlock()

    future, exists := fr.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("future token not found: %s", tokenID)
    }

    return future, nil
}
