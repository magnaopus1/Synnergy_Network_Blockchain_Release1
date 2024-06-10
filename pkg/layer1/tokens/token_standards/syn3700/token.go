package syn3700

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// IndexToken represents an index or basket of various financial instruments.
type IndexToken struct {
    TokenID         string       `json:"tokenId"`
    IndexName       string       `json:"indexName"`    // Name of the index or basket
    Components      []Component  `json:"components"`   // Components of the index (stocks, bonds, etc.)
    CreationDate    time.Time    `json:"creationDate"`
    MarketValue     float64      `json:"marketValue"`  // Current market value of the entire basket
    Holder          string       `json:"holder"`       // Owner of the token
    LastRebalance   time.Time    `json:"lastRebalance"`// Last rebalance date
}

// Component represents a single asset within an index.
type Component struct {
    AssetID     string  `json:"assetId"`
    Weight      float64 `json:"weight"`      // Target percentage of the asset's total value in the index
    Quantity    float64 `json:"quantity"`    // Quantity of the asset held
}

// IndexRegistry manages all index tokens.
type IndexRegistry struct {
    Tokens map[string]*IndexToken
    mutex  sync.Mutex
}

// NewIndexRegistry creates a new registry for managing index tokens.
func NewIndexRegistry() *IndexRegistry {
    return &IndexRegistry{
        Tokens: make(map[string]*IndexToken),
    }
}

// GenerateTokenID creates a secure, unique token ID.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateIndexToken issues a new index token.
func (r *IndexRegistry) CreateIndexToken(indexName string, components []Component, holder string) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    marketValue := calculateMarketValue(components)
    indexToken := &IndexToken{
        TokenID:       tokenID,
        IndexName:     indexName,
        Components:    components,
        CreationDate:  time.Now(),
        MarketValue:   marketValue,
        Holder:        holder,
        LastRebalance: time.Now(),
    }

    r.Tokens[tokenID] = indexToken
    return tokenID, nil
}

// UpdateIndexToken adjusts the composition or weights of the index token.
func (r *IndexRegistry) UpdateIndexToken(tokenID string, components []Component) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    indexToken, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("index token not found")
    }

    indexToken.Components = components
    indexToken.MarketValue = calculateMarketValue(components)
    indexToken.LastRebalance = time.Now()
    return nil
}

// GetIndexDetails retrieves the details of a specific index token.
func (r *IndexRegistry) GetIndexDetails(tokenID string) (*IndexToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    indexToken, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("index token not found: %s", tokenID)
    }

    return indexToken, nil
}

// calculateMarketValue computes the total market value of the index based on its components.
func calculateMarketValue(components []Component) float64 {
    var marketValue float64
    for _, component := range components {
        marketValue += component.Weight * component.Quantity // Simplified market value calculation
    }
    return marketValue
}
