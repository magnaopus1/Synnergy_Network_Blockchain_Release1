package syn4900

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// AgriculturalToken represents tangible or intangible agricultural assets on the blockchain.
type AgriculturalToken struct {
    TokenID         string    `json:"tokenId"`
    AssetType       string    `json:"assetType"`        // Type of agricultural asset (e.g., land, produce, livestock)
    Quantity        float64   `json:"quantity"`         // Quantity of the asset
    Owner           string    `json:"owner"`            // Current owner of the asset
    Origin          string    `json:"origin"`           // Geographic origin of the asset
    HarvestDate     time.Time `json:"harvestDate"`      // Date of harvest for produce
    ExpiryDate      time.Time `json:"expiryDate"`       // Expiry date for perishable goods
    Status          string    `json:"status"`           // Current status of the token (active, traded, expired)
    Certification   string    `json:"certification"`    // Certification details, if applicable
    TransactionHistory []Transaction `json:"transactionHistory"` // History of all transactions
}

// Transaction details related to the transfer or modification of tokens.
type Transaction struct {
    TransactionID   string    `json:"transactionId"`
    Timestamp       time.Time `json:"timestamp"`
    From            string    `json:"from"`
    To              string    `json:"to"`
    Quantity        float64   `json:"quantity"`
    Description     string    `json:"description"`
}

// AgriculturalRegistry manages all agricultural tokens, facilitating tracking and transactions.
type AgriculturalRegistry struct {
    Tokens map[string]*AgriculturalToken
    mutex  sync.Mutex
}

// NewAgriculturalRegistry creates a new registry to manage agricultural tokens.
func NewAgriculturalRegistry() *AgriculturalRegistry {
    return &AgriculturalRegistry{
        Tokens: make(map[string]*AgriculturalToken),
    }
}

// GenerateTokenID creates a unique identifier for an agricultural token.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateAgriculturalToken registers a new agricultural token in the system.
func (r *AgriculturalRegistry) CreateAgriculturalToken(assetType string, quantity float64, owner, origin, certification string, harvestDate, expiryDate time.Time) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    token := &AgriculturalToken{
        TokenID:       tokenID,
        AssetType:     assetType,
        Quantity:      quantity,
        Owner:         owner,
        Origin:        origin,
        HarvestDate:   harvestDate,
        ExpiryDate:    expiryDate,
        Status:        "active",
        Certification: certification,
        TransactionHistory: []Transaction{},
    }

    r.Tokens[tokenID] = token
    return tokenID, nil
}

// UpdateTokenStatus changes the status of an agricultural token.
func (r *AgriculturalRegistry) UpdateTokenStatus(tokenID, status string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("agricultural token not found")
    }

    token.Status = status
    return nil
}

// RecordTransaction logs a transaction affecting the agricultural token.
func (r *AgriculturalRegistry) RecordTransaction(tokenID, from, to string, quantity float64, description string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("agricultural token not found")
    }

    transactionID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d", from, to, time.Now().UnixNano()))))
    transaction := Transaction{
        TransactionID:   transactionID,
        Timestamp:       time.Now(),
        From:            from,
        To:              to,
        Quantity:        quantity,
        Description:     description,
    }

    token.TransactionHistory = append(token.TransactionHistory, transaction)
    return nil
}

// GetTokenDetails retrieves details for a specific agricultural token, including its transaction history.
func (r *AgriculturalRegistry) GetTokenDetails(tokenID string) (*AgriculturalToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("agricultural token not found: %s", tokenID)
    }

    return token, nil
}
