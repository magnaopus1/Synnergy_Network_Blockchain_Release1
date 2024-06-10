package syn5000

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// GamblingToken represents digital assets used in gambling, betting, or gaming.
type GamblingToken struct {
    TokenID            string    `json:"tokenId"`
    GameType           string    `json:"gameType"`           // Type of game (e.g., poker, sports betting, roulette)
    Amount             float64   `json:"amount"`             // Token amount for betting
    Owner              string    `json:"owner"`              // Owner of the token
    IssuedDate         time.Time `json:"issuedDate"`         // When the token was issued
    ExpiryDate         time.Time `json:"expiryDate"`         // When the token expires
    Active             bool      `json:"active"`             // Whether the token is currently active
    TransactionHistory []Transaction `json:"transactionHistory"` // Transaction history for this token
    SecureHash         string    `json:"secureHash"`         // Security hash to verify token integrity
}

// Transaction records details about token transactions.
type Transaction struct {
    TransactionID string    `json:"transactionId"`
    Timestamp     time.Time `json:"timestamp"`
    Amount        float64   `json:"amount"`
    Description   string    `json:"description"`
    SecureHash    string    `json:"secureHash"` // Hash to ensure transaction integrity
}

// GamblingRegistry manages gambling tokens across various games and platforms.
type GamblingRegistry struct {
    Tokens map[string]*GamblingToken
    mutex  sync.Mutex
}

// NewGamblingRegistry initializes a new registry for managing gambling tokens.
func NewGamblingRegistry() *GamblingRegistry {
    return &GamblingRegistry{
        Tokens: make(map[string]*GamblingToken),
    }
}

// GenerateTokenID creates a unique identifier for a gambling token.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateToken issues a new gambling token.
func (r *GamblingRegistry) CreateToken(gameType string, amount float64, owner string, expiryDate time.Time) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    secureHash := generateSecureHash(tokenID, owner, amount)

    token := &GamblingToken{
        TokenID:            tokenID,
        GameType:           gameType,
        Amount:             amount,
        Owner:              owner,
        IssuedDate:         time.Now(),
        ExpiryDate:         expiryDate,
        Active:             true,
        TransactionHistory: []Transaction{},
        SecureHash:         secureHash,
    }

    r.Tokens[tokenID] = token
    return tokenID, nil
}

// UpdateTokenStatus activates or deactivates a token.
func (r *GamblingRegistry) UpdateTokenStatus(tokenID string, active bool) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("gambling token not found")
    }

    token.Active = active
    return nil
}

// RecordTransaction logs a transaction for a gambling token.
func (r *GamblingRegistry) RecordTransaction(tokenID, description string, amount float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("gambling token not found")
    }

    transactionID := fmt.Sprintf("%s-%d", tokenID, time.Now().UnixNano())
    secureHash := generateSecureHash(transactionID, token.Owner, amount)

    transaction := Transaction{
        TransactionID: transactionID,
        Timestamp:     time.Now(),
        Amount:        amount,
        Description:   description,
        SecureHash:    secureHash,
    }

    token.TransactionHistory = append(token.TransactionHistory, transaction)
    return nil
}

// GetTokenDetails retrieves details and transaction history of a gambling token.
func (r *GamblingRegistry) GetTokenDetails(tokenID string) (*GamblingToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("gambling token not found: %s", tokenID)
    }

    return token, nil
}

// generateSecureHash creates a hash from token data to ensure integrity.
func generateSecureHash(data ...interface{}) string {
    hash := sha256.New()
    for _, d := range data {
        hash.Write([]byte(fmt.Sprint(d)))
    }
    return hex.EncodeToString(hash.Sum(nil))
}
