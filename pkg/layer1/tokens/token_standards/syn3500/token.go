package syn3500

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// CurrencyToken represents a stablecoin or fiat currency token on the blockchain.
type CurrencyToken struct {
    TokenID         string    `json:"tokenId"`
    CurrencyCode    string    `json:"currencyCode"` // ISO currency code, e.g., USD, EUR, etc.
    Holder          string    `json:"holder"`
    Balance         float64   `json:"balance"`
    IssuedDate      time.Time `json:"issuedDate"`
    AuditTrail      []TransactionRecord `json:"auditTrail"`
}

// TransactionRecord stores the history of transactions for audit purposes.
type TransactionRecord struct {
    Timestamp    time.Time `json:"timestamp"`
    Amount       float64   `json:"amount"`
    TransactionType string `json:"transactionType"`
    RelatedTokenID string  `json:"relatedTokenId,omitempty"`
}

// CurrencyRegistry is a structure for managing all tokens within the system.
type CurrencyRegistry struct {
    Tokens map[string]*CurrencyToken
    mutex  sync.Mutex
}

// NewCurrencyRegistry initializes a new currency registry.
func NewCurrencyRegistry() *CurrencyRegistry {
    return &CurrencyRegistry{
        Tokens: make(map[string]*CurrencyToken),
    }
}

// GenerateTokenID creates a secure, random token ID.
func GenerateTokenID() (string, error) {
    bytes := make([]byte, 16) // 128-bit
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// CreateToken issues a new currency token to a user's wallet.
func (r *CurrencyRegistry) CreateToken(currencyCode, holder string, initialBalance float64) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", fmt.Errorf("failed to generate token ID: %v", err)
    }

    if initialBalance < 0 {
        return "", errors.New("initial balance cannot be negative")
    }

    token := &CurrencyToken{
        TokenID:     tokenID,
        CurrencyCode: currencyCode,
        Holder:      holder,
        Balance:     initialBalance,
        IssuedDate:  time.Now(),
        AuditTrail:  []TransactionRecord{{time.Now(), initialBalance, "Issue", ""}},
    }

    r.Tokens[tokenID] = token
    return tokenID, nil
}

// Transfer transfers a specified amount from one token to another, recording the transaction.
func (r *CurrencyRegistry) Transfer(fromTokenID, toTokenID string, amount float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    fromToken, ok := r.Tokens[fromTokenID]
    if !ok {
        return errors.New("source token does not exist")
    }
    toToken, ok := r.Tokens[toTokenID]
    if !ok {
        return errors.New("destination token does not exist")
    }
    if fromToken.Balance < amount {
        return errors.New("insufficient balance in source token")
    }

    fromToken.Balance -= amount
    toToken.Balance += amount

    fromToken.AuditTrail = append(fromToken.AuditTrail, TransactionRecord{time.Now(), -amount, "Transfer", toTokenID})
    toToken.AuditTrail = append(toToken.AuditTrail, TransactionRecord{time.Now(), amount, "Transfer", fromTokenID})

    return nil
}

// GetTokenDetails retrieves and returns the details of a specific token.
func (r *CurrencyRegistry) GetTokenDetails(tokenID string) (*CurrencyToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("token not found: %s", tokenID)
    }
    return token, nil
}

// UpdateBalance adjusts the balance of a specified token, logging the change.
func (r *CurrencyRegistry) UpdateBalance(tokenID string, newBalance float64) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    if newBalance < 0 {
        return errors.New("balance cannot be negative")
    }
    token, exists := r.Tokens[tokenID]
    if !exists {
        return fmt.Errorf("token not found: %s", tokenID)
    }

    change := newBalance - token.Balance
    token.Balance = newBalance
    token.AuditTrail = append(token.AuditTrail, TransactionRecord{time.Now(), change, "Balance Update", ""})
    return nil
}
