package carbon_credit_tokens

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"

    "github.com/pkg/errors"
    "golang.org/x/crypto/scrypt"
)

// CarbonCreditToken represents a token for carbon credits.
type CarbonCreditToken struct {
    ID           string
    IssuedTo     string
    Amount       float64
    IssuedAt     time.Time
    ValidUntil   time.Time
    IsRetired    bool
    Hash         string
}

// NewCarbonCreditToken creates a new carbon credit token.
func NewCarbonCreditToken(issuedTo string, amount float64, validUntil time.Time) (*CarbonCreditToken, error) {
    id, err := generateUniqueID()
    if err != nil {
        return nil, err
    }

    issuedAt := time.Now()

    token := &CarbonCreditToken{
        ID:         id,
        IssuedTo:   issuedTo,
        Amount:     amount,
        IssuedAt:   issuedAt,
        ValidUntil: validUntil,
        IsRetired:  false,
    }

    token.Hash, err = token.calculateHash()
    if err != nil {
        return nil, err
    }

    return token, nil
}

// generateUniqueID generates a unique ID for the carbon credit token.
func generateUniqueID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// calculateHash calculates the hash of the carbon credit token.
func (token *CarbonCreditToken) calculateHash() (string, error) {
    data := fmt.Sprintf("%s%s%f%s%s%t",
        token.ID, token.IssuedTo, token.Amount, token.IssuedAt, token.ValidUntil, token.IsRetired)
    hash, err := scrypt.Key([]byte(data), []byte(token.ID), 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hash), nil
}

// VerifyHash verifies the hash of the carbon credit token.
func (token *CarbonCreditToken) VerifyHash() (bool, error) {
    expectedHash, err := token.calculateHash()
    if err != nil {
        return false, err
    }
    return expectedHash == token.Hash, nil
}

// Retire retires the carbon credit token.
func (token *CarbonCreditToken) Retire() error {
    if token.IsRetired {
        return errors.New("token is already retired")
    }
    token.IsRetired = true
    newHash, err := token.calculateHash()
    if err != nil {
        return err
    }
    token.Hash = newHash
    return nil
}

// Transfer transfers the carbon credit token to a new owner.
func (token *CarbonCreditToken) Transfer(newOwner string) error {
    if token.IsRetired {
        return errors.New("cannot transfer a retired token")
    }
    token.IssuedTo = newOwner
    newHash, err := token.calculateHash()
    if err != nil {
        return err
    }
    token.Hash = newHash
    return nil
}

// Validate checks if the token is still valid based on its expiration date.
func (token *CarbonCreditToken) Validate() (bool, error) {
    if time.Now().After(token.ValidUntil) {
        return false, errors.New("token has expired")
    }
    return true, nil
}

// TokenManagement is responsible for managing carbon credit tokens.
type TokenManagement struct {
    tokens map[string]*CarbonCreditToken
}

// NewTokenManagement creates a new token management instance.
func NewTokenManagement() *TokenManagement {
    return &TokenManagement{
        tokens: make(map[string]*CarbonCreditToken),
    }
}

// IssueToken issues a new carbon credit token.
func (tm *TokenManagement) IssueToken(issuedTo string, amount float64, validUntil time.Time) (*CarbonCreditToken, error) {
    token, err := NewCarbonCreditToken(issuedTo, amount, validUntil)
    if err != nil {
        return nil, err
    }
    tm.tokens[token.ID] = token
    return token, nil
}

// RetireToken retires an existing carbon credit token.
func (tm *TokenManagement) RetireToken(tokenID string) error {
    token, exists := tm.tokens[tokenID]
    if !exists {
        return errors.New("token not found")
    }
    return token.Retire()
}

// TransferToken transfers a token to a new owner.
func (tm *TokenManagement) TransferToken(tokenID string, newOwner string) error {
    token, exists := tm.tokens[tokenID]
    if !exists {
        return errors.New("token not found")
    }
    return token.Transfer(newOwner)
}

// VerifyToken verifies the integrity of a token.
func (tm *TokenManagement) VerifyToken(tokenID string) (bool, error) {
    token, exists := tm.tokens[tokenID]
    if !exists {
        return false, errors.New("token not found")
    }
    return token.VerifyHash()
}

// ValidateToken checks if a token is valid based on its expiration date.
func (tm *TokenManagement) ValidateToken(tokenID string) (bool, error) {
    token, exists := tm.tokens[tokenID]
    if !exists {
        return false, errors.New("token not found")
    }
    return token.Validate()
}

// ListTokens lists all tokens with their details.
func (tm *TokenManagement) ListTokens() []*CarbonCreditToken {
    tokens := make([]*CarbonCreditToken, 0, len(tm.tokens))
    for _, token := range tm.tokens {
        tokens = append(tokens, token)
    }
    return tokens
}

// GetToken retrieves a specific token by ID.
func (tm *TokenManagement) GetToken(tokenID string) (*CarbonCreditToken, error) {
    token, exists := tm.tokens[tokenID]
    if !exists {
        return nil, errors.New("token not found")
    }
    return token, nil
}
