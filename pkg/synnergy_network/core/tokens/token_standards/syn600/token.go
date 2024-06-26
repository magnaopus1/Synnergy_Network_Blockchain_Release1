package syn600

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// Token represents the structure of the SYN600 reward token.
type Token struct {
	ID           string    // Unique identifier for the token
	Owner        string    // Owner's wallet address
	Balance      float64   // Current balance of the token
	CreatedAt    time.Time // Creation timestamp
	ExpiresAt    time.Time // Expiry date to use the token
	Stakeable    bool      // Whether the token can be staked
	StakedAmount float64   // Amount of token that is staked
	mutex        sync.Mutex
}

// TokenPool represents a collective pool of reward tokens.
type TokenPool struct {
	Tokens map[string]*Token
	mutex  sync.Mutex
}

// NewTokenPool initializes a new pool for managing reward tokens.
func NewTokenPool() *TokenPool {
	return &TokenPool{
		Tokens: make(map[string]*Token),
	}
}

// CreateToken issues a new reward token with features like staking and expiration.
func (p *TokenPool) CreateToken(owner string, initialBalance float64, stakeable bool, duration time.Duration) *Token {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	tokenID := generateTokenID(owner, initialBalance)
	token := &Token{
		ID:           tokenID,
		Owner:        owner,
		Balance:      initialBalance,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(duration),
		Stakeable:    stakeable,
		StakedAmount: 0,
	}

	p.Tokens[tokenID] = token
	log.Printf("New reward token created: ID=%s, Owner=%s, Balance=%f, Expires=%s, Stakeable=%t",
		tokenID, owner, initialBalance, token.ExpiresAt, stakeable)
	return token
}

// GenerateTokenID creates a unique ID for each token based on owner and current time.
func generateTokenID(owner string, balance float64) string {
	data := fmt.Sprintf("%s:%f:%d", owner, balance, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Transfer transfers tokens from one owner to another, respecting token expiration.
func (p *TokenPool) Transfer(tokenID, fromOwner, toOwner string, amount float64) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	token, exists := p.Tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("token with ID %s has expired", tokenID)
	}

	if token.Owner != fromOwner {
		return fmt.Errorf("token ownership mismatch: expected %s, got %s", token.Owner, fromOwner)
	}

	if token.Balance < amount {
		return fmt.Errorf("insufficient token balance: available %f, required %f", token.Balance, amount)
	}

	token.Balance -= amount
	log.Printf("Token %s: %f transferred from %s to %s", tokenID, amount, fromOwner, toOwner)

	recipientToken, exists := p.Tokens[toOwner]
	if !exists {
		recipientToken = p.CreateToken(toOwner, amount, token.Stakeable, token.ExpiresAt.Sub(time.Now()))
	} else {
		recipientToken.Balance += amount
	}

	return nil
}

// StakeToken allows staking of tokens if they are stakeable.
func (p *TokenPool) StakeToken(tokenID string, amount float64) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	token, exists := p.Tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	if !token.Stakeable {
		return fmt.Errorf("token with ID %s is not stakeable", tokenID)
	}

	if token.Balance < amount {
		return fmt.Errorf("insufficient token balance: available %f, required %f", token.Balance, amount)
	}

	token.Balance -= amount
	token.StakedAmount += amount
	log.Printf("Token %s: %f staked by %s", tokenID, amount, token.Owner)
	return nil
}

// UnstakeToken releases staked tokens back to the token's balance.
func (p *TokenPool) UnstakeToken(tokenID string, amount float64) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	token, exists := p.Tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	if token.StakedAmount < amount {
		return fmt.Errorf("insufficient staked token balance: staked %f, required %f", token.StakedAmount, amount)
	}

	token.StakedAmount -= amount
	token.Balance += amount
	log.Printf("Token %s: %f unstaked by %s", tokenID, amount, token.Owner)
	return nil
}
