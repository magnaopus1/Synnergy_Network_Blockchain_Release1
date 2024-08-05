package token_support

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/scrypt"
)

// UniversalToken represents a universal token with its details
type UniversalToken struct {
	Symbol     string
	Name       string
	Decimals   int
	TotalSupply decimal.Decimal
	Address    common.Address
}

// TokenManager manages universal tokens
type TokenManager struct {
	Tokens map[string]UniversalToken
	Lock   sync.Mutex
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager() *TokenManager {
	return &TokenManager{
		Tokens: make(map[string]UniversalToken),
	}
}

// AddUniversalToken adds a new universal token to the manager
func (tm *TokenManager) AddUniversalToken(symbol, name string, decimals int, totalSupply decimal.Decimal, address common.Address) error {
	tm.Lock.Lock()
	defer tm.Lock.Unlock()

	if _, exists := tm.Tokens[symbol]; exists {
		return errors.New("universal token already exists")
	}

	token := UniversalToken{
		Symbol:     symbol,
		Name:       name,
		Decimals:   decimals,
		TotalSupply: totalSupply,
		Address:    address,
	}

	tm.Tokens[symbol] = token
	return nil
}

// RemoveUniversalToken removes a universal token from the manager
func (tm *TokenManager) RemoveUniversalToken(symbol string) error {
	tm.Lock.Lock()
	defer tm.Lock.Unlock()

	if _, exists := tm.Tokens[symbol]; !exists {
		return errors.New("universal token not found")
	}

	delete(tm.Tokens, symbol)
	return nil
}

// GetUniversalToken retrieves a universal token by its symbol
func (tm *TokenManager) GetUniversalToken(symbol string) (UniversalToken, error) {
	tm.Lock.Lock()
	defer tm.Lock.Unlock()

	token, exists := tm.Tokens[symbol]
	if !exists {
		return UniversalToken{}, errors.New("universal token not found")
	}

	return token, nil
}

// ListAllUniversalTokens lists all universal tokens managed by the TokenManager
func (tm *TokenManager) ListAllUniversalTokens() []UniversalToken {
	tm.Lock.Lock()
	defer tm.Lock.Unlock()

	tokens := []UniversalToken{}
	for _, token := range tm.Tokens {
		tokens = append(tokens, token)
	}
	return tokens
}

// TransferToken transfers tokens from one address to another
func (tm *TokenManager) TransferToken(symbol string, from common.Address, to common.Address, amount decimal.Decimal) error {
	tm.Lock.Lock()
	defer tm.Lock.Unlock()

	token, exists := tm.Tokens[symbol]
	if !exists {
		return errors.New("universal token not found")
	}

	// Simulate balance checking and transfer
	// In a real-world scenario, this would interact with a blockchain smart contract
	fromBalance := tm.getBalance(symbol, from)
	toBalance := tm.getBalance(symbol, to)

	if fromBalance.LessThan(amount) {
		return errors.New("insufficient balance")
	}

	fromBalance = fromBalance.Sub(amount)
	toBalance = toBalance.Add(amount)

	// Update balances
	tm.setBalance(symbol, from, fromBalance)
	tm.setBalance(symbol, to, toBalance)

	return nil
}

// getBalance simulates getting the balance of an address for a token
func (tm *TokenManager) getBalance(symbol string, address common.Address) decimal.Decimal {
	// In a real-world scenario, this would interact with a blockchain smart contract
	// For simulation purposes, return a fixed balance
	return decimal.NewFromInt(1000)
}

// setBalance simulates setting the balance of an address for a token
func (tm *TokenManager) setBalance(symbol string, address common.Address, balance decimal.Decimal) {
	// In a real-world scenario, this would interact with a blockchain smart contract
	// For simulation purposes, this function does nothing
}

// generateSalt generates a random salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// hashPassword hashes a password using scrypt with a salt
func hashPassword(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

// generateTokenID generates a unique token ID
func generateTokenID(name string, address common.Address) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s-%s", name, address.Hex(), hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}
