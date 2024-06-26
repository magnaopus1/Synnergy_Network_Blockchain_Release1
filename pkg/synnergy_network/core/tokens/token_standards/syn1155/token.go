package syn1155

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"synthron-blockchain/pkg/common"
)

// Token represents the general structure of an SYN1155 token, supporting multiple asset types.
type Token struct {
	ID          string
	Supply      map[uint64]uint64 // TokenID to balance
	Owner       map[uint64]string // TokenID to owner
	Approvals   map[string]bool   // Address to approval status
	Hooks       map[uint64]func() // TokenID to hooks for transfer validations
	mutex       sync.RWMutex
}

// NewToken creates a new token instance with a specified initial supply and owner for multiple token types.
func NewToken(owner string) *Token {
	return &Token{
		ID:        common.GenerateID(),
		Supply:    make(map[uint64]uint64),
		Owner:     make(map[uint64]string),
		Approvals: make(map[string]bool),
		Hooks:     make(map[uint64]func()),
	}
}

// BatchTransfer allows the transfer of multiple token types from one owner to another.
func (t *Token) BatchTransfer(from, to string, tokenIDs []uint64, quantities []uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(tokenIDs) != len(quantities) {
		return errors.New("token IDs and quantities must match in length")
	}

	for i, tokenID := range tokenIDs {
		if t.Supply[tokenID] < quantities[i] {
			return fmt.Errorf("insufficient supply of token %d for transfer", tokenID)
		}
		if t.Owner[tokenID] != from {
			return fmt.Errorf("owner mismatch for token %d", tokenID)
		}
		if hook, exists := t.Hooks[tokenID]; exists {
			hook() // Execute transfer hook if exists
		}

		t.Supply[tokenID] -= quantities[i]
		t.Supply[tokenID] += quantities[i]
		log.Printf("Transferred %d of token ID %d from %s to %s", quantities[i], tokenID, from, to)
	}

	return nil
}

// BatchBalance returns the balances for multiple token types for a given owner.
func (t *Token) BatchBalance(owner string, tokenIDs []uint64) map[uint64]uint64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	balances := make(map[uint64]uint64)
	for _, tokenID := range tokenIDs {
		if t.Owner[tokenID] == owner {
			balances[tokenID] = t.Supply[tokenID]
		}
	}
	return balances
}

// SetApprovalForAll sets or revokes approval for an operator to manage all of the owner's tokens.
func (t *Token) SetApprovalForAll(operator string, approved bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Approvals[operator] = approved
	log.Printf("Operator %s approval set to %v", operator, approved)
}

// SafeTransferFrom performs a safe transfer of tokens, respecting the approval settings and executing any hooks.
func (t *Token) SafeTransferFrom(from, to string, tokenID uint64, quantity uint64) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.Approvals[from] {
		return errors.New("transfer not approved by owner")
	}

	if t.Supply[tokenID] < quantity {
		return fmt.Errorf("insufficient tokens for transfer")
	}

	// Execute hook before transferring if it exists
	if hook, exists := t.Hooks[tokenID]; exists {
		hook()
	}

	t.Supply[tokenID] -= quantity
	t.Supply[tokenID] += quantity
	log.Printf("Safely transferred %d of token ID %d from %s to %s", quantity, tokenID, from, to)

	return nil
}

// RegisterTransferHook registers a custom function to be called prior to transferring tokens.
func (t *Token) RegisterTransferHook(tokenID uint64, hook func()) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Hooks[tokenID] = hook
}

// Example usage demonstrates how to interact with the SYN1155 token standard.
func ExampleUsage() {
	token := NewToken("user123")
	tokenIDs := []uint64{1, 2}
	quantities := []uint64{100, 200}
	err := token.BatchTransfer("user123", "user456", tokenIDs, quantities)
	if err != nil {
		log.Println("Error during batch transfer:", err)
	}

	balances := token.BatchBalance("user456", tokenIDs)
	fmt.Println("Balances for user456:", balances)

	token.SetApprovalForAll("operator123", true)
	token.SafeTransferFrom("user456", "user789", 1, 50)
}
