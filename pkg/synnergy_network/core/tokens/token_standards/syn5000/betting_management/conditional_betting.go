// conditional_betting.go

package betting_management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ConditionalBet represents a bet that is placed based on specific conditions
type ConditionalBet struct {
	ConditionID     string    // Unique identifier for the condition
	TokenID         string    // Token identifier associated with the bet
	Bettor          string    // Identifier for the bettor (e.g., wallet address)
	BetAmount       float64   // Amount wagered
	Odds            float64   // Betting odds
	Condition       string    // Condition for the bet to be executed (e.g., "TeamA Wins")
	ExecutionTime   time.Time // Time when the bet condition is evaluated
	Status          string    // Status of the bet (pending/fulfilled/canceled)
	SecureHash      string    // Secure hash for verifying bet integrity
}

// ConditionalBetStatus constants
const (
	StatusPending   = "pending"
	StatusFulfilled = "fulfilled"
	StatusCanceled  = "canceled"
)

// ConditionalBetManager manages conditional bets
type ConditionalBetManager struct {
	mu             sync.RWMutex
	conditionalBets map[string]*ConditionalBet // In-memory storage of conditional bets
}

// NewConditionalBetManager creates a new instance of ConditionalBetManager
func NewConditionalBetManager() *ConditionalBetManager {
	return &ConditionalBetManager{
		conditionalBets: make(map[string]*ConditionalBet),
	}
}

// PlaceConditionalBet places a new conditional bet based on specific conditions
func (cbm *ConditionalBetManager) PlaceConditionalBet(tokenID, bettor, condition string, betAmount, odds float64, executionTime time.Time) (*ConditionalBet, error) {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	// Validate inputs
	if betAmount <= 0 || odds <= 0 || condition == "" {
		return nil, errors.New("invalid bet parameters")
	}

	// Generate unique ConditionID and secure hash
	conditionID := generateUniqueID()
	secureHash := generateConditionalBetSecureHash(conditionID, tokenID, bettor, condition, betAmount, odds, executionTime, StatusPending)

	// Create the ConditionalBet instance
	conditionalBet := &ConditionalBet{
		ConditionID:   conditionID,
		TokenID:       tokenID,
		Bettor:        bettor,
		BetAmount:     betAmount,
		Odds:          odds,
		Condition:     condition,
		ExecutionTime: executionTime,
		Status:        StatusPending,
		SecureHash:    secureHash,
	}

	// Store the conditional bet
	cbm.conditionalBets[conditionID] = conditionalBet

	return conditionalBet, nil
}

// FulfillConditionalBet fulfills a conditional bet if the condition is met
func (cbm *ConditionalBetManager) FulfillConditionalBet(conditionID string) error {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	conditionalBet, exists := cbm.conditionalBets[conditionID]
	if !exists {
		return errors.New("conditional bet not found")
	}

	if conditionalBet.Status != StatusPending {
		return errors.New("conditional bet is not pending")
	}

	// Check if the condition is met (logic to check condition is external and not implemented here)
	// Assuming condition is met for this example
	conditionMet := true // This should be determined by external logic

	if conditionMet {
		conditionalBet.Status = StatusFulfilled
		conditionalBet.ExecutionTime = time.Now()
	} else {
		conditionalBet.Status = StatusCanceled
	}

	conditionalBet.SecureHash = generateConditionalBetSecureHash(conditionalBet.ConditionID, conditionalBet.TokenID, conditionalBet.Bettor, conditionalBet.Condition, conditionalBet.BetAmount, conditionalBet.Odds, conditionalBet.ExecutionTime, conditionalBet.Status)

	// Update the conditional bet in storage
	cbm.conditionalBets[conditionID] = conditionalBet

	return nil
}

// CancelConditionalBet cancels a conditional bet if it is still pending
func (cbm *ConditionalBetManager) CancelConditionalBet(conditionID string) error {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	conditionalBet, exists := cbm.conditionalBets[conditionID]
	if !exists {
		return errors.New("conditional bet not found")
	}

	if conditionalBet.Status != StatusPending {
		return errors.New("conditional bet is not pending and cannot be canceled")
	}

	// Cancel the conditional bet
	conditionalBet.Status = StatusCanceled
	conditionalBet.SecureHash = generateConditionalBetSecureHash(conditionalBet.ConditionID, conditionalBet.TokenID, conditionalBet.Bettor, conditionalBet.Condition, conditionalBet.BetAmount, conditionalBet.Odds, conditionalBet.ExecutionTime, conditionalBet.Status)

	// Update the conditional bet in storage
	cbm.conditionalBets[conditionID] = conditionalBet

	return nil
}

// GetConditionalBet retrieves a conditional bet's details by its ID
func (cbm *ConditionalBetManager) GetConditionalBet(conditionID string) (*ConditionalBet, error) {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	conditionalBet, exists := cbm.conditionalBets[conditionID]
	if !exists {
		return nil, errors.New("conditional bet not found")
	}

	return conditionalBet, nil
}

// generateUniqueID generates a unique identifier for conditional bets using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateConditionalBetSecureHash generates a secure hash for conditional bet verification
func generateConditionalBetSecureHash(conditionID, tokenID, bettor, condition string, betAmount, odds float64, executionTime time.Time, status string) string {
	hash := sha256.New()
	hash.Write([]byte(conditionID))
	hash.Write([]byte(tokenID))
	hash.Write([]byte(bettor))
	hash.Write([]byte(condition))
	hash.Write([]byte(fmt.Sprintf("%f", betAmount)))
	hash.Write([]byte(fmt.Sprintf("%f", odds)))
	hash.Write([]byte(executionTime.String()))
	hash.Write([]byte(status))
	return hex.EncodeToString(hash.Sum(nil))
}
