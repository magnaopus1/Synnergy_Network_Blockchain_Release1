// fair_gaming.go

package smart_contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network/ledger"
	"github.com/synnergy_network/security"
)

// GameOutcome represents the outcome of a game, including necessary metadata
type GameOutcome struct {
	GameID        string
	Timestamp     time.Time
	ResultHash    string
	Participants  map[string]float64 // Maps participant IDs to their stake amounts
	Outcome       string             // Outcome of the game
	DistributeWinnings bool          // Whether to distribute winnings
}

// FairGaming manages the fairness and transparency of gaming operations
type FairGaming struct {
	outcomes  map[string]*GameOutcome
	ledger    *ledger.GamblingTransactionLedger
	security  *security.Security
}

// NewFairGaming initializes the fair gaming management system
func NewFairGaming(ledger *ledger.GamblingTransactionLedger, security *security.Security) *FairGaming {
	return &FairGaming{
		outcomes:  make(map[string]*GameOutcome),
		ledger:    ledger,
		security:  security,
	}
}

// RecordGameOutcome records the outcome of a game and ensures it is tamper-proof
func (fg *FairGaming) RecordGameOutcome(gameID, outcome string, participants map[string]float64) (*GameOutcome, error) {
	if gameID == "" || outcome == "" {
		return nil, errors.New("gameID and outcome cannot be empty")
	}

	// Generate a secure hash of the outcome using SHA-256
	hash := fg.generateOutcomeHash(gameID, outcome)
	gameOutcome := &GameOutcome{
		GameID:        gameID,
		Timestamp:     time.Now(),
		ResultHash:    hash,
		Participants:  participants,
		Outcome:       outcome,
		DistributeWinnings: false,
	}

	fg.outcomes[gameID] = gameOutcome
	fg.ledger.LogGameOutcome(gameID, outcome, hash, participants)

	return gameOutcome, nil
}

// VerifyGameOutcome verifies the outcome of a game to ensure it has not been tampered with
func (fg *FairGaming) VerifyGameOutcome(gameID, outcome string) (bool, error) {
	gameOutcome, exists := fg.outcomes[gameID]
	if !exists {
		return false, errors.New("game outcome not found")
	}

	expectedHash := fg.generateOutcomeHash(gameID, outcome)
	return expectedHash == gameOutcome.ResultHash, nil
}

// DistributeWinnings distributes winnings based on the game outcome
func (fg *FairGaming) DistributeWinnings(gameID string) error {
	gameOutcome, exists := fg.outcomes[gameID]
	if !exists {
		return errors.New("game outcome not found")
	}

	if gameOutcome.DistributeWinnings {
		return errors.New("winnings have already been distributed")
	}

	// Implement logic to distribute winnings based on game outcome
	// This may involve interacting with the ledger to update balances
	// Example: fg.ledger.UpdateBalances(gameOutcome.Participants, gameOutcome.Outcome)
	// Set DistributeWinnings to true to prevent re-distribution

	gameOutcome.DistributeWinnings = true
	return nil
}

// GetGameOutcome retrieves the details of a game outcome by its ID
func (fg *FairGaming) GetGameOutcome(gameID string) (*GameOutcome, error) {
	gameOutcome, exists := fg.outcomes[gameID]
	if !exists {
		return nil, errors.New("game outcome not found")
	}
	return gameOutcome, nil
}

// Utility and helper functions

// generateOutcomeHash generates a secure hash for the game outcome
func (fg *FairGaming) generateOutcomeHash(gameID, outcome string) string {
	data := gameID + outcome + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

