// automated_betting_operations.go

package betting_management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Bet represents a single betting instance with associated metadata
type Bet struct {
	BetID           string    // Unique identifier for the bet
	TokenID         string    // Token identifier associated with the bet
	Bettor          string    // Identifier for the bettor (e.g., wallet address)
	BetAmount       float64   // Amount wagered
	Odds            float64   // Betting odds
	PotentialPayout float64   // Potential payout based on the odds
	PlacedTime      time.Time // Time when the bet was placed
	ResultTime      time.Time // Time when the result is determined
	Result          string    // Result of the bet (win/loss/pending)
	SecureHash      string    // Secure hash for verifying bet integrity
}

// BetResult constants
const (
	BetWin    = "win"
	BetLoss   = "loss"
	BetPending = "pending"
)

// BetManager manages all betting operations, including bet placement and results
type BetManager struct {
	mu    sync.RWMutex
	bets  map[string]*Bet // In-memory storage of bets
}

// NewBetManager creates a new instance of BetManager
func NewBetManager() *BetManager {
	return &BetManager{
		bets: make(map[string]*Bet),
	}
}

// PlaceBet places a new bet, calculates the potential payout, and stores the bet details
func (bm *BetManager) PlaceBet(tokenID, bettor string, betAmount, odds float64) (*Bet, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Validate inputs
	if betAmount <= 0 || odds <= 0 {
		return nil, errors.New("invalid bet amount or odds")
	}

	// Generate unique BetID and secure hash
	betID := generateUniqueID()
	placedTime := time.Now()
	potentialPayout := betAmount * odds
	secureHash := generateBetSecureHash(betID, tokenID, bettor, betAmount, odds, placedTime, BetPending)

	// Create the Bet instance
	bet := &Bet{
		BetID:           betID,
		TokenID:         tokenID,
		Bettor:          bettor,
		BetAmount:       betAmount,
		Odds:            odds,
		PotentialPayout: potentialPayout,
		PlacedTime:      placedTime,
		Result:          BetPending,
		SecureHash:      secureHash,
	}

	// Store the bet
	bm.bets[betID] = bet

	return bet, nil
}

// SettleBet settles a bet by setting the result and calculating the final payout
func (bm *BetManager) SettleBet(betID, result string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bet, exists := bm.bets[betID]
	if !exists {
		return errors.New("bet not found")
	}

	// Settle the bet with the provided result
	if result != BetWin && result != BetLoss {
		return errors.New("invalid bet result")
	}
	bet.Result = result
	bet.ResultTime = time.Now()
	bet.SecureHash = generateBetSecureHash(bet.BetID, bet.TokenID, bet.Bettor, bet.BetAmount, bet.Odds, bet.PlacedTime, bet.Result)

	// Update the bet in the storage
	bm.bets[betID] = bet

	return nil
}

// GetBet retrieves a bet's details by its ID
func (bm *BetManager) GetBet(betID string) (*Bet, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	bet, exists := bm.bets[betID]
	if !exists {
		return nil, errors.New("bet not found")
	}

	return bet, nil
}

// generateUniqueID generates a unique identifier for bets using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateBetSecureHash generates a secure hash for bet verification
func generateBetSecureHash(betID, tokenID, bettor string, betAmount, odds float64, placedTime time.Time, result string) string {
	hash := sha256.New()
	hash.Write([]byte(betID))
	hash.Write([]byte(tokenID))
	hash.Write([]byte(bettor))
	hash.Write([]byte(fmt.Sprintf("%f", betAmount)))
	hash.Write([]byte(fmt.Sprintf("%f", odds)))
	hash.Write([]byte(placedTime.String()))
	hash.Write([]byte(result))
	return hex.EncodeToString(hash.Sum(nil))
}
