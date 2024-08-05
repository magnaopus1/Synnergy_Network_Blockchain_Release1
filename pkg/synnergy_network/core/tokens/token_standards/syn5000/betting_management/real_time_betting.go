// real_time_betting.go

package betting_management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RealTimeBet represents a bet placed in real-time with dynamic odds
type RealTimeBet struct {
	BetID           string    // Unique identifier for the bet
	TokenID         string    // Token identifier associated with the bet
	Bettor          string    // Identifier for the bettor (e.g., wallet address)
	BetAmount       float64   // Amount wagered
	InitialOdds     float64   // Initial odds at the time of bet placement
	CurrentOdds     float64   // Current odds which may adjust over time
	PotentialPayout float64   // Potential payout based on the current odds
	PlacedTime      time.Time // Time when the bet was placed
	Status          string    // Status of the bet (pending/won/lost)
	SecureHash      string    // Secure hash for verifying bet integrity
}

// RealTimeBetStatus constants
const (
	StatusPending = "pending"
	StatusWon     = "won"
	StatusLost    = "lost"
)

// RealTimeBetManager manages real-time betting operations
type RealTimeBetManager struct {
	mu    sync.RWMutex
	bets  map[string]*RealTimeBet // In-memory storage of real-time bets
	odds  map[string]float64      // In-memory storage of current odds for tokens
}

// NewRealTimeBetManager creates a new instance of RealTimeBetManager
func NewRealTimeBetManager() *RealTimeBetManager {
	return &RealTimeBetManager{
		bets: make(map[string]*RealTimeBet),
		odds: make(map[string]float64),
	}
}

// PlaceRealTimeBet places a new bet with the current odds
func (rtm *RealTimeBetManager) PlaceRealTimeBet(tokenID, bettor string, betAmount float64) (*RealTimeBet, error) {
	rtm.mu.Lock()
	defer rtm.mu.Unlock()

	// Validate inputs
	if betAmount <= 0 {
		return nil, errors.New("invalid bet amount")
	}

	// Get the current odds for the token
	currentOdds, exists := rtm.odds[tokenID]
	if !exists {
		return nil, errors.New("odds not available for the token")
	}

	// Calculate the potential payout
	potentialPayout := betAmount * currentOdds

	// Generate unique BetID and secure hash
	betID := generateUniqueID()
	placedTime := time.Now()
	secureHash := generateRealTimeBetSecureHash(betID, tokenID, bettor, betAmount, currentOdds, placedTime, StatusPending)

	// Create the RealTimeBet instance
	realTimeBet := &RealTimeBet{
		BetID:           betID,
		TokenID:         tokenID,
		Bettor:          bettor,
		BetAmount:       betAmount,
		InitialOdds:     currentOdds,
		CurrentOdds:     currentOdds,
		PotentialPayout: potentialPayout,
		PlacedTime:      placedTime,
		Status:          StatusPending,
		SecureHash:      secureHash,
	}

	// Store the bet
	rtm.bets[betID] = realTimeBet

	return realTimeBet, nil
}

// UpdateOdds updates the odds for a specific token, affecting all associated bets
func (rtm *RealTimeBetManager) UpdateOdds(tokenID string, newOdds float64) error {
	rtm.mu.Lock()
	defer rtm.mu.Unlock()

	if newOdds <= 0 {
		return errors.New("invalid odds value")
	}

	// Update the odds in the storage
	rtm.odds[tokenID] = newOdds

	// Update the current odds for all bets associated with the token
	for _, bet := range rtm.bets {
		if bet.TokenID == tokenID && bet.Status == StatusPending {
			bet.CurrentOdds = newOdds
			bet.PotentialPayout = bet.BetAmount * newOdds
			bet.SecureHash = generateRealTimeBetSecureHash(bet.BetID, bet.TokenID, bet.Bettor, bet.BetAmount, bet.CurrentOdds, bet.PlacedTime, bet.Status)
		}
	}

	return nil
}

// SettleBet sets the result of a bet (won/lost) and updates the status
func (rtm *RealTimeBetManager) SettleBet(betID, result string) error {
	rtm.mu.Lock()
	defer rtm.mu.Unlock()

	bet, exists := rtm.bets[betID]
	if !exists {
		return errors.New("bet not found")
	}

	if bet.Status != StatusPending {
		return errors.New("bet has already been settled")
	}

	if result != StatusWon && result != StatusLost {
		return errors.New("invalid result status")
	}

	// Settle the bet
	bet.Status = result
	bet.SecureHash = generateRealTimeBetSecureHash(bet.BetID, bet.TokenID, bet.Bettor, bet.BetAmount, bet.CurrentOdds, bet.PlacedTime, bet.Status)

	// Update the bet in the storage
	rtm.bets[betID] = bet

	return nil
}

// GetRealTimeBet retrieves the details of a real-time bet by its ID
func (rtm *RealTimeBetManager) GetRealTimeBet(betID string) (*RealTimeBet, error) {
	rtm.mu.RLock()
	defer rtm.mu.RUnlock()

	bet, exists := rtm.bets[betID]
	if !exists {
		return nil, errors.New("bet not found")
	}

	return bet, nil
}

// generateUniqueID generates a unique identifier for real-time bets using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateRealTimeBetSecureHash generates a secure hash for real-time bet verification
func generateRealTimeBetSecureHash(betID, tokenID, bettor string, betAmount, currentOdds float64, placedTime time.Time, status string) string {
	hash := sha256.New()
	hash.Write([]byte(betID))
	hash.Write([]byte(tokenID))
	hash.Write([]byte(bettor))
	hash.Write([]byte(fmt.Sprintf("%f", betAmount)))
	hash.Write([]byte(fmt.Sprintf("%f", currentOdds)))
	hash.Write([]byte(placedTime.String()))
	hash.Write([]byte(status))
	return hex.EncodeToString(hash.Sum(nil))
}
