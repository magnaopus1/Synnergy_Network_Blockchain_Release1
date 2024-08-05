// escrow_mechanisms.go

package betting_management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// EscrowAccount represents an escrow account holding funds for a specific bet
type EscrowAccount struct {
	AccountID     string    // Unique identifier for the escrow account
	TokenID       string    // Token identifier associated with the bet
	Bettor        string    // Identifier for the bettor (e.g., wallet address)
	BetAmount     float64   // Amount held in escrow
	CreationTime  time.Time // Time when the escrow was created
	ReleaseTime   time.Time // Time when the funds are released
	Status        string    // Status of the escrow account (pending/released/disputed)
	SecureHash    string    // Secure hash for verifying escrow integrity
}

// EscrowStatus constants
const (
	EscrowPending   = "pending"
	EscrowReleased  = "released"
	EscrowDisputed  = "disputed"
)

// EscrowManager manages escrow accounts for bets
type EscrowManager struct {
	mu            sync.RWMutex
	escrowAccounts map[string]*EscrowAccount // In-memory storage of escrow accounts
}

// NewEscrowManager creates a new instance of EscrowManager
func NewEscrowManager() *EscrowManager {
	return &EscrowManager{
		escrowAccounts: make(map[string]*EscrowAccount),
	}
}

// CreateEscrowAccount creates a new escrow account for a bet
func (em *EscrowManager) CreateEscrowAccount(tokenID, bettor string, betAmount float64) (*EscrowAccount, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Validate inputs
	if betAmount <= 0 {
		return nil, errors.New("invalid bet amount")
	}

	// Generate unique AccountID and secure hash
	accountID := generateUniqueID()
	creationTime := time.Now()
	secureHash := generateEscrowSecureHash(accountID, tokenID, bettor, betAmount, creationTime, EscrowPending)

	// Create the EscrowAccount instance
	escrowAccount := &EscrowAccount{
		AccountID:    accountID,
		TokenID:      tokenID,
		Bettor:       bettor,
		BetAmount:    betAmount,
		CreationTime: creationTime,
		Status:       EscrowPending,
		SecureHash:   secureHash,
	}

	// Store the escrow account
	em.escrowAccounts[accountID] = escrowAccount

	return escrowAccount, nil
}

// ReleaseEscrow releases the funds held in escrow after the bet is settled
func (em *EscrowManager) ReleaseEscrow(accountID string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	escrowAccount, exists := em.escrowAccounts[accountID]
	if !exists {
		return errors.New("escrow account not found")
	}

	if escrowAccount.Status != EscrowPending {
		return errors.New("escrow cannot be released in its current state")
	}

	// Release the escrow funds
	escrowAccount.Status = EscrowReleased
	escrowAccount.ReleaseTime = time.Now()
	escrowAccount.SecureHash = generateEscrowSecureHash(escrowAccount.AccountID, escrowAccount.TokenID, escrowAccount.Bettor, escrowAccount.BetAmount, escrowAccount.CreationTime, escrowAccount.Status)

	// Update the escrow account in storage
	em.escrowAccounts[accountID] = escrowAccount

	return nil
}

// DisputeEscrow marks an escrow as disputed, preventing funds release
func (em *EscrowManager) DisputeEscrow(accountID string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	escrowAccount, exists := em.escrowAccounts[accountID]
	if !exists {
		return errors.New("escrow account not found")
	}

	if escrowAccount.Status != EscrowPending {
		return errors.New("only pending escrows can be disputed")
	}

	// Mark the escrow as disputed
	escrowAccount.Status = EscrowDisputed
	escrowAccount.SecureHash = generateEscrowSecureHash(escrowAccount.AccountID, escrowAccount.TokenID, escrowAccount.Bettor, escrowAccount.BetAmount, escrowAccount.CreationTime, escrowAccount.Status)

	// Update the escrow account in storage
	em.escrowAccounts[accountID] = escrowAccount

	return nil
}

// GetEscrowAccount retrieves an escrow account's details by its ID
func (em *EscrowManager) GetEscrowAccount(accountID string) (*EscrowAccount, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	escrowAccount, exists := em.escrowAccounts[accountID]
	if !exists {
		return nil, errors.New("escrow account not found")
	}

	return escrowAccount, nil
}

// generateUniqueID generates a unique identifier for escrow accounts using Argon2
func generateUniqueID() string {
	return hex.EncodeToString(sha256.New().Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))
}

// generateEscrowSecureHash generates a secure hash for escrow account verification
func generateEscrowSecureHash(accountID, tokenID, bettor string, betAmount float64, creationTime time.Time, status string) string {
	hash := sha256.New()
	hash.Write([]byte(accountID))
	hash.Write([]byte(tokenID))
	hash.Write([]byte(bettor))
	hash.Write([]byte(fmt.Sprintf("%f", betAmount)))
	hash.Write([]byte(creationTime.String()))
	hash.Write([]byte(status))
	return hex.EncodeToString(hash.Sum(nil))
}
