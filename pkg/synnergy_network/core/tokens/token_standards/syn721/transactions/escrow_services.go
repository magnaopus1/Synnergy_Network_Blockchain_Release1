package transactions

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// EscrowStatus represents the status of an escrow
type EscrowStatus string

const (
	Pending   EscrowStatus = "pending"
	Completed EscrowStatus = "completed"
	Cancelled EscrowStatus = "cancelled"
)

// Escrow represents an escrow transaction for SYN721 tokens
type Escrow struct {
	TokenID    string
	Seller     string
	Buyer      string
	Amount     float64
	Expiration time.Time
	Status     EscrowStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// EscrowManager manages escrow services for SYN721 tokens
type EscrowManager struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	escrows         map[string]Escrow
	mutex           sync.Mutex
}

// NewEscrowManager initializes a new EscrowManager
func NewEscrowManager(ledger *ledger.Ledger, securityManager *security.SecurityManager) *EscrowManager {
	return &EscrowManager{
		ledger:          ledger,
		securityManager: securityManager,
		escrows:         make(map[string]Escrow),
	}
}

// CreateEscrow creates a new escrow for a SYN721 token
func (em *EscrowManager) CreateEscrow(tokenID, seller, buyer string, amount float64, expiration time.Time) (string, error) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	if _, exists := em.escrows[tokenID]; exists {
		return "", fmt.Errorf("escrow for token ID %s already exists", tokenID)
	}

	escrow := Escrow{
		TokenID:    tokenID,
		Seller:     seller,
		Buyer:      buyer,
		Amount:     amount,
		Expiration: expiration,
		Status:     Pending,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	em.escrows[tokenID] = escrow
	return tokenID, nil
}

// CompleteEscrow completes an escrow transaction, transferring the SYN721 token to the buyer
func (em *EscrowManager) CompleteEscrow(tokenID string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	escrow, exists := em.escrows[tokenID]
	if !exists {
		return fmt.Errorf("escrow for token ID %s not found", tokenID)
	}

	if escrow.Status != Pending {
		return fmt.Errorf("escrow for token ID %s is not pending", tokenID)
	}

	token, err := em.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner != escrow.Seller {
		return fmt.Errorf("current owner of token %s is not the seller", tokenID)
	}

	err = em.ledger.TransferOwnership(tokenID, escrow.Buyer)
	if err != nil {
		return err
	}

	escrow.Status = Completed
	escrow.UpdatedAt = time.Now()
	em.escrows[tokenID] = escrow

	return nil
}

// CancelEscrow cancels an escrow transaction
func (em *EscrowManager) CancelEscrow(tokenID string) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	escrow, exists := em.escrows[tokenID]
	if !exists {
		return fmt.Errorf("escrow for token ID %s not found", tokenID)
	}

	if escrow.Status != Pending {
		return fmt.Errorf("escrow for token ID %s is not pending", tokenID)
	}

	escrow.Status = Cancelled
	escrow.UpdatedAt = time.Now()
	em.escrows[tokenID] = escrow

	return nil
}

// GetEscrow retrieves an escrow by its token ID
func (em *EscrowManager) GetEscrow(tokenID string) (Escrow, error) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	escrow, exists := em.escrows[tokenID]
	if !exists {
		return Escrow{}, fmt.Errorf("escrow for token ID %s not found", tokenID)
	}

	return escrow, nil
}

// ListEscrows lists all escrows
func (em *EscrowManager) ListEscrows() []Escrow {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	var escrows []Escrow
	for _, escrow := range em.escrows {
		escrows = append(escrows, escrow)
	}

	return escrows
}

// ExpireEscrows checks for and expires any pending escrows that have passed their expiration time
func (em *EscrowManager) ExpireEscrows() {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	now := time.Now()
	for tokenID, escrow := range em.escrows {
		if escrow.Status == Pending && escrow.Expiration.Before(now) {
			escrow.Status = Cancelled
			escrow.UpdatedAt = now
			em.escrows[tokenID] = escrow
		}
	}
}
