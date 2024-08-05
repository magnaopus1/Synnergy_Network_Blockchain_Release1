package transactions

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/assets"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
)

// TransactionValidator validates transactions in the SYN721 token system
type TransactionValidator struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	mutex           sync.Mutex
}

// NewTransactionValidator initializes a new TransactionValidator
func NewTransactionValidator(ledger *ledger.Ledger, securityManager *security.SecurityManager) *TransactionValidator {
	return &TransactionValidator{
		ledger:          ledger,
		securityManager: securityManager,
	}
}

// ValidateMintTransaction validates a mint transaction
func (tv *TransactionValidator) ValidateMintTransaction(sender string, metadata assets.Metadata, valuation assets.Valuation) error {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	// Validate the sender's identity
	if !tv.securityManager.IsValidUser(sender) {
		return fmt.Errorf("invalid sender: %s", sender)
	}

	// Validate metadata
	if err := tv.validateMetadata(metadata); err != nil {
		return fmt.Errorf("invalid metadata: %v", err)
	}

	// Validate valuation
	if err := tv.validateValuation(valuation); err != nil {
		return fmt.Errorf("invalid valuation: %v", err)
	}

	return nil
}

// ValidateTransferTransaction validates a transfer transaction
func (tv *TransactionValidator) ValidateTransferTransaction(sender, receiver, tokenID string) error {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	// Validate sender and receiver identities
	if !tv.securityManager.IsValidUser(sender) {
		return fmt.Errorf("invalid sender: %s", sender)
	}
	if !tv.securityManager.IsValidUser(receiver) {
		return fmt.Errorf("invalid receiver: %s", receiver)
	}

	// Validate token ownership
	token, err := tv.ledger.GetToken(tokenID)
	if err != nil {
		return fmt.Errorf("token not found: %s", tokenID)
	}
	if token.Owner != sender {
		return fmt.Errorf("sender does not own the token: %s", tokenID)
	}

	return nil
}

// ValidateBurnTransaction validates a burn transaction
func (tv *TransactionValidator) ValidateBurnTransaction(sender, tokenID string) error {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	// Validate sender's identity
	if !tv.securityManager.IsValidUser(sender) {
		return fmt.Errorf("invalid sender: %s", sender)
	}

	// Validate token ownership
	token, err := tv.ledger.GetToken(tokenID)
	if err != nil {
		return fmt.Errorf("token not found: %s", tokenID)
	}
	if token.Owner != sender {
		return fmt.Errorf("sender does not own the token: %s", tokenID)
	}

	return nil
}

// validateMetadata performs internal validation on token metadata
func (tv *TransactionValidator) validateMetadata(metadata assets.Metadata) error {
	if metadata.ID == "" || metadata.Name == "" || metadata.Description == "" {
		return errors.New("metadata fields cannot be empty")
	}
	if metadata.CreatedAt.IsZero() || metadata.UpdatedAt.IsZero() {
		return errors.New("invalid metadata timestamps")
	}
	return nil
}

// validateValuation performs internal validation on token valuation
func (tv *TransactionValidator) validateValuation(valuation assets.Valuation) error {
	if valuation.Value < 0 {
		return errors.New("valuation value cannot be negative")
	}
	if valuation.Currency == "" {
		return errors.New("valuation currency cannot be empty")
	}
	return nil
}

// ValidateBatchTransferTransaction validates a batch transfer transaction
func (tv *TransactionValidator) ValidateBatchTransferTransaction(sender string, transfers []BatchTransfer) error {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	for _, transfer := range transfers {
		if err := tv.ValidateTransferTransaction(sender, transfer.Receiver, transfer.TokenID); err != nil {
			return fmt.Errorf("batch transfer validation failed: %v", err)
		}
	}
	return nil
}

// ValidateEscrowTransaction validates an escrow transaction
func (tv *TransactionValidator) ValidateEscrowTransaction(sender, receiver, tokenID string, escrowAmount float64) error {
	tv.mutex.Lock()
	defer tv.mutex.Unlock()

	// Validate sender and receiver identities
	if !tv.securityManager.IsValidUser(sender) {
		return fmt.Errorf("invalid sender: %s", sender)
	}
	if !tv.securityManager.IsValidUser(receiver) {
		return fmt.Errorf("invalid receiver: %s", receiver)
	}

	// Validate token ownership
	token, err := tv.ledger.GetToken(tokenID)
	if err != nil {
		return fmt.Errorf("token not found: %s", tokenID)
	}
	if token.Owner != sender {
		return fmt.Errorf("sender does not own the token: %s", tokenID)
	}

	// Validate escrow amount
	if escrowAmount <= 0 {
		return fmt.Errorf("invalid escrow amount: %f", escrowAmount)
	}

	return nil
}

// BatchTransfer represents a batch transfer operation
type BatchTransfer struct {
	TokenID  string
	Receiver string
}
