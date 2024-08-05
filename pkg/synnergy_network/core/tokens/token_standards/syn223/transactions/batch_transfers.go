package transactions

import (
	"errors"
	"fmt"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

type BatchTransfer struct {
	Ledger        *ledger.Ledger
	AccessControl *security.AccessControl
}

// NewBatchTransfer initializes a new BatchTransfer instance.
func NewBatchTransfer(ledger *ledger.Ledger, accessControl *security.AccessControl) *BatchTransfer {
	return &BatchTransfer{
		Ledger:        ledger,
		AccessControl: accessControl,
	}
}

// Transfer represents a single token transfer.
type Transfer struct {
	From   string
	To     string
	Amount uint64
}

// BatchTransfer executes multiple token transfers in a single transaction.
func (bt *BatchTransfer) ExecuteBatch(transfers []Transfer, authKey string) error {
	// Pre-check: Verify all addresses and balances
	for _, transfer := range transfers {
		if err := bt.verifyTransfer(transfer); err != nil {
			return err
		}
	}

	// Check authorization
	if !bt.AccessControl.IsAuthorized(authKey) {
		return errors.New("unauthorized access")
	}

	// Execute all transfers
	for _, transfer := range transfers {
		if err := bt.executeTransfer(transfer); err != nil {
			return err
		}
	}

	return nil
}

func (bt *BatchTransfer) verifyTransfer(transfer Transfer) error {
	// Verify sender has sufficient balance
	balance, err := bt.Ledger.GetBalance(transfer.From)
	if err != nil {
		return fmt.Errorf("failed to get balance for address %s: %v", transfer.From, err)
	}

	if balance < transfer.Amount {
		return fmt.Errorf("insufficient balance for address %s", transfer.From)
	}

	// Verify recipient address is valid and capable of receiving tokens
	if !bt.Ledger.IsValidAddress(transfer.To) {
		return fmt.Errorf("invalid recipient address %s", transfer.To)
	}

	return nil
}

func (bt *BatchTransfer) executeTransfer(transfer Transfer) error {
	// Deduct amount from sender
	if err := bt.Ledger.DeductBalance(transfer.From, transfer.Amount); err != nil {
		return fmt.Errorf("failed to deduct balance from address %s: %v", transfer.From, err)
	}

	// Add amount to recipient
	if err := bt.Ledger.AddBalance(transfer.To, transfer.Amount); err != nil {
		return fmt.Errorf("failed to add balance to address %s: %v", transfer.To, err)
	}

	// Log the transfer
	return bt.logTransfer(transfer)
}

func (bt *BatchTransfer) logTransfer(transfer Transfer) error {
	logEntry := ledger.TransactionLog{
		From:   transfer.From,
		To:     transfer.To,
		Amount: transfer.Amount,
	}

	return bt.Ledger.LogTransaction(logEntry)
}
