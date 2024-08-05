package transactions

import (
	"errors"
	"fmt"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// TransactionValidator handles the validation of SYN223 transactions
type TransactionValidator struct {
	Ledger             *ledger.Ledger
	AccessControl      *security.AccessControl
	WhitelistBlacklist *security.WhitelistBlacklist
	ReversionMechanism *security.ReversionMechanism
}

// NewTransactionValidator initializes a new TransactionValidator instance
func NewTransactionValidator(ledger *ledger.Ledger, accessControl *security.AccessControl, whitelistBlacklist *security.WhitelistBlacklist, reversionMechanism *security.ReversionMechanism) *TransactionValidator {
	return &TransactionValidator{
		Ledger:             ledger,
		AccessControl:      accessControl,
		WhitelistBlacklist: whitelistBlacklist,
		ReversionMechanism: reversionMechanism,
	}
}

// ValidateTransaction validates a SYN223 transaction
func (tv *TransactionValidator) ValidateTransaction(tx *FeeFreeTransaction) error {
	if err := tv.validateAddresses(tx.From, tx.To); err != nil {
		return err
	}

	if err := tv.validateBalance(tx.From, tx.Amount); err != nil {
		return err
	}

	if err := tv.validateWhitelistBlacklist(tx.To); err != nil {
		return err
	}

	return nil
}

// validateAddresses checks if the sender and receiver addresses are valid
func (tv *TransactionValidator) validateAddresses(from, to string) error {
	if !tv.Ledger.IsValidAddress(from) {
		return fmt.Errorf("invalid sender address: %s", from)
	}
	if !tv.Ledger.IsValidAddress(to) {
		return fmt.Errorf("invalid receiver address: %s", to)
	}
	return nil
}

// validateBalance checks if the sender has enough balance to make the transaction
func (tv *TransactionValidator) validateBalance(from string, amount float64) error {
	if !tv.Ledger.HasSufficientBalance(from, amount) {
		return fmt.Errorf("insufficient balance for address: %s", from)
	}
	return nil
}

// validateWhitelistBlacklist checks if the receiver address is allowed to receive tokens
func (tv *TransactionValidator) validateWhitelistBlacklist(to string) error {
	if err := tv.WhitelistBlacklist.CheckRestrictions(to); err != nil {
		return fmt.Errorf("address %s is restricted: %v", to, err)
	}
	return nil
}

// ValidateAndExecuteTransaction validates and executes a transaction
func (tv *TransactionValidator) ValidateAndExecuteTransaction(tx *FeeFreeTransaction) error {
	if err := tv.ValidateTransaction(tx); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		return err
	}

	if err := tv.executeTransaction(tx); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		return err
	}

	tx.Status = "completed"
	return nil
}

// executeTransaction executes the transaction and updates the ledger
func (tv *TransactionValidator) executeTransaction(tx *FeeFreeTransaction) error {
	if err := tv.Ledger.Debit(tx.From, tx.Amount); err != nil {
		return err
	}

	if err := tv.Ledger.Credit(tx.To, tx.Amount); err != nil {
		tv.ReversionMechanism.RevertTransaction(tx.From, tx.Amount)
		return err
	}

	return nil
}

// ValidateBatchTransactions validates a batch of transactions
func (tv *TransactionValidator) ValidateBatchTransactions(txs []*FeeFreeTransaction) ([]*FeeFreeTransaction, []error) {
	var validTxs []*FeeFreeTransaction
	var errors []error

	for _, tx := range txs {
		if err := tv.ValidateTransaction(tx); err != nil {
			tx.Status = "failed"
			tx.ErrorMessage = err.Error()
			errors = append(errors, err)
		} else {
			validTxs = append(validTxs, tx)
		}
	}

	return validTxs, errors
}

// LogTransaction logs the transaction details
func (tv *TransactionValidator) LogTransaction(tx *FeeFreeTransaction) error {
	return tv.Ledger.LogTransaction(*tx)
}

// ValidateAndExecuteBatchTransactions validates and executes a batch of transactions
func (tv *TransactionValidator) ValidateAndExecuteBatchTransactions(txs []*FeeFreeTransaction) ([]*FeeFreeTransaction, []error) {
	var successfulTxs []*FeeFreeTransaction
	var errors []error

	for _, tx := range txs {
		if err := tv.ValidateAndExecuteTransaction(tx); err != nil {
			errors = append(errors, err)
		} else {
			successfulTxs = append(successfulTxs, tx)
		}
	}

	return successfulTxs, errors
}
