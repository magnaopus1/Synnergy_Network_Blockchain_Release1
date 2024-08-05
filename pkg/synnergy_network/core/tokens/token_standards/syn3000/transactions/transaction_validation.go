package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn3000/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn3000/security"
)

// TransactionValidator handles the validation of transactions
type TransactionValidator struct {
	ledger   *ledger.Ledger
	security *security.SecurityHandler
}

// NewTransactionValidator initializes a new TransactionValidator
func NewTransactionValidator(ledger *ledger.Ledger, security *security.SecurityHandler) *TransactionValidator {
	return &TransactionValidator{
		ledger:   ledger,
		security: security,
	}
}

// ValidateTransaction validates a transaction's integrity and authenticity
func (tv *TransactionValidator) ValidateTransaction(transaction *Transaction) error {
	// Check if the transaction ID is valid
	if err := tv.validateTransactionID(transaction); err != nil {
		return fmt.Errorf("transaction ID validation failed: %v", err)
	}

	// Verify the transaction signature
	if err := tv.security.VerifyTransaction(transaction); err != nil {
		return fmt.Errorf("transaction signature verification failed: %v", err)
	}

	// Check if the transaction is not expired
	if err := tv.validateTransactionTimestamp(transaction); err != nil {
		return fmt.Errorf("transaction timestamp validation failed: %v", err)
	}

	// Check if the sender has enough balance
	if err := tv.validateSenderBalance(transaction); err != nil {
		return fmt.Errorf("sender balance validation failed: %v", err)
	}

	// Ensure the transaction is not a duplicate
	if err := tv.validateDuplicateTransaction(transaction); err != nil {
		return fmt.Errorf("duplicate transaction validation failed: %v", err)
	}

	return nil
}

// validateTransactionID checks the validity of the transaction ID
func (tv *TransactionValidator) validateTransactionID(transaction *Transaction) error {
	expectedID := generateTransactionID(transaction)
	if transaction.TransactionID != expectedID {
		return errors.New("invalid transaction ID")
	}
	return nil
}

// validateTransactionTimestamp checks if the transaction timestamp is within a valid time range
func (tv *TransactionValidator) validateTransactionTimestamp(transaction *Transaction) error {
	currentTime := time.Now()
	if transaction.Timestamp.After(currentTime) {
		return errors.New("transaction timestamp is in the future")
	}
	if transaction.Timestamp.Before(currentTime.Add(-24 * time.Hour)) {
		return errors.New("transaction timestamp is too old")
	}
	return nil
}

// validateSenderBalance ensures the sender has enough balance for the transaction
func (tv *TransactionValidator) validateSenderBalance(transaction *Transaction) error {
	balance, err := tv.ledger.GetBalance(transaction.FromAddress, transaction.TokenID)
	if err != nil {
		return fmt.Errorf("error fetching sender balance: %v", err)
	}
	if balance < transaction.Amount {
		return errors.New("insufficient balance")
	}
	return nil
}

// validateDuplicateTransaction ensures the transaction is not a duplicate
func (tv *TransactionValidator) validateDuplicateTransaction(transaction *Transaction) error {
	existingTransaction, err := tv.ledger.GetTransaction(transaction.TransactionID)
	if err == nil && existingTransaction != nil {
		return errors.New("duplicate transaction")
	}
	return nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID(transaction *Transaction) string {
	data := fmt.Sprintf("%s%s%s%f%s", transaction.TokenID, transaction.FromAddress, transaction.ToAddress, transaction.Amount, transaction.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
