package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// TransactionValidator validates Forex transactions
type TransactionValidator struct {
	ledgerManager *ledger.LedgerManager
	tokenManager  *assets.TokenManager
	eventLogger   *events.EventLogger
}

// NewTransactionValidator initializes a new TransactionValidator instance
func NewTransactionValidator(ledgerMgr *ledger.LedgerManager, tokenMgr *assets.TokenManager, eventLogger *events.EventLogger) (*TransactionValidator, error) {
	return &TransactionValidator{
		ledgerManager: ledgerMgr,
		tokenManager:  tokenMgr,
		eventLogger:   eventLogger,
	}, nil
}

// ValidateTransaction checks if a transaction is valid
func (tv *TransactionValidator) ValidateTransaction(transaction Transaction) error {
	// Validate transaction ID
	if !isValidTransactionID(transaction.TransactionID) {
		return errors.New("invalid transaction ID")
	}

	// Validate token existence
	token, err := tv.tokenManager.GetToken(transaction.TokenID)
	if err != nil {
		return errors.New("token does not exist")
	}

	// Validate token ownership
	if token.Owner != transaction.From {
		return errors.New("invalid token ownership")
	}

	// Validate timestamp
	if !isValidTimestamp(transaction.Timestamp) {
		return errors.New("invalid timestamp")
	}

	// Validate transaction amount
	if transaction.Amount <= 0 {
		return errors.New("invalid transaction amount")
	}

	// Check for duplicate transactions in the ledger
	if tv.ledgerManager.TransactionExists(transaction.TransactionID) {
		return errors.New("duplicate transaction")
	}

	// Log validation event
	tv.logValidationEvent(transaction)

	return nil
}

// isValidTransactionID checks if the transaction ID is valid
func isValidTransactionID(transactionID string) bool {
	_, err := hex.DecodeString(transactionID)
	return err == nil && len(transactionID) == sha256.Size*2
}

// isValidTimestamp checks if the transaction timestamp is valid
func isValidTimestamp(timestamp time.Time) bool {
	// Allow transactions within a 24-hour window
	return time.Since(timestamp) <= 24*time.Hour && timestamp.Before(time.Now().Add(24*time.Hour))
}

// logValidationEvent logs a validation event
func (tv *TransactionValidator) logValidationEvent(transaction Transaction) {
	event := events.Event{
		Type:      "TransactionValidation",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"transactionID": transaction.TransactionID,
			"tokenID":       transaction.TokenID,
			"from":          transaction.From,
			"to":            transaction.To,
			"amount":        transaction.Amount,
			"status":        "validated",
		},
	}
	tv.eventLogger.LogEvent(event)
}

// ValidateBatchTransactions validates a batch of transactions
func (tv *TransactionValidator) ValidateBatchTransactions(transactions []Transaction) []error {
	var validationErrors []error
	for _, tx := range transactions {
		if err := tv.ValidateTransaction(tx); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}
	return validationErrors
}
