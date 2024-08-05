package transactions

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/security"
)

// TransactionValidator handles the validation of transactions.
type TransactionValidator struct {
	ledger       *ledger.Ledger
	eventRecords *assets.EventRecords
	security     *security.SecurityManager
}

// NewTransactionValidator creates a new instance of TransactionValidator.
func NewTransactionValidator(ledger *ledger.Ledger, eventRecords *assets.EventRecords, security *security.SecurityManager) *TransactionValidator {
	return &TransactionValidator{
		ledger:       ledger,
		eventRecords: eventRecords,
		security:     security,
	}
}

// ValidateTransaction validates a transaction and ensures it meets all necessary criteria.
func (tv *TransactionValidator) ValidateTransaction(transactionData string) (bool, error) {
	var transaction Transaction
	err := json.Unmarshal([]byte(transactionData), &transaction)
	if err != nil {
		return false, err
	}

	// Check if the transaction already exists in the ledger
	if tv.ledger.TransactionExists(transaction.TransactionID) {
		return false, errors.New("transaction already exists")
	}

	// Validate timestamp
	if transaction.Timestamp.After(time.Now()) {
		return false, errors.New("transaction timestamp is in the future")
	}

	// Validate event and ticket IDs
	if !tv.eventRecords.EventExists(transaction.EventID) {
		return false, errors.New("event does not exist")
	}

	if !tv.eventRecords.TicketExists(transaction.EventID, transaction.TicketID) {
		return false, errors.New("ticket does not exist")
	}

	// Validate ownership
	if !tv.ledger.VerifyOwnership(transaction.TicketID, transaction.FromOwnerID) {
		return false, errors.New("invalid ownership")
	}

	// Validate the signature
	if !tv.security.ValidateSignature(transaction.Signature, transaction.FromOwnerID, transactionData) {
		return false, errors.New("invalid signature")
	}

	// Additional validations can be added here (e.g., regulatory compliance, anti-fraud checks)

	return true, nil
}

// RecordTransaction records a validated transaction in the ledger.
func (tv *TransactionValidator) RecordTransaction(transactionData string) error {
	var transaction Transaction
	err := json.Unmarshal([]byte(transactionData), &transaction)
	if err != nil {
		return err
	}

	// Record the transaction in the ledger
	err = tv.ledger.RecordTransaction(transaction)
	if err != nil {
		return err
	}

	// Update the ownership records
	err = tv.ledger.UpdateOwnership(transaction.TicketID, transaction.ToOwnerID)
	if err != nil {
		return err
	}

	return nil
}

// Transaction represents a transaction in the SYN1700 token standard.
type Transaction struct {
	EventID       string    `json:"event_id"`
	TicketID      string    `json:"ticket_id"`
	FromOwnerID   string    `json:"from_owner_id"`
	ToOwnerID     string    `json:"to_owner_id"`
	TransactionID string    `json:"transaction_id"`
	Timestamp     time.Time `json:"timestamp"`
	Signature     string    `json:"signature"`
}
