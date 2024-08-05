package transactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/storage"
)

// TransactionValidation handles the validation of employment transactions
type TransactionValidation struct {
	ledger        *ledger.EmploymentTransactionLedger
	security      *security.SecurityManager
	storage       *storage.DatabaseManagement
	encryptionKey []byte
}

// NewTransactionValidation initializes a new TransactionValidation instance
func NewTransactionValidation(ledger *ledger.EmploymentTransactionLedger, security *security.SecurityManager, storage *storage.DatabaseManagement, encryptionKey []byte) (*TransactionValidation, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	return &TransactionValidation{
		ledger:        ledger,
		security:      security,
		storage:       storage,
		encryptionKey: encryptionKey,
	}, nil
}

// EmploymentTransaction represents a single employment transaction record
type EmploymentTransaction struct {
	TransactionID string    `json:"transaction_id"`
	SenderID      string    `json:"sender_id"`
	ReceiverID    string    `json:"receiver_id"`
	TokenID       string    `json:"token_id"`
	ContractID    string    `json:"contract_id"`
	Timestamp     time.Time `json:"timestamp"`
	Details       string    `json:"details"`
}

// ValidateTransaction validates an employment transaction
func (tv *TransactionValidation) ValidateTransaction(transactionID string) (bool, error) {
	// Load transaction
	transaction, err := tv.loadTransaction(transactionID)
	if err != nil {
		return false, fmt.Errorf("failed to load transaction: %w", err)
	}

	// Validate transaction details (e.g., existence of sender, receiver, token, contract)
	if !tv.validateTransactionDetails(transaction) {
		return false, errors.New("transaction details are invalid")
	}

	// Check if the transaction exists in the ledger
	exists, err := tv.ledger.TransactionExists(transactionID)
	if err != nil {
		return false, fmt.Errorf("failed to check transaction existence in ledger: %w", err)
	}

	if !exists {
		return false, errors.New("transaction does not exist in ledger")
	}

	return true, nil
}

// validateTransactionDetails checks the validity of transaction details
func (tv *TransactionValidation) validateTransactionDetails(transaction *EmploymentTransaction) bool {
	// Check if the sender, receiver, token, and contract IDs are non-empty
	if transaction.SenderID == "" || transaction.ReceiverID == "" || transaction.TokenID == "" || transaction.ContractID == "" {
		return false
	}

	// Additional checks (e.g., existence of entities) can be added here
	return true
}

// loadTransaction loads a transaction by its ID
func (tv *TransactionValidation) loadTransaction(transactionID string) (*EmploymentTransaction, error) {
	data, err := tv.storage.LoadData(transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to load transaction data: %w", err)
	}

	decryptedData, err := tv.security.Decrypt(data, tv.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt transaction data: %w", err)
	}

	var transaction EmploymentTransaction
	err = json.Unmarshal(decryptedData, &transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction data: %w", err)
	}

	return &transaction, nil
}

// ListValidTransactions lists all valid transactions
func (tv *TransactionValidation) ListValidTransactions() ([]EmploymentTransaction, error) {
	// Load all transaction IDs
	transactionIDs, err := tv.storage.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list transaction keys: %w", err)
	}

	var validTransactions []EmploymentTransaction
	for _, transactionID := range transactionIDs {
		valid, err := tv.ValidateTransaction(transactionID)
		if err != nil {
			return nil, fmt.Errorf("failed to validate transaction: %w", err)
		}
		if valid {
			transaction, err := tv.loadTransaction(transactionID)
			if err != nil {
				return nil, fmt.Errorf("failed to load transaction: %w", err)
			}
			validTransactions = append(validTransactions, *transaction)
		}
	}

	return validTransactions, nil
}
