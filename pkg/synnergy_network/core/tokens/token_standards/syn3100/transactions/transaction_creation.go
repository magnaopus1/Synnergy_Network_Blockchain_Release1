package transactions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/storage"
)

// TransactionCreation manages the creation of new transactions
type TransactionCreation struct {
	ledger        *ledger.EmploymentTransactionLedger
	security      *security.SecurityManager
	storage       *storage.DatabaseManagement
	encryptionKey []byte
}

// NewTransactionCreation initializes a new TransactionCreation instance
func NewTransactionCreation(ledger *ledger.EmploymentTransactionLedger, security *security.SecurityManager, storage *storage.DatabaseManagement, encryptionKey []byte) (*TransactionCreation, error) {
	if len(encryptionKey) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}

	return &TransactionCreation{
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

// CreateTransaction creates a new employment transaction
func (tc *TransactionCreation) CreateTransaction(senderID, receiverID, tokenID, contractID, details string) (*EmploymentTransaction, error) {
	transactionID, err := tc.generateTransactionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	transaction := &EmploymentTransaction{
		TransactionID: transactionID,
		SenderID:      senderID,
		ReceiverID:    receiverID,
		TokenID:       tokenID,
		ContractID:    contractID,
		Timestamp:     time.Now(),
		Details:       details,
	}

	err = tc.saveTransaction(transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to save transaction: %w", err)
	}

	// Update ledger
	err = tc.ledger.AddTransaction(transaction.TransactionID, transaction.SenderID, transaction.ReceiverID, transaction.TokenID, transaction.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to update ledger: %w", err)
	}

	return transaction, nil
}

// generateTransactionID generates a unique transaction ID
func (tc *TransactionCreation) generateTransactionID() (string, error) {
	// Generate a unique transaction ID using current timestamp and random number
	timestamp := time.Now().UnixNano()
	randomBytes := tc.security.GenerateRandomBytes(16)
	if randomBytes == nil {
		return "", errors.New("failed to generate random bytes")
	}

	transactionID := fmt.Sprintf("%d-%x", timestamp, randomBytes)
	return transactionID, nil
}

// saveTransaction saves a transaction to storage
func (tc *TransactionCreation) saveTransaction(transaction *EmploymentTransaction) error {
	records, err := tc.loadTransactionHistory()
	if err != nil {
		return fmt.Errorf("failed to load transaction history: %w", err)
	}

	records = append(records, *transaction)
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction records: %w", err)
	}

	encryptedData, err := tc.security.Encrypt(data, tc.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction data: %w", err)
	}

	err = tc.storage.SaveData(transaction.TransactionID, encryptedData)
	if err != nil {
		return fmt.Errorf("failed to save transaction data: %w", err)
	}

	return nil
}

// loadTransactionHistory loads the transaction history from storage
func (tc *TransactionCreation) loadTransactionHistory() ([]EmploymentTransaction, error) {
	var records []EmploymentTransaction

	data, err := tc.storage.LoadData("transaction_history")
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return records, nil
		}
		return nil, fmt.Errorf("failed to load transaction history: %w", err)
	}

	decryptedData, err := tc.security.Decrypt(data, tc.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt transaction data: %w", err)
	}

	err = json.Unmarshal(decryptedData, &records)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction records: %w", err)
	}

	return records, nil
}

// ListAllTransactions lists all transactions in the history
func (tc *TransactionCreation) ListAllTransactions() ([]EmploymentTransaction, error) {
	return tc.loadTransactionHistory()
}
