package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/storage"
)

// TransactionCreationManager handles the creation and management of transactions.
type TransactionCreationManager struct {
	ledger         *ledger.TransactionRecords
	storageManager *storage.StorageManager
}

// NewTransactionCreationManager creates a new TransactionCreationManager.
func NewTransactionCreationManager(ledger *ledger.TransactionRecords, storageManager *storage.StorageManager) *TransactionCreationManager {
	return &TransactionCreationManager{
		ledger:         ledger,
		storageManager: storageManager,
	}
}

// CreateTransaction initializes and records a new transaction.
func (tcm *TransactionCreationManager) CreateTransaction(tokenID, from, to string, amount float64, transactionType string, data string) (string, error) {
	if from == to {
		return "", errors.New("cannot transfer to the same account")
	}

	// Generate a unique transaction ID
	transactionID := tcm.generateTransactionID(tokenID, from, to, amount, transactionType)

	// Create a transaction record
	transactionRecord := ledger.TransactionRecord{
		TransactionID:  transactionID,
		TokenID:        tokenID,
		From:           from,
		To:             to,
		Amount:         amount,
		Data:           data,
		Timestamp:      time.Now(),
		TransactionType: transactionType,
	}

	// Record the transaction in the ledger
	if err := tcm.ledger.RecordTransaction(transactionRecord); err != nil {
		return "", fmt.Errorf("failed to record transaction: %v", err)
	}

	// Store the transaction record in persistent storage
	if err := tcm.storageManager.SaveData(fmt.Sprintf("transaction_%s", transactionID), transactionRecord); err != nil {
		return "", fmt.Errorf("failed to store transaction record: %v", err)
	}

	return transactionID, nil
}

// generateTransactionID creates a unique ID for the transaction.
func (tcm *TransactionCreationManager) generateTransactionID(tokenID, from, to string, amount float64, transactionType string) string {
	data := fmt.Sprintf("%s-%s-%s-%f-%s-%d", tokenID, from, to, amount, transactionType, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ValidateTransaction checks if a transaction is valid before execution.
func (tcm *TransactionCreationManager) ValidateTransaction(transactionID string) (bool, error) {
	transaction, err := tcm.ledger.GetTransactionByID("", transactionID)
	if err != nil {
		return false, fmt.Errorf("transaction not found: %v", err)
	}

	// Add additional validation checks as necessary
	if transaction.Amount <= 0 {
		return false, errors.New("transaction amount must be greater than zero")
	}

	// Example: check if the 'from' account has sufficient funds (business logic)
	// This would typically involve checking the account balance in the ledger

	return true, nil
}

// GetTransactionDetails retrieves the details of a specific transaction.
func (tcm *TransactionCreationManager) GetTransactionDetails(transactionID string) (*ledger.TransactionRecord, error) {
	transaction, err := tcm.ledger.GetTransactionByID("", transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transaction details: %v", err)
	}

	return transaction, nil
}
