package transactions

import (
	"errors"
	"sync"
	"time"
)

// TransactionType defines the type of transaction
type TransactionType string

const (
	Issuance   TransactionType = "Issuance"
	Repayment  TransactionType = "Repayment"
	Refinancing TransactionType = "Refinancing"
	Transfer   TransactionType = "Transfer"
)

// Transaction represents a transaction related to a debt instrument
type Transaction struct {
	ID            string
	Type          TransactionType
	InstrumentID  string
	From          string
	To            string
	Amount        float64
	InterestRate  float64
	Date          time.Time
	ExtraData     map[string]interface{}
}

// TransactionManager handles the creation and management of transactions
type TransactionManager struct {
	transactions map[string]*Transaction
	mu           sync.RWMutex
}

// NewTransactionManager creates a new TransactionManager instance
func NewTransactionManager() *TransactionManager {
	return &TransactionManager{
		transactions: make(map[string]*Transaction),
	}
}

// CreateTransaction creates a new transaction
func (tm *TransactionManager) CreateTransaction(tType TransactionType, instrumentID, from, to string, amount, interestRate float64, extraData map[string]interface{}) (*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Generate a unique ID for the transaction (in real implementation, use a proper ID generator)
	transactionID := generateUniqueID()

	transaction := &Transaction{
		ID:           transactionID,
		Type:         tType,
		InstrumentID: instrumentID,
		From:         from,
		To:           to,
		Amount:       amount,
		InterestRate: interestRate,
		Date:         time.Now(),
		ExtraData:    extraData,
	}

	tm.transactions[transactionID] = transaction
	return transaction, nil
}

// GetTransaction retrieves a transaction by its ID
func (tm *TransactionManager) GetTransaction(transactionID string) (*Transaction, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	transaction, exists := tm.transactions[transactionID]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	return transaction, nil
}

// GetTransactionsByInstrument retrieves all transactions for a specific debt instrument
func (tm *TransactionManager) GetTransactionsByInstrument(instrumentID string) ([]*Transaction, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var transactions []*Transaction
	for _, transaction := range tm.transactions {
		if transaction.InstrumentID == instrumentID {
			transactions = append(transactions, transaction)
		}
	}

	return transactions, nil
}

// GetAllTransactions retrieves all transactions
func (tm *TransactionManager) GetAllTransactions() []*Transaction {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var transactions []*Transaction
	for _, transaction := range tm.transactions {
		transactions = append(transactions, transaction)
	}

	return transactions
}

// generateUniqueID generates a unique ID for the transaction
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
