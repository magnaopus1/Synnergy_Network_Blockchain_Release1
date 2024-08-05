package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

type ForexTransaction struct {
	TransactionID string    `json:"transaction_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	PairID        string    `json:"pair_id"`
	Amount        float64   `json:"amount"`
	Rate          float64   `json:"rate"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"`
}

type ForexTransactionLedger struct {
	Transactions map[string]ForexTransaction
	mutex        sync.Mutex
}

// InitializeForexTransactionLedger initializes the ForexTransactionLedger structure
func InitializeForexTransactionLedger() *ForexTransactionLedger {
	return &ForexTransactionLedger{
		Transactions: make(map[string]ForexTransaction),
	}
}

// AddTransaction adds a new transaction to the ledger
func (ftl *ForexTransactionLedger) AddTransaction(transaction ForexTransaction) error {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	if _, exists := ftl.Transactions[transaction.TransactionID]; exists {
		return errors.New("transaction already exists")
	}

	ftl.Transactions[transaction.TransactionID] = transaction

	// Log the transaction addition
	ftl.logTransactionEvent(transaction, "TRANSACTION_ADDED")

	return nil
}

// UpdateTransaction updates an existing transaction in the ledger
func (ftl *ForexTransactionLedger) UpdateTransaction(transactionID string, status string) error {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	transaction, exists := ftl.Transactions[transactionID]
	if !exists {
		return errors.New("transaction not found")
	}

	transaction.Status = status
	ftl.Transactions[transactionID] = transaction

	// Log the transaction update
	ftl.logTransactionEvent(transaction, "TRANSACTION_UPDATED")

	return nil
}

// GetTransaction retrieves a transaction from the ledger
func (ftl *ForexTransactionLedger) GetTransaction(transactionID string) (ForexTransaction, error) {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	transaction, exists := ftl.Transactions[transactionID]
	if !exists {
		return ForexTransaction{}, errors.New("transaction not found")
	}

	return transaction, nil
}

// DeleteTransaction removes a transaction from the ledger
func (ftl *ForexTransactionLedger) DeleteTransaction(transactionID string) error {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	if _, exists := ftl.Transactions[transactionID]; !exists {
		return errors.New("transaction not found")
	}

	delete(ftl.Transactions, transactionID)

	// Log the transaction deletion
	ftl.logTransactionEvent(ForexTransaction{TransactionID: transactionID}, "TRANSACTION_DELETED")

	return nil
}

// GetTransactionsByPairID retrieves all transactions for a specific Forex pair
func (ftl *ForexTransactionLedger) GetTransactionsByPairID(pairID string) ([]ForexTransaction, error) {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	var transactions []ForexTransaction
	for _, transaction := range ftl.Transactions {
		if transaction.PairID == pairID {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the specified pair ID")
	}

	return transactions, nil
}

// SaveLedgerToFile saves the transaction ledger to a file
func (ftl *ForexTransactionLedger) SaveLedgerToFile(filename string) error {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	data, err := json.Marshal(ftl.Transactions)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadLedgerFromFile loads the transaction ledger from a file
func (ftl *ForexTransactionLedger) LoadLedgerFromFile(filename string) error {
	ftl.mutex.Lock()
	defer ftl.mutex.Unlock()

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ftl.Transactions)
}

// logTransactionEvent logs events related to transactions
func (ftl *ForexTransactionLedger) logTransactionEvent(transaction ForexTransaction, eventType string) {
	fmt.Printf("Event: %s - Transaction ID: %s, From: %s, To: %s, PairID: %s, Amount: %f, Rate: %f, Timestamp: %s, Status: %s\n",
		eventType, transaction.TransactionID, transaction.From, transaction.To, transaction.PairID, transaction.Amount, transaction.Rate, transaction.Timestamp, transaction.Status)
}
