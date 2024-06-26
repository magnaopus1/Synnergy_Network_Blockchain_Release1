package storage

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/google/uuid"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID            string  `json:"id"`
	From          string  `json:"from"`
	To            string  `json:"to"`
	Amount        float64 `json:"amount"`
	Timestamp     int64   `json:"timestamp"`
	Signature     string  `json:"signature"`
	TransactionFee float64 `json:"transaction_fee"`
}

// TransactionStorage manages the storage of transactions
type TransactionStorage struct {
	transactions map[string]Transaction
	mu           sync.RWMutex
	filePath     string
}

// NewTransactionStorage initializes and returns a new TransactionStorage
func NewTransactionStorage(filePath string) *TransactionStorage {
	ts := &TransactionStorage{
		transactions: make(map[string]Transaction),
		filePath:     filePath,
	}
	ts.loadFromFile()
	return ts
}

// AddTransaction adds a new transaction to the storage
func (ts *TransactionStorage) AddTransaction(from, to string, amount, transactionFee float64, timestamp int64, signature string) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := uuid.New().String()
	transaction := Transaction{
		ID:            id,
		From:          from,
		To:            to,
		Amount:        amount,
		Timestamp:     timestamp,
		Signature:     signature,
		TransactionFee: transactionFee,
	}
	ts.transactions[id] = transaction
	err := ts.saveToFile()
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetTransaction retrieves a transaction by ID
func (ts *TransactionStorage) GetTransaction(id string) (Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	transaction, exists := ts.transactions[id]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}
	return transaction, nil
}

// GetTransactionsByAddress retrieves all transactions associated with a given address
func (ts *TransactionStorage) GetTransactionsByAddress(address string) ([]Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var transactions []Transaction
	for _, transaction := range ts.transactions {
		if transaction.From == address || transaction.To == address {
			transactions = append(transactions, transaction)
		}
	}
	return transactions, nil
}

// GetAllTransactions retrieves all transactions
func (ts *TransactionStorage) GetAllTransactions() ([]Transaction, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var transactions []Transaction
	for _, transaction := range ts.transactions {
		transactions = append(transactions, transaction)
	}
	return transactions, nil
}

// DeleteTransaction deletes a transaction by ID
func (ts *TransactionStorage) DeleteTransaction(id string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.transactions[id]; !exists {
		return errors.New("transaction not found")
	}
	delete(ts.transactions, id)
	return ts.saveToFile()
}

// saveToFile saves the current state of transactions to a file
func (ts *TransactionStorage) saveToFile() error {
	data, err := json.Marshal(ts.transactions)
	if err != nil {
		return err
	}
	return os.WriteFile(ts.filePath, data, 0644)
}

// loadFromFile loads the transactions from a file
func (ts *TransactionStorage) loadFromFile() error {
	file, err := os.ReadFile(ts.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // File does not exist, no transactions to load
		}
		return err
	}
	return json.Unmarshal(file, &ts.transactions)
}

func main() {
	// Example usage
	filePath := "transactions.json"
	ts := NewTransactionStorage(filePath)

	// Add a new transaction
	from := "address1"
	to := "address2"
	amount := 100.0
	transactionFee := 0.01
	timestamp := int64(1625298482)
	signature := "signature_placeholder"
	id, err := ts.AddTransaction(from, to, amount, transactionFee, timestamp, signature)
	if err != nil {
		panic(err)
	}
	println("Transaction added with ID:", id)

	// Retrieve a transaction
	transaction, err := ts.GetTransaction(id)
	if err != nil {
		panic(err)
	}
	println("Retrieved transaction:", transaction.ID, transaction.Amount)

	// Get all transactions for an address
	transactions, err := ts.GetTransactionsByAddress(from)
	if err != nil {
		panic(err)
	}
	println("Transactions for address:", from)
	for _, tx := range transactions {
		println(tx.ID, tx.Amount)
	}

	// Get all transactions
	allTransactions, err := ts.GetAllTransactions()
	if err != nil {
		panic(err)
	}
	println("All transactions:")
	for _, tx := range allTransactions {
		println(tx.ID, tx.Amount)
	}

	// Delete a transaction
	err = ts.DeleteTransaction(id)
	if err != nil {
		panic(err)
	}
	println("Transaction deleted:", id)
}
