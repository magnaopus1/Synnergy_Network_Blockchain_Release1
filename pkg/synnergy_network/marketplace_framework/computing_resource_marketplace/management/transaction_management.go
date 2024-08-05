package management

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transaction represents a marketplace transaction
type Transaction struct {
	ID           string
	ListingID    string
	BuyerID      string
	SellerID     string
	Amount       float64
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TransactionStatus constants
const (
	StatusPending   = "PENDING"
	StatusCompleted = "COMPLETED"
	StatusFailed    = "FAILED"
)

// TransactionManager manages marketplace transactions
type TransactionManager struct {
	mu            sync.Mutex
	transactions  map[string]*Transaction
	nextTransID   int
}

// NewTransactionManager initializes a new TransactionManager
func NewTransactionManager() *TransactionManager {
	return &TransactionManager{
		transactions: make(map[string]*Transaction),
		nextTransID:  1,
	}
}

// CreateTransaction creates a new transaction
func (tm *TransactionManager) CreateTransaction(listingID, buyerID, sellerID string, amount float64) (*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if amount <= 0 {
		return nil, errors.New("transaction amount must be greater than zero")
	}

	id := tm.generateTransactionID()
	transaction := &Transaction{
		ID:         id,
		ListingID:  listingID,
		BuyerID:    buyerID,
		SellerID:   sellerID,
		Amount:     amount,
		Status:     StatusPending,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	tm.transactions[id] = transaction
	return transaction, nil
}

// GetTransaction retrieves a transaction by ID
func (tm *TransactionManager) GetTransaction(id string) (*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	transaction, exists := tm.transactions[id]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	return transaction, nil
}

// UpdateTransactionStatus updates the status of a transaction
func (tm *TransactionManager) UpdateTransactionStatus(id, status string) (*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	transaction, exists := tm.transactions[id]
	if !exists {
		return nil, errors.New("transaction not found")
	}

	if status != StatusPending && status != StatusCompleted && status != StatusFailed {
		return nil, errors.New("invalid transaction status")
	}

	transaction.Status = status
	transaction.UpdatedAt = time.Now()
	return transaction, nil
}

// ListTransactionsByUser retrieves all transactions for a given user
func (tm *TransactionManager) ListTransactionsByUser(userID string) ([]*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var transactions []*Transaction
	for _, transaction := range tm.transactions {
		if transaction.BuyerID == userID || transaction.SellerID == userID {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the user")
	}

	return transactions, nil
}

// ListTransactionsByListing retrieves all transactions for a given listing
func (tm *TransactionManager) ListTransactionsByListing(listingID string) ([]*Transaction, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	var transactions []*Transaction
	for _, transaction := range tm.transactions {
		if transaction.ListingID == listingID {
			transactions = append(transactions, transaction)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the listing")
	}

	return transactions, nil
}

// generateTransactionID generates a unique ID for a transaction
func (tm *TransactionManager) generateTransactionID() string {
	id := fmt.Sprintf("T-%d", tm.nextTransID)
	tm.nextTransID++
	return id
}
