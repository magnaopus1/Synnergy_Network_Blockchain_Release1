// gambling_transaction_ledger.go

package ledger

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// TransactionType defines the type of transaction
type TransactionType string

const (
	TransactionTypeBetPlacement   TransactionType = "BetPlacement"
	TransactionTypePayout         TransactionType = "Payout"
	TransactionTypeTokenTransfer  TransactionType = "TokenTransfer"
	TransactionTypeTokenCreation  TransactionType = "TokenCreation"
	TransactionTypeTokenBurning   TransactionType = "TokenBurning"
)

// Transaction represents a gambling transaction in the SYN5000 standard
type Transaction struct {
	ID        string                 // Unique identifier for the transaction
	Type      TransactionType        // Type of the transaction
	Timestamp time.Time              // Time the transaction was created
	Amount    float64                // Amount involved in the transaction
	TokenID   string                 // Associated token ID
	From      string                 // Sender's address
	To        string                 // Receiver's address
	Metadata  map[string]interface{} // Additional data related to the transaction
	Hash      string                 // Hash of the transaction for integrity verification
}

// Ledger is the system that records all transactions
type Ledger struct {
	transactions map[string]Transaction // A map to store transactions by their ID
}

// NewLedger creates a new instance of Ledger
func NewLedger() *Ledger {
	return &Ledger{
		transactions: make(map[string]Transaction),
	}
}

// AddTransaction records a new transaction in the ledger
func (l *Ledger) AddTransaction(transactionType TransactionType, amount float64, tokenID, from, to string, metadata map[string]interface{}) (*Transaction, error) {
	if amount <= 0 {
		return nil, errors.New("transaction amount must be positive")
	}

	transactionID, err := generateUniqueID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	transaction := Transaction{
		ID:        transactionID,
		Type:      transactionType,
		Timestamp: time.Now(),
		Amount:    amount,
		TokenID:   tokenID,
		From:      from,
		To:        to,
		Metadata:  metadata,
	}

	transaction.Hash = generateTransactionHash(transaction)
	l.transactions[transactionID] = transaction

	return &transaction, nil
}

// GetTransactionByID retrieves a transaction by its ID
func (l *Ledger) GetTransactionByID(transactionID string) (*Transaction, error) {
	transaction, exists := l.transactions[transactionID]
	if !exists {
		return nil, errors.New("transaction not found")
	}
	return &transaction, nil
}

// VerifyTransactionHash checks the integrity of a transaction using its hash
func (l *Ledger) VerifyTransactionHash(transactionID string) (bool, error) {
	transaction, err := l.GetTransactionByID(transactionID)
	if err != nil {
		return false, err
	}

	expectedHash := generateTransactionHash(*transaction)
	return transaction.Hash == expectedHash, nil
}

// generateUniqueID generates a unique identifier for transactions
func generateUniqueID() (string, error) {
	// For simplicity, we're using a timestamp-based ID; for real-world use, consider more secure methods.
	now := time.Now().UnixNano()
	hash := sha256.New()
	_, err := hash.Write([]byte(fmt.Sprintf("%d", now)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// generateTransactionHash generates a hash for a transaction
func generateTransactionHash(transaction Transaction) string {
	data := fmt.Sprintf("%s:%s:%f:%s:%s:%s", transaction.ID, transaction.Type, transaction.Amount, transaction.TokenID, transaction.From, transaction.To)
	hash := sha256.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
