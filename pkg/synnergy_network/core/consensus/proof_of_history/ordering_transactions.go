package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Transaction represents a blockchain transaction with a timestamp and cryptographic hash.
type Transaction struct {
	ID          string
	Timestamp   time.Time
	Data        string
	Hash        string
	PreviousHash string
}

// TransactionOrderer encapsulates methods for ordering transactions using PoH.
type TransactionOrderer struct {
	transactions []*Transaction
	lastHash     string
	mu           sync.Mutex
}

// NewTransactionOrderer creates a new transaction orderer with an initial hash.
func NewTransactionOrderer(initialHash string) *TransactionOrderer {
	return &TransactionOrderer{
		lastHash: initialHash,
	}
}

// AddTransaction adds a new transaction to the ledger, assigning it a timestamp and linking it to the previous hash.
func (to *TransactionOrderer) AddTransaction(data string) {
	to.mu.Lock()
	defer to.mu.Unlock()

	transaction := &Transaction{
		ID:          generateUUID(),
		Timestamp:   time.Now(),
		Data:        data,
		PreviousHash: to.lastHash,
	}
	transaction.Hash = to.generateHash(transaction)
	to.transactions = append(to.transactions, transaction)
	to.lastHash = transaction.Hash
}

// generateHash computes a SHA-256 hash for a transaction.
func (to *TransactionOrderer) generateHash(t *Transaction) string {
	record := fmt.Sprintf("%s%s%s", t.PreviousHash, t.Timestamp, t.Data)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// GetOrderedTransactions returns a list of transactions in the order they were added.
func (to *TransactionOrderer) GetOrderedTransactions() []*Transaction {
	to.mu.Lock()
	defer to.mu.Unlock()
	return to.transactions
}

// ValidateTransactionChain verifies the integrity of the transaction chain.
func (to *TransactionOrderer) ValidateTransactionChain() bool {
	to.mu.Lock()
	defer to.mu.Unlock()

	if len(to.transactions) == 0 {
		return true
	}

	for i := 1; i < len(to.transactions); i++ {
		if to.transactions[i].PreviousHash != to.transactions[i-1].Hash {
			return false
		}
	}

	return true
}

// generateUUID generates a unique identifier for a transaction. This is a placeholder and should use a robust UUID generation method suitable for production.
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

