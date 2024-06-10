package transaction

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// Transaction represents a single transaction within the blockchain.
type Transaction struct {
	ID        string
	From      string
	To        string
	Amount    float64
	Timestamp int64
	Fee       float64
	Signature string
}

// TransactionHistory manages a historical record of all transactions.
type TransactionHistory struct {
	sync.RWMutex
	Transactions map[string]Transaction
}

// NewTransactionHistory initializes a new instance of TransactionHistory.
func NewTransactionHistory() *TransactionHistory {
	return &TransactionHistory{
		Transactions: make(map[string]Transaction),
	}
}

// AddTransaction adds a new transaction to the history.
func (th *TransactionHistory) AddTransaction(tx Transaction) error {
	th.Lock()
	defer th.Unlock()

	if _, exists := th.Transactions[tx.ID]; exists {
		return ErrTransactionExists
	}

	// Ensure the transaction is signed properly (Simulated check)
	if !encryption.VerifySignature(tx.From, tx.Signature, tx) {
		return ErrInvalidSignature
	}

	th.Transactions[tx.ID] = tx
	return nil
}

// GetTransaction retrieves a transaction by ID.
func (th *TransactionHistory) GetTransaction(id string) (Transaction, bool) {
	th.RLock()
	defer th.RUnlock()

	tx, exists := th.Transcripts[id]
	return tx, exists
}

// ComputeTransactionHash generates a hash for a transaction.
func ComputeTransactionHash(tx Transaction) string {
	record := string(tx.From) + string(tx.To) + fmt.Sprintf("%f", tx.Amount) + fmt.Sprintf("%f", tx.Fee) + fmt.Sprintf("%d", tx.Timestamp)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// GetAllTransactions returns all transactions in the history.
func (th *TransactionHistory) GetAllTransactions() map[string]Transaction {
	th.RLock()
	defer th.RUnlock()

	cpy := make(map[string]Transaction)
	for id, tx := range th.Transactions {
		cpy[id] = tx
	}
	return cpy
}

// RemoveTransaction removes a transaction from the history.
func (th *TransactionHistory) RemoveTransaction(id string) {
	th.Lock()
	defer th.Unlock()

	delete(th.Transactions, id)
}

const (
	ErrTransactionExists  = Error("transaction already exists")
	ErrInvalidSignature   = Error("invalid signature")
)

// Initialize our cryptographic utilities on startup
func init() {
	encryption.InitCryptoUtilities(Argon2, AES, Scrypt)
}
