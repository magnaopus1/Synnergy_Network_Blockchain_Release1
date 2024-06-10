package mempool

import (
	"errors"
	"sync"
	"time"

	"synthron_blockchain_final/pkg/layer0/core/transaction"
	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// Mempool represents the transaction pool with mutex protection to handle concurrent access.
type Mempool struct {
	sync.Mutex
	Transactions []*transaction.Transaction
	maxSize      int
}

// NewMempool initializes a new transaction mempool with a given maximum size.
func NewMempool(maxSize int) *Mempool {
	return &Mempool{
		Transactions: make([]*transaction.Transaction, 0),
		maxSize:      maxSize,
	}
}

// AddTransaction adds a new transaction to the mempool if there is room and if it passes validation.
func (m *Mempool) AddTransaction(tx *transaction.Transaction) error {
	m.Lock()
	defer m.Unlock()

	if len(m.Transactions) >= m.maxSize {
		return errors.New("mempool is full")
	}

	if !tx.IsValid() {
		return errors.New("invalid transaction")
	}

	m.Transactions = append(m.Transactions, tx)
	return nil
}

// RemoveTransaction removes a transaction from the mempool, typically when it has been included in a block.
func (m *Mempool) RemoveTransaction(txID string) error {
	m.Lock()
	defer m.Unlock()

	for i, tx := range m.Transactions {
		if tx.ID == txID {
			m.Transactions = append(m.Transactions[:i], m.Transactions[i+1:]...)
			return nil
		}
	}
	return errors.New("transaction not found")
}

// GetPendingTransactions returns all transactions currently in the mempool.
func (m *Mempool) GetPendingTransactions() []*transaction.Transaction {
	m.Lock()
	defer m.Unlock()
	return m.Transactions
}

// Size returns the current number of transactions in the mempool.
func (m *Mempool) Size() int {
	m.Lock()
	defer m.Unlock()
	return len(m.Transactions)
}

// Cleanup periodically removes transactions that are too old or have been superseded.
func (m *Mempool) Cleanup() {
	m.Lock()
	defer m.Unlock()

	currentTime := time.Now().Unix()
	for i := 0; i < len(m.Transactions); {
		if currentTime-m.Transactions[i].Timestamp > 3600 { // 1 hour limit for transactions in the mempool
			m.Transactions = append(m.Transactions[:i], m.Transactions[i+1:]...)
			continue
		}
		i++
	}
}

// init initializes the cryptographic utilities and the transaction validator.
func init() {
	encryption.InitCryptoUtilities("Scrypt", "AES", "Argon2")
}

