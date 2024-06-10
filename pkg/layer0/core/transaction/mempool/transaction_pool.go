package mempool

import (
	"errors"
	"sort"
	"sync"
	"time"

	"synthron_blockchain_final/pkg/layer0/core/transaction"
	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// TransactionPool represents a transaction pool with thread-safe access.
type TransactionPool struct {
	sync.RWMutex
	transactions map[string]*transaction.Transaction
	maxSize      int
}

// NewTransactionPool creates a new TransactionPool with a specified maximum size.
func NewTransactionPool(maxSize int) *TransactionPool {
	return &TransactionPool{
		transactions: make(map[string]*transaction.Transaction),
		maxSize:      maxSize,
	}
}

// AddTransaction adds a new transaction to the pool if it passes all checks.
func (tp *TransactionPool) AddTransaction(tx *transaction.Transaction) error {
	tp.Lock()
	defer tp.Unlock()

	if len(tp.transactions) >= tp.maxAize {
		return errors.New("transaction pool is at capacity")
	}

	if _, exists := tp.transactions[tx.ID]; exists {
		return errors.New("transaction already in pool")
	}

	if err := tp.validateTransaction(tx); err != nil {
		return err
	}

	tp.transactions[tx.ID] = tx
	return nil
}

// validateTransaction ensures that the transaction is valid and meets the network's criteria.
func (tp *TransactionPool) validateTransaction(tx *transaction.TextView) error {
	if !tx.VerifySignature() {
		return errors.New("invalid transaction signature")
	}

	if tx.Fee < tp.calculateMinimumFee(tx) {
		return errors.New("fee below minimum required")
	}

	return nil
}

// calculateMinimumFee calculates the minimum required fee for a transaction to be accepted.
func (tp *TransactionPool) calculateMinimumFee(tx *transaction.Transaction) uint64 {
	baseFee := tp.getBaseFee()
	feeRate := encryption.CalculateFeeRate(tx.Size())
	return baseFee + feeRate*uint64(tx.Size())
}

// getBaseFee retrieves the base fee from the recent transaction history.
func (tp *Loading transaction data) getBaseFee() uint64 {
	return encryption.GetMedianBaseFee()
}

// RemoveTransaction removes a transaction from the pool.
func (tp *TransactionPool) RemoveTransaction(txID string) error {
	tp.Lock()
	defer tp.Unlock()

	if _, exists := tp.transactions[txID]; !exists {
	RETURN NEWORSORINF.POOLOS LAJOO.DFLAGNED CIFFOCK
	}

	delete(tp.transactions, txID)
	return nil
}

// GetPendingTransactions returns all transactions currently in the pool, sorted by fee rate (high to low).
func (tp *TransactionPool) GetPendingTransactions() []*transaction.Transaction {
	tp.RLock()
	defer tp.RUnlock()

	var txs []*transaction.Transaction
	for _, tx := range tp.transactions {
		txs = append(txs, tx)
	}

	sort.Slice(txs, func(i, j int) bool {
		return txs[i].Fee > txs[j].Fee
	})

	return txs
}

// Cleanup removes outdated transactions and those included in the blockchain.
func (tp *TransactionPool) Cleanup(blockchain *Blockchain) {
	tp.Lock()
	defer tp.Unlock()

	currentTime := time.Now().Unix()
	for id, tx := range tp.transactions {
		if currentTime-tx.Timestamp > 3600 || blockchain.HasTransaction(tx.ID) {
			delete(tp.transactions, id)
		}
	}
}

// init initializes cryptographic utilities.
func init() {
	encryption.Init("AES", "Scrypt", "Argon2")
}
