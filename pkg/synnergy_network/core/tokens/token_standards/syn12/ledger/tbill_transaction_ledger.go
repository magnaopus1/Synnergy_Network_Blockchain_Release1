package ledger

import (
	"errors"
	"sync"
	"time"
)

// TBillTransaction represents a transaction involving SYN12 tokens.
type TBillTransaction struct {
	TransactionID string
	TokenID       string
	From          string
	To            string
	Amount        float64
	Timestamp     time.Time
}

// TBillTransactionLedger manages the ledger of all T-Bill transactions.
type TBillTransactionLedger struct {
	transactions map[string]TBillTransaction
	mutex        sync.RWMutex
}

// NewTBillTransactionLedger creates a new instance of TBillTransactionLedger.
func NewTBillTransactionLedger() *TBillTransactionLedger {
	return &TBillTransactionLedger{
		transactions: make(map[string]TBillTransaction),
	}
}

// RecordTransaction adds a new transaction to the ledger.
func (tl *TBillTransactionLedger) RecordTransaction(txID, tokenID, from, to string, amount float64) error {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	// Check if the transaction ID already exists
	if _, exists := tl.transactions[txID]; exists {
		return errors.New("transaction ID already exists in the ledger")
	}

	// Create a new transaction record
	transaction := TBillTransaction{
		TransactionID: txID,
		TokenID:       tokenID,
		From:          from,
		To:            to,
		Amount:        amount,
		Timestamp:     time.Now(),
	}

	// Add the transaction to the ledger
	tl.transactions[txID] = transaction
	return nil
}

// GetTransaction retrieves the details of a specific transaction.
func (tl *TBillTransactionLedger) GetTransaction(txID string) (TBillTransaction, error) {
	tl.mutex.RLock()
	defer tl.mutex.RUnlock()

	// Retrieve the transaction from the ledger
	transaction, exists := tl.transactions[txID]
	if !exists {
		return TBillTransaction{}, errors.New("transaction ID not found in the ledger")
	}

	return transaction, nil
}

// GetTransactionsByToken retrieves all transactions related to a specific token.
func (tl *TBillTransactionLedger) GetTransactionsByToken(tokenID string) ([]TBillTransaction, error) {
	tl.mutex.RLock()
	defer tl.mutex.RUnlock()

	var transactions []TBillTransaction
	for _, tx := range tl.transactions {
		if tx.TokenID == tokenID {
			transactions = append(transactions, tx)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the given token ID")
	}

	return transactions, nil
}

// GetTransactionsByAccount retrieves all transactions associated with a specific account.
func (tl *TBillTransactionLedger) GetTransactionsByAccount(accountID string) ([]TBillTransaction, error) {
	tl.mutex.RLock()
	defer tl.mutex.RUnlock()

	var transactions []TBillTransaction
	for _, tx := range tl.transactions {
		if tx.From == accountID || tx.To == accountID {
			transactions = append(transactions, tx)
		}
	}

	if len(transactions) == 0 {
		return nil, errors.New("no transactions found for the given account ID")
	}

	return transactions, nil
}

// DeleteTransaction removes a transaction from the ledger, typically used for error correction or fraud detection.
func (tl *TBillTransactionLedger) DeleteTransaction(txID string) error {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	// Remove the transaction from the ledger
	if _, exists := tl.transactions[txID]; !exists {
		return errors.New("transaction ID not found in the ledger")
	}

	delete(tl.transactions, txID)
	return nil
}

// ListAllTransactions returns all transactions in the ledger, typically used for auditing and regulatory purposes.
func (tl *TBillTransactionLedger) ListAllTransactions() ([]TBillTransaction, error) {
	tl.mutex.RLock()
	defer tl.mutex.RUnlock()

	if len(tl.transactions) == 0 {
		return nil, errors.New("no transactions found in the ledger")
	}

	var transactions []TBillTransaction
	for _, tx := range tl.transactions {
		transactions = append(transactions, tx)
	}

	return transactions, nil
}
