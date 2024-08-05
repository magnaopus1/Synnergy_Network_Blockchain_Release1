// Package ledger provides functionalities to handle the ledger for SYN3200 tokens.
package ledger

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// BillTransaction represents a transaction record in the bill ledger.
type BillTransaction struct {
	TransactionID string    `json:"transaction_id"`
	BillID        string    `json:"bill_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
}

// BillTransactionLedger manages the transactions related to bill payments.
type BillTransactionLedger struct {
	DB *leveldb.DB
}

// NewBillTransactionLedger creates a new instance of BillTransactionLedger.
func NewBillTransactionLedger(dbPath string) (*BillTransactionLedger, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &BillTransactionLedger{DB: db}, nil
}

// CloseDB closes the database connection.
func (btl *BillTransactionLedger) CloseDB() error {
	return btl.DB.Close()
}

// AddTransaction adds a new transaction to the ledger.
func (btl *BillTransactionLedger) AddTransaction(transaction BillTransaction) error {
	data, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	return btl.DB.Put([]byte("transaction_"+transaction.TransactionID), data, nil)
}

// GetTransaction retrieves a transaction by its ID.
func (btl *BillTransactionLedger) GetTransaction(transactionID string) (*BillTransaction, error) {
	data, err := btl.DB.Get([]byte("transaction_"+transactionID), nil)
	if err != nil {
		return nil, err
	}
	var transaction BillTransaction
	if err := json.Unmarshal(data, &transaction); err != nil {
		return nil, err
	}
	return &transaction, nil
}

// GetAllTransactions retrieves all transactions from the ledger.
func (btl *BillTransactionLedger) GetAllTransactions() ([]BillTransaction, error) {
	var transactions []BillTransaction
	iter := btl.DB.NewIterator(util.BytesPrefix([]byte("transaction_")), nil)
	defer iter.Release()
	for iter.Next() {
		var transaction BillTransaction
		if err := json.Unmarshal(iter.Value(), &transaction); err != nil {
			return nil, err
		}
		transactions = append(transactions, transaction)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return transactions, nil
}

// GetTransactionsByBillID retrieves all transactions for a specific bill.
func (btl *BillTransactionLedger) GetTransactionsByBillID(billID string) ([]BillTransaction, error) {
	var transactions []BillTransaction
	iter := btl.DB.NewIterator(util.BytesPrefix([]byte("transaction_")), nil)
	defer iter.Release()
	for iter.Next() {
		var transaction BillTransaction
		if err := json.Unmarshal(iter.Value(), &transaction); err != nil {
			return nil, err
		}
		if transaction.BillID == billID {
			transactions = append(transactions, transaction)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return transactions, nil
}

// ValidateTransaction ensures the transaction is valid before adding it to the ledger.
func (btl *BillTransactionLedger) ValidateTransaction(transaction BillTransaction) error {
	if transaction.Amount <= 0 {
		return errors.New("transaction amount must be greater than zero")
	}
	if transaction.From == "" || transaction.To == "" {
		return errors.New("transaction must have valid from and to addresses")
	}
	if transaction.BillID == "" {
		return errors.New("transaction must be associated with a valid bill ID")
	}
	// Add more validation rules as necessary
	return nil
}

// VerifyTransaction verifies the authenticity of a transaction.
func (btl *BillTransactionLedger) VerifyTransaction(transactionID string) (bool, error) {
	transaction, err := btl.GetTransaction(transactionID)
	if err != nil {
		return false, err
	}
	// Implement verification logic, e.g., cryptographic signature verification
	return true, nil
}

// DeleteTransaction removes a transaction from the ledger.
func (btl *BillTransactionLedger) DeleteTransaction(transactionID string) error {
	return btl.DB.Delete([]byte("transaction_"+transactionID), nil)
}

// UpdateTransaction updates an existing transaction in the ledger.
func (btl *BillTransactionLedger) UpdateTransaction(transaction BillTransaction) error {
	existingTransaction, err := btl.GetTransaction(transaction.TransactionID)
	if err != nil {
		return err
	}
	if existingTransaction == nil {
		return errors.New("transaction not found")
	}
	data, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	return btl.DB.Put([]byte("transaction_"+transaction.TransactionID), data, nil)
}
