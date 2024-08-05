// Package ledger provides functionalities to handle the transaction records for SYN3200 tokens.
package ledger

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// TransactionRecord represents the details of a transaction for a bill token.
type TransactionRecord struct {
	TransactionID string    `json:"transaction_id"`
	TokenID       string    `json:"token_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
}

// TransactionRecordsLedger manages the transaction records of bill tokens.
type TransactionRecordsLedger struct {
	DB *leveldb.DB
}

// NewTransactionRecordsLedger creates a new instance of TransactionRecordsLedger.
func NewTransactionRecordsLedger(dbPath string) (*TransactionRecordsLedger, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &TransactionRecordsLedger{DB: db}, nil
}

// CloseDB closes the database connection.
func (trl *TransactionRecordsLedger) CloseDB() error {
	return trl.DB.Close()
}

// AddTransactionRecord adds a new transaction record to the ledger.
func (trl *TransactionRecordsLedger) AddTransactionRecord(record TransactionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return trl.DB.Put([]byte("transaction_"+record.TransactionID), data, nil)
}

// GetTransactionRecord retrieves a transaction record by transaction ID.
func (trl *TransactionRecordsLedger) GetTransactionRecord(transactionID string) (*TransactionRecord, error) {
	data, err := trl.DB.Get([]byte("transaction_"+transactionID), nil)
	if err != nil {
		return nil, err
	}
	var record TransactionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// GetAllTransactionRecords retrieves all transaction records from the ledger.
func (trl *TransactionRecordsLedger) GetAllTransactionRecords() ([]TransactionRecord, error) {
	var records []TransactionRecord
	iter := trl.DB.NewIterator(util.BytesPrefix([]byte("transaction_")), nil)
	defer iter.Release()
	for iter.Next() {
		var record TransactionRecord
		if err := json.Unmarshal(iter.Value(), &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return records, nil
}

// GetTransactionRecordsByTokenID retrieves all transaction records for a specific token ID.
func (trl *TransactionRecordsLedger) GetTransactionRecordsByTokenID(tokenID string) ([]TransactionRecord, error) {
	var records []TransactionRecord
	iter := trl.DB.NewIterator(util.BytesPrefix([]byte("transaction_")), nil)
	defer iter.Release()
	for iter.Next() {
		var record TransactionRecord
		if err := json.Unmarshal(iter.Value(), &record); err != nil {
			return nil, err
		}
		if record.TokenID == tokenID {
			records = append(records, record)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return records, nil
}

// ValidateTransactionRecord ensures the transaction record is valid before adding it to the ledger.
func (trl *TransactionRecordsLedger) ValidateTransactionRecord(record TransactionRecord) error {
	if record.TransactionID == "" {
		return errors.New("transaction ID must be provided")
	}
	if record.TokenID == "" {
		return errors.New("token ID must be provided")
	}
	if record.From == "" || record.To == "" {
		return errors.New("both from and to addresses must be provided")
	}
	if record.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if record.Timestamp.IsZero() {
		return errors.New("timestamp must be provided")
	}
	// Add more validation rules as necessary
	return nil
}

// DeleteTransactionRecord removes a transaction record from the ledger.
func (trl *TransactionRecordsLedger) DeleteTransactionRecord(transactionID string) error {
	return trl.DB.Delete([]byte("transaction_"+transactionID), nil)
}

// UpdateTransactionRecord updates an existing transaction record in the ledger.
func (trl *TransactionRecordsLedger) UpdateTransactionRecord(record TransactionRecord) error {
	existingRecord, err := trl.GetTransactionRecord(record.TransactionID)
	if err != nil {
		return err
	}
	if existingRecord == nil {
		return errors.New("transaction record not found")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return trl.DB.Put([]byte("transaction_"+record.TransactionID), data, nil)
}
