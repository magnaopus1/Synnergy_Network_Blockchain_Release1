package payment_fractals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// PaymentHistoryEntry represents an entry in the payment history for a bill.
type PaymentHistoryEntry struct {
	PaymentID   string    `json:"payment_id"`
	BillID      string    `json:"bill_id"`
	Payer       string    `json:"payer"`
	Amount      float64   `json:"amount"`
	PaymentDate time.Time `json:"payment_date"`
	Status      string    `json:"status"`
}

// PaymentHistoryDB represents the database for managing payment history entries.
type PaymentHistoryDB struct {
	DB *leveldb.DB
}

// NewPaymentHistoryDB creates a new PaymentHistoryDB instance.
func NewPaymentHistoryDB(dbPath string) (*PaymentHistoryDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentHistoryDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (phdb *PaymentHistoryDB) CloseDB() error {
	return phdb.DB.Close()
}

// AddPaymentHistoryEntry adds a new payment history entry to the database.
func (phdb *PaymentHistoryDB) AddPaymentHistoryEntry(entry PaymentHistoryEntry) error {
	if err := phdb.ValidatePaymentHistoryEntry(entry); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return phdb.DB.Put([]byte("payment_history_"+entry.PaymentID), data, nil)
}

// GetPaymentHistoryEntry retrieves a payment history entry by its payment ID.
func (phdb *PaymentHistoryDB) GetPaymentHistoryEntry(paymentID string) (*PaymentHistoryEntry, error) {
	data, err := phdb.DB.Get([]byte("payment_history_"+paymentID), nil)
	if err != nil {
		return nil, err
	}
	var entry PaymentHistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// GetAllPaymentHistoryEntries retrieves all payment history entries from the database.
func (phdb *PaymentHistoryDB) GetAllPaymentHistoryEntries() ([]PaymentHistoryEntry, error) {
	var entries []PaymentHistoryEntry
	iter := phdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var entry PaymentHistoryEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return entries, nil
}

// ValidatePaymentHistoryEntry ensures the payment history entry is valid before adding it to the database.
func (phdb *PaymentHistoryDB) ValidatePaymentHistoryEntry(entry PaymentHistoryEntry) error {
	if entry.PaymentID == "" {
		return errors.New("payment ID must be provided")
	}
	if entry.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if entry.Payer == "" {
		return errors.New("payer must be provided")
	}
	if entry.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if entry.PaymentDate.IsZero() {
		return errors.New("payment date must be provided")
	}
	if entry.Status == "" {
		return errors.New("status must be provided")
	}
	return nil
}

// UpdatePaymentHistoryEntry updates an existing payment history entry in the database.
func (phdb *PaymentHistoryDB) UpdatePaymentHistoryEntry(entry PaymentHistoryEntry) error {
	if _, err := phdb.GetPaymentHistoryEntry(entry.PaymentID); err != nil {
		return err
	}
	if err := phdb.ValidatePaymentHistoryEntry(entry); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return phdb.DB.Put([]byte("payment_history_"+entry.PaymentID), data, nil)
}

// DeletePaymentHistoryEntry removes a payment history entry from the database.
func (phdb *PaymentHistoryDB) DeletePaymentHistoryEntry(paymentID string) error {
	return phdb.DB.Delete([]byte("payment_history_"+paymentID), nil)
}

// SearchPaymentHistoryByBillID retrieves all payment history entries for a specific bill ID.
func (phdb *PaymentHistoryDB) SearchPaymentHistoryByBillID(billID string) ([]PaymentHistoryEntry, error) {
	var entries []PaymentHistoryEntry
	iter := phdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var entry PaymentHistoryEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			return nil, err
		}
		if entry.BillID == billID {
			entries = append(entries, entry)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return entries, nil
}

// SearchPaymentHistoryByPayer retrieves all payment history entries for a specific payer.
func (phdb *PaymentHistoryDB) SearchPaymentHistoryByPayer(payer string) ([]PaymentHistoryEntry, error) {
	var entries []PaymentHistoryEntry
	iter := phdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var entry PaymentHistoryEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			return nil, err
		}
		if entry.Payer == payer {
			entries = append(entries, entry)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return entries, nil
}

// SearchPaymentHistoryByDateRange retrieves all payment history entries within a specific date range.
func (phdb *PaymentHistoryDB) SearchPaymentHistoryByDateRange(startDate, endDate time.Time) ([]PaymentHistoryEntry, error) {
	var entries []PaymentHistoryEntry
	iter := phdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var entry PaymentHistoryEntry
		if err := json.Unmarshal(iter.Value(), &entry); err != nil {
			return nil, err
		}
		if entry.PaymentDate.After(startDate) && entry.PaymentDate.Before(endDate) {
			entries = append(entries, entry)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return entries, nil
}
