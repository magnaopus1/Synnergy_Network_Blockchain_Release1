package ledger

import (
	"errors"
	"sync"
	"time"
)

// TransactionRecord represents a record of a transaction in the blockchain ledger.
type TransactionRecord struct {
	RecordID      string
	TransactionID string
	TokenID       string
	OwnerID       string
	Amount        float64
	Timestamp     time.Time
}

// TransactionRecords manages all transaction records.
type TransactionRecords struct {
	records map[string]TransactionRecord
	mutex   sync.RWMutex
}

// NewTransactionRecords creates a new instance of TransactionRecords.
func NewTransactionRecords() *TransactionRecords {
	return &TransactionRecords{
		records: make(map[string]TransactionRecord),
	}
}

// AddRecord adds a new transaction record to the ledger.
func (tr *TransactionRecords) AddRecord(recordID, txID, tokenID, ownerID string, amount float64) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	// Check if the record ID already exists
	if _, exists := tr.records[recordID]; exists {
		return errors.New("record ID already exists in the ledger")
	}

	// Create a new transaction record
	record := TransactionRecord{
		RecordID:      recordID,
		TransactionID: txID,
		TokenID:       tokenID,
		OwnerID:       ownerID,
		Amount:        amount,
		Timestamp:     time.Now(),
	}

	// Add the record to the ledger
	tr.records[recordID] = record
	return nil
}

// GetRecord retrieves a specific transaction record by its ID.
func (tr *TransactionRecords) GetRecord(recordID string) (TransactionRecord, error) {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	// Retrieve the record from the ledger
	record, exists := tr.records[recordID]
	if !exists {
		return TransactionRecord{}, errors.New("record ID not found in the ledger")
	}

	return record, nil
}

// GetRecordsByTransactionID retrieves all records associated with a specific transaction ID.
func (tr *TransactionRecords) GetRecordsByTransactionID(txID string) ([]TransactionRecord, error) {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	var records []TransactionRecord
	for _, record := range tr.records {
		if record.TransactionID == txID {
			records = append(records, record)
		}
	}

	if len(records) == 0 {
		return nil, errors.New("no records found for the given transaction ID")
	}

	return records, nil
}

// GetRecordsByTokenID retrieves all records associated with a specific token ID.
func (tr *TransactionRecords) GetRecordsByTokenID(tokenID string) ([]TransactionRecord, error) {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	var records []TransactionRecord
	for _, record := range tr.records {
		if record.TokenID == tokenID {
			records = append(records, record)
		}
	}

	if len(records) == 0 {
		return nil, errors.New("no records found for the given token ID")
	}

	return records, nil
}

// DeleteRecord removes a record from the ledger, typically used for correction or audit purposes.
func (tr *TransactionRecords) DeleteRecord(recordID string) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	// Remove the record from the ledger
	if _, exists := tr.records[recordID]; !exists {
		return errors.New("record ID not found in the ledger")
	}

	delete(tr.records, recordID)
	return nil
}

// ListAllRecords returns all transaction records in the ledger, typically used for auditing and regulatory purposes.
func (tr *TransactionRecords) ListAllRecords() ([]TransactionRecord, error) {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	if len(tr.records) == 0 {
		return nil, errors.New("no records found in the ledger")
	}

	var records []TransactionRecord
	for _, record := range tr.records {
		records = append(records, record)
	}

	return records, nil
}
