// Package ledger provides functionality for managing transaction records in the SYN4900 Token Standard.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// TransactionRecord represents a single transaction record in the ledger.
type TransactionRecord struct {
	TransactionID string
	Timestamp     time.Time
	From          string
	To            string
	TokenID       string
	Quantity      int
	Status        string
	Signature     string
}

// TransactionLedger manages the records of transactions for agricultural tokens.
type TransactionLedger struct {
	transactions map[string]TransactionRecord
	mutex        sync.Mutex
}

// NewTransactionLedger initializes and returns a new TransactionLedger.
func NewTransactionLedger() *TransactionLedger {
	return &TransactionLedger{
		transactions: make(map[string]TransactionRecord),
	}
}

// RecordTransaction logs a new transaction into the ledger.
func (tl *TransactionLedger) RecordTransaction(from, to, tokenID string, quantity int) (TransactionRecord, error) {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	// Validate inputs
	if from == "" || to == "" || tokenID == "" || quantity <= 0 {
		return TransactionRecord{}, errors.New("invalid transaction details")
	}

	// Create a new transaction record
	timestamp := time.Now()
	record := TransactionRecord{
		TransactionID: generateTransactionID(tokenID, from, to, timestamp),
		Timestamp:     timestamp,
		From:          from,
		To:            to,
		TokenID:       tokenID,
		Quantity:      quantity,
		Status:        "Pending",
	}

	// Sign the transaction record
	record.Signature = signTransactionRecord(record)

	// Save the transaction record
	tl.transactions[record.TransactionID] = record

	return record, nil
}

// VerifyTransaction verifies the authenticity and integrity of a transaction.
func (tl *TransactionLedger) VerifyTransaction(transactionID string) (bool, error) {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	record, exists := tl.transactions[transactionID]
	if !exists {
		return false, errors.New("transaction record not found")
	}

	// Verify the signature
	if !verifySignature(record) {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// GetTransaction retrieves a transaction record by its ID.
func (tl *TransactionLedger) GetTransaction(transactionID string) (TransactionRecord, error) {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	record, exists := tl.transactions[transactionID]
	if !exists {
		return TransactionRecord{}, errors.New("transaction record not found")
	}

	return record, nil
}

// ListTransactions returns a list of all transaction records.
func (tl *TransactionLedger) ListTransactions() []TransactionRecord {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()

	records := make([]TransactionRecord, 0, len(tl.transactions))
	for _, record := range tl.transactions {
		records = append(records, record)
	}

	return records
}

// generateTransactionID generates a unique transaction ID based on the token ID, participants, and timestamp.
func generateTransactionID(tokenID, from, to string, timestamp time.Time) string {
	data := tokenID + from + to + timestamp.String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// signTransactionRecord signs the transaction record using a hashing algorithm.
func signTransactionRecord(record TransactionRecord) string {
	data := record.TransactionID + record.From + record.To + record.TokenID + string(record.Quantity) + record.Timestamp.String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// verifySignature verifies the signature of a transaction record.
func verifySignature(record TransactionRecord) bool {
	expectedSignature := signTransactionRecord(record)
	return expectedSignature == record.Signature
}
