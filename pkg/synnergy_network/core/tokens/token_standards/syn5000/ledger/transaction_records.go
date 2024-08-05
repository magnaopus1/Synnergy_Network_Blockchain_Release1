// transaction_records.go

package ledger

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// TransactionType defines the type of transaction (e.g., transfer, bet, payout)
type TransactionType string

const (
	Transfer TransactionType = "TRANSFER"
	Bet      TransactionType = "BET"
	Payout   TransactionType = "PAYOUT"
)

// TransactionRecord represents a record of a transaction in the system
type TransactionRecord struct {
	TransactionID   string                 // Unique identifier for the transaction
	TokenID         string                 // Identifier for the gambling token involved
	From            string                 // Address of the sender
	To              string                 // Address of the receiver
	Amount          float64                // Amount of tokens transferred
	Type            TransactionType        // Type of the transaction
	Timestamp       time.Time              // Time when the transaction was executed
	AdditionalData  map[string]interface{} // Additional data related to the transaction
	Hash            string                 // Hash of the record for integrity verification
}

// TransactionLedger manages the transaction records of gambling tokens
type TransactionLedger struct {
	records map[string]TransactionRecord // Maps transaction IDs to their records
}

// NewTransactionLedger creates a new instance of TransactionLedger
func NewTransactionLedger() *TransactionLedger {
	return &TransactionLedger{
		records: make(map[string]TransactionRecord),
	}
}

// AddTransactionRecord adds a new transaction record to the ledger
func (tl *TransactionLedger) AddTransactionRecord(transactionID, tokenID, from, to string, amount float64, tType TransactionType, additionalData map[string]interface{}) (*TransactionRecord, error) {
	if transactionID == "" || tokenID == "" || from == "" || to == "" {
		return nil, errors.New("transaction ID, token ID, from, and to must not be empty")
	}

	record := TransactionRecord{
		TransactionID:  transactionID,
		TokenID:        tokenID,
		From:           from,
		To:             to,
		Amount:         amount,
		Type:           tType,
		Timestamp:      time.Now(),
		AdditionalData: additionalData,
	}

	record.Hash = generateTransactionRecordHash(record)
	tl.records[transactionID] = record

	return &record, nil
}

// GetTransactionRecord retrieves the transaction record for a specific transaction ID
func (tl *TransactionLedger) GetTransactionRecord(transactionID string) (*TransactionRecord, error) {
	record, exists := tl.records[transactionID]
	if !exists {
		return nil, errors.New("transaction record not found")
	}
	return &record, nil
}

// VerifyTransactionRecordHash verifies the integrity of a transaction record using its hash
func (tl *TransactionLedger) VerifyTransactionRecordHash(transactionID string) (bool, error) {
	record, err := tl.GetTransactionRecord(transactionID)
	if err != nil {
		return false, err
	}

	expectedHash := generateTransactionRecordHash(*record)
	return record.Hash == expectedHash, nil
}

// generateTransactionRecordHash generates a hash for the transaction record to ensure data integrity
func generateTransactionRecordHash(record TransactionRecord) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%f:%s:%s", record.TransactionID, record.TokenID, record.From, record.To, record.Amount, record.Type, record.Timestamp)
	hash := sha256.New()
	hash.Write([]byte(data))
	return fmt.Sprintf("%x", hash.Sum(nil))
}
