package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
)

// TransactionType defines the type of transaction (Transfer, Issue, Redeem, etc.)
type TransactionType string

const (
	TransactionTypeTransfer  TransactionType = "Transfer"
	TransactionTypeIssue     TransactionType = "Issue"
	TransactionTypeRedeem    TransactionType = "Redeem"
	TransactionTypeInterest  TransactionType = "Interest"
	TransactionTypeCoupon    TransactionType = "Coupon"
)

// TransactionRecord represents the details of a token transaction.
type TransactionRecord struct {
	TransactionID   string
	TokenID         string
	From            string
	To              string
	Amount          float64
	TransactionType TransactionType
	Timestamp       time.Time
	Status          string // Pending, Confirmed, Failed
	Metadata        map[string]interface{}
}

// TransactionLedger manages the transaction records for SYN11 tokens.
type TransactionLedger struct {
	mu             sync.Mutex
	transactions   map[string]TransactionRecord
	complianceSvc  *compliance.ComplianceService
	securitySvc    *security.SecurityService
}

// NewTransactionLedger creates a new TransactionLedger.
func NewTransactionLedger(complianceSvc *compliance.ComplianceService, securitySvc *security.SecurityService) *TransactionLedger {
	return &TransactionLedger{
		transactions:  make(map[string]TransactionRecord),
		complianceSvc: complianceSvc,
		securitySvc:   securitySvc,
	}
}

// RecordTransaction adds a new transaction record to the ledger.
func (ledger *TransactionLedger) RecordTransaction(record TransactionRecord) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	// Compliance and Security Checks
	if err := ledger.complianceSvc.ValidateTransaction(record); err != nil {
		return fmt.Errorf("compliance validation failed: %w", err)
	}

	if err := ledger.securitySvc.AuthorizeTransaction(record); err != nil {
		return fmt.Errorf("transaction authorization failed: %w", err)
	}

	// Record the Transaction
	record.Timestamp = time.Now()
	record.Status = "Confirmed"
	ledger.transactions[record.TransactionID] = record

	log.Printf("Transaction recorded: %v", record)
	return nil
}

// GetTransaction retrieves a transaction record by TransactionID.
func (ledger *TransactionLedger) GetTransaction(transactionID string) (TransactionRecord, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	record, exists := ledger.transactions[transactionID]
	if !exists {
		return TransactionRecord{}, fmt.Errorf("transaction record for ID %s not found", transactionID)
	}
	return record, nil
}

// ListTransactions returns all transaction records.
func (ledger *TransactionLedger) ListTransactions() []TransactionRecord {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	records := make([]TransactionRecord, 0, len(ledger.transactions))
	for _, record := range ledger.transactions {
		records = append(records, record)
	}
	return records
}

// UpdateTransaction updates the status of a transaction record.
func (ledger *TransactionLedger) UpdateTransaction(transactionID string, status string, metadata map[string]interface{}) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	record, exists := ledger.transactions[transactionID]
	if !exists {
		return fmt.Errorf("transaction record for ID %s not found", transactionID)
	}

	record.Status = status
	record.Metadata = metadata
	ledger.transactions[transactionID] = record

	log.Printf("Transaction updated for ID %s: %v", transactionID, record)
	return nil
}

// EncodeTransaction converts a transaction record into a JSON string.
func (ledger *TransactionLedger) EncodeTransaction(record TransactionRecord) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to encode transaction record: %w", err)
	}
	return string(data), nil
}

// DecodeTransaction parses a JSON string into a transaction record.
func (ledger *TransactionLedger) DecodeTransaction(data string) (TransactionRecord, error) {
	var record TransactionRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return TransactionRecord{}, fmt.Errorf("failed to decode transaction record: %w", err)
	}
	return record, nil
}
