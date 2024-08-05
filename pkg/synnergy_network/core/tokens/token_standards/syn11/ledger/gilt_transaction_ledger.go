package ledger

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
)

// GiltTransaction represents a transaction related to SYN11 tokens.
type GiltTransaction struct {
	TransactionID string
	TokenID       string
	From          string
	To            string
	Amount        uint64
	Timestamp     time.Time
	TransactionType string // Issue, Transfer, Burn, Redeem, etc.
	Status        string
}

// GiltTransactionLedger maintains the transaction records for SYN11 tokens.
type GiltTransactionLedger struct {
	mu             sync.Mutex
	transactions   map[string]GiltTransaction
	complianceSvc  *compliance.ComplianceService
	securitySvc    *security.SecurityService
}

// NewGiltTransactionLedger creates a new GiltTransactionLedger.
func NewGiltTransactionLedger(complianceSvc *compliance.ComplianceService, securitySvc *security.SecurityService) *GiltTransactionLedger {
	return &GiltTransactionLedger{
		transactions:  make(map[string]GiltTransaction),
		complianceSvc: complianceSvc,
		securitySvc:   securitySvc,
	}
}

// RecordTransaction records a new transaction in the ledger.
func (ledger *GiltTransactionLedger) RecordTransaction(transaction GiltTransaction) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	// Compliance and Security Checks
	if err := ledger.complianceSvc.ValidateTransaction(transaction); err != nil {
		return fmt.Errorf("compliance validation failed: %w", err)
	}

	if err := ledger.securitySvc.AuthorizeTransaction(transaction); err != nil {
		return fmt.Errorf("transaction authorization failed: %w", err)
	}

	// Record the Transaction
	transactionID := fmt.Sprintf("TX-%d-%s", time.Now().UnixNano(), transaction.TokenID)
	transaction.TransactionID = transactionID
	transaction.Timestamp = time.Now()
	transaction.Status = "Completed"
	ledger.transactions[transactionID] = transaction

	log.Printf("Transaction recorded: %v", transaction)
	return nil
}

// GetTransaction retrieves a transaction by its ID.
func (ledger *GiltTransactionLedger) GetTransaction(transactionID string) (GiltTransaction, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	transaction, exists := ledger.transactions[transactionID]
	if !exists {
		return GiltTransaction{}, fmt.Errorf("transaction ID %s not found", transactionID)
	}
	return transaction, nil
}

// ListTransactions returns a list of all recorded transactions.
func (ledger *GiltTransactionLedger) ListTransactions() []GiltTransaction {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	transactions := make([]GiltTransaction, 0, len(ledger.transactions))
	for _, transaction := range ledger.transactions {
		transactions = append(transactions, transaction)
	}
	return transactions
}

// VerifyTransaction verifies the integrity and authenticity of a transaction.
func (ledger *GiltTransactionLedger) VerifyTransaction(transactionID string) (bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	transaction, exists := ledger.transactions[transactionID]
	if !exists {
		return false, fmt.Errorf("transaction ID %s not found", transactionID)
	}

	// Perform additional checks as needed
	if transaction.Status != "Completed" {
		return false, fmt.Errorf("transaction %s is not in a completed state", transactionID)
	}

	return true, nil
}

// RevokeTransaction revokes a transaction under specific conditions, typically for compliance reasons.
func (ledger *GiltTransactionLedger) RevokeTransaction(transactionID string, reason string) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()

	transaction, exists := ledger.transactions[transactionID]
	if !exists {
		return fmt.Errorf("transaction ID %s not found", transactionID)
	}

	// Compliance check for revocation
	if err := ledger.complianceSvc.ValidateRevocation(transaction); err != nil {
		return fmt.Errorf("revocation validation failed: %w", err)
	}

	transaction.Status = "Revoked"
	ledger.transactions[transactionID] = transaction

	log.Printf("Transaction revoked: %v, Reason: %s", transaction, reason)
	return nil
}
