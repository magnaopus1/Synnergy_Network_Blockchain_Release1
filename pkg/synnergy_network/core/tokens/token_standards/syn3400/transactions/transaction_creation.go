package transactions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/speculation"
)

const (
	transactionSaltSize = 16
)

// Transaction represents a Forex transaction
type Transaction struct {
	TransactionID string
	TokenID       string
	From          string
	To            string
	Amount        float64
	Timestamp     time.Time
	Status        string
}

// TransactionManager manages Forex transactions
type TransactionManager struct {
	transactions       []Transaction
	ledgerManager      *ledger.LedgerManager
	tokenManager       *assets.TokenManager
	eventLogger        *events.EventLogger
	speculationManager *speculation.SpeculationManager
}

// NewTransactionManager initializes a new TransactionManager instance
func NewTransactionManager(ledgerMgr *ledger.LedgerManager, tokenMgr *assets.TokenManager, eventLogger *events.EventLogger, speculationMgr *speculation.SpeculationManager) (*TransactionManager, error) {
	return &TransactionManager{
		transactions:       []Transaction{},
		ledgerManager:      ledgerMgr,
		tokenManager:       tokenMgr,
		eventLogger:        eventLogger,
		speculationManager: speculationMgr,
	}, nil
}

// generateTransactionID generates a unique ID for a transaction
func generateTransactionID() (string, error) {
	id := make([]byte, transactionSaltSize)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	hash := sha256.Sum256(id)
	return hex.EncodeToString(hash[:]), nil
}

// CreateTransaction creates a new Forex transaction
func (tm *TransactionManager) CreateTransaction(tokenID, from, to string, amount float64) (Transaction, error) {
	// Validate inputs
	if amount <= 0 {
		return Transaction{}, errors.New("amount must be greater than zero")
	}

	// Verify token ownership
	currentOwner, err := tm.tokenManager.GetOwner(tokenID)
	if err != nil {
		return Transaction{}, err
	}
	if currentOwner != from {
		return Transaction{}, errors.New("the from address does not own the token")
	}

	// Generate transaction ID
	transactionID, err := generateTransactionID()
	if err != nil {
		return Transaction{}, err
	}

	// Create a new transaction
	transaction := Transaction{
		TransactionID: transactionID,
		TokenID:       tokenID,
		From:          from,
		To:            to,
		Amount:        amount,
		Timestamp:     time.Now(),
		Status:        "pending",
	}

	// Record the transaction
	tm.transactions = append(tm.transactions, transaction)

	// Update ledger
	err = tm.ledgerManager.RecordTransaction(transaction.TransactionID, transaction.TokenID, transaction.From, transaction.To, transaction.Amount, transaction.Timestamp)
	if err != nil {
		return Transaction{}, err
	}

	// Update token ownership
	err = tm.tokenManager.TransferOwnership(tokenID, from, to)
	if err != nil {
		return Transaction{}, err
	}

	// Log event
	tm.logTransactionEvent(transaction)

	// Update transaction status
	transaction.Status = "completed"
	tm.updateTransactionStatus(transaction.TransactionID, "completed")

	return transaction, nil
}

// updateTransactionStatus updates the status of a transaction
func (tm *TransactionManager) updateTransactionStatus(transactionID, status string) error {
	for i, tx := range tm.transactions {
		if tx.TransactionID == transactionID {
			tm.transactions[i].Status = status
			return nil
		}
	}
	return errors.New("transaction not found")
}

// logTransactionEvent logs a transaction event
func (tm *TransactionManager) logTransactionEvent(transaction Transaction) {
	event := events.Event{
		Type:      "Transaction",
		Timestamp: transaction.Timestamp,
		Data: map[string]interface{}{
			"transactionID": transaction.TransactionID,
			"tokenID":       transaction.TokenID,
			"from":          transaction.From,
			"to":            transaction.To,
			"amount":        transaction.Amount,
			"status":        transaction.Status,
		},
	}
	tm.eventLogger.LogEvent(event)
}

// GetTransaction retrieves a transaction by ID
func (tm *TransactionManager) GetTransaction(transactionID string) (Transaction, error) {
	for _, tx := range tm.transactions {
		if tx.TransactionID == transactionID {
			return tx, nil
		}
	}
	return Transaction{}, errors.New("transaction not found")
}

// ListTransactions lists all transactions
func (tm *TransactionManager) ListTransactions() []Transaction {
	return tm.transactions
}
