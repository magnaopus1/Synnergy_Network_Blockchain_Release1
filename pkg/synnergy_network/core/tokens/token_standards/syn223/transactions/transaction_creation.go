package transactions

import (
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// Transaction represents a SYN223 token transaction
type Transaction struct {
	ID            string
	From          string
	To            string
	Amount        float64
	Timestamp     time.Time
	Status        string
	ErrorMessage  string
	Metadata      map[string]interface{}
}

// TransactionManager handles the creation and management of transactions
type TransactionManager struct {
	Ledger              *ledger.Ledger
	AccessControl       *security.AccessControl
	WhitelistBlacklist  *security.WhitelistBlacklist
	ReversionMechanism  *security.ReversionMechanism
	TransactionRecords  map[string]Transaction
}

// NewTransactionManager initializes a new TransactionManager instance
func NewTransactionManager(ledger *ledger.Ledger, accessControl *security.AccessControl, whitelistBlacklist *security.WhitelistBlacklist, reversionMechanism *security.ReversionMechanism) *TransactionManager {
	return &TransactionManager{
		Ledger:             ledger,
		AccessControl:      accessControl,
		WhitelistBlacklist: whitelistBlacklist,
		ReversionMechanism: reversionMechanism,
		TransactionRecords: make(map[string]Transaction),
	}
}

// CreateTransaction creates a new SYN223 token transaction
func (tm *TransactionManager) CreateTransaction(from, to string, amount float64, metadata map[string]interface{}) (Transaction, error) {
	if err := tm.preTransferChecks(from, to, amount); err != nil {
		return Transaction{}, err
	}

	tx := Transaction{
		ID:        utils.GenerateTransactionID(),
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
		Status:    "pending",
		Metadata:  metadata,
	}

	tm.TransactionRecords[tx.ID] = tx

	if err := tm.executeTransaction(&tx); err != nil {
		return tx, err
	}

	tx.Status = "completed"
	tm.TransactionRecords[tx.ID] = tx
	return tx, nil
}

// preTransferChecks performs pre-transfer validation and checks
func (tm *TransactionManager) preTransferChecks(from, to string, amount float64) error {
	if !tm.Ledger.IsValidAddress(from) || !tm.Ledger.IsValidAddress(to) {
		return fmt.Errorf("invalid sender or receiver address")
	}

	if err := tm.WhitelistBlacklist.CheckRestrictions(to); err != nil {
		return err
	}

	if !tm.Ledger.HasSufficientBalance(from, amount) {
		return fmt.Errorf("insufficient balance")
	}

	return nil
}

// executeTransaction executes the transaction and updates the ledger
func (tm *TransactionManager) executeTransaction(tx *Transaction) error {
	if err := tm.Ledger.Debit(tx.From, tx.Amount); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		tm.TransactionRecords[tx.ID] = *tx
		return err
	}

	if err := tm.Ledger.Credit(tx.To, tx.Amount); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		tm.TransactionRecords[tx.ID] = *tx
		return tm.ReversionMechanism.RevertTransaction(tx.From, tx.Amount)
	}

	return nil
}

// GetTransaction returns the details of a transaction by its ID
func (tm *TransactionManager) GetTransaction(txID string) (Transaction, error) {
	tx, exists := tm.TransactionRecords[txID]
	if !exists {
		return Transaction{}, fmt.Errorf("transaction not found")
	}
	return tx, nil
}

// LogTransaction logs the transaction details in the ledger
func (tm *TransactionManager) LogTransaction(tx Transaction) error {
	return tm.Ledger.LogTransaction(tx)
}
