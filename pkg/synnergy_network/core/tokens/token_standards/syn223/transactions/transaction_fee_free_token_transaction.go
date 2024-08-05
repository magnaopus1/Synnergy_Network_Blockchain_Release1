package transactions

import (
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn223/utils"
)

// FeeFreeTransaction represents a SYN223 token transaction without a fee
type FeeFreeTransaction struct {
	ID            string
	From          string
	To            string
	Amount        float64
	Timestamp     time.Time
	Status        string
	ErrorMessage  string
	Metadata      map[string]interface{}
}

// FeeFreeTransactionManager handles the creation and management of fee-free transactions
type FeeFreeTransactionManager struct {
	Ledger              *ledger.Ledger
	AccessControl       *security.AccessControl
	WhitelistBlacklist  *security.WhitelistBlacklist
	ReversionMechanism  *security.ReversionMechanism
	TransactionRecords  map[string]FeeFreeTransaction
}

// NewFeeFreeTransactionManager initializes a new FeeFreeTransactionManager instance
func NewFeeFreeTransactionManager(ledger *ledger.Ledger, accessControl *security.AccessControl, whitelistBlacklist *security.WhitelistBlacklist, reversionMechanism *security.ReversionMechanism) *FeeFreeTransactionManager {
	return &FeeFreeTransactionManager{
		Ledger:             ledger,
		AccessControl:      accessControl,
		WhitelistBlacklist: whitelistBlacklist,
		ReversionMechanism: reversionMechanism,
		TransactionRecords: make(map[string]FeeFreeTransaction),
	}
}

// CreateFeeFreeTransaction creates a new SYN223 token transaction without a fee
func (fftm *FeeFreeTransactionManager) CreateFeeFreeTransaction(from, to string, amount float64, metadata map[string]interface{}) (FeeFreeTransaction, error) {
	if err := fftm.preTransferChecks(from, to, amount); err != nil {
		return FeeFreeTransaction{}, err
	}

	tx := FeeFreeTransaction{
		ID:        utils.GenerateTransactionID(),
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
		Status:    "pending",
		Metadata:  metadata,
	}

	fftm.TransactionRecords[tx.ID] = tx

	if err := fftm.executeTransaction(&tx); err != nil {
		return tx, err
	}

	tx.Status = "completed"
	fftm.TransactionRecords[tx.ID] = tx
	return tx, nil
}

// preTransferChecks performs pre-transfer validation and checks
func (fftm *FeeFreeTransactionManager) preTransferChecks(from, to string, amount float64) error {
	if !fftm.Ledger.IsValidAddress(from) || !fftm.Ledger.IsValidAddress(to) {
		return fmt.Errorf("invalid sender or receiver address")
	}

	if err := fftm.WhitelistBlacklist.CheckRestrictions(to); err != nil {
		return err
	}

	if !fftm.Ledger.HasSufficientBalance(from, amount) {
		return fmt.Errorf("insufficient balance")
	}

	return nil
}

// executeTransaction executes the transaction and updates the ledger
func (fftm *FeeFreeTransactionManager) executeTransaction(tx *FeeFreeTransaction) error {
	if err := fftm.Ledger.Debit(tx.From, tx.Amount); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		fftm.TransactionRecords[tx.ID] = *tx
		return err
	}

	if err := fftm.Ledger.Credit(tx.To, tx.Amount); err != nil {
		tx.Status = "failed"
		tx.ErrorMessage = err.Error()
		fftm.TransactionRecords[tx.ID] = *tx
		return fftm.ReversionMechanism.RevertTransaction(tx.From, tx.Amount)
	}

	return nil
}

// GetFeeFreeTransaction returns the details of a fee-free transaction by its ID
func (fftm *FeeFreeTransactionManager) GetFeeFreeTransaction(txID string) (FeeFreeTransaction, error) {
	tx, exists := fftm.TransactionRecords[txID]
	if !exists {
		return FeeFreeTransaction{}, fmt.Errorf("transaction not found")
	}
	return tx, nil
}

// LogFeeFreeTransaction logs the transaction details in the ledger
func (fftm *FeeFreeTransactionManager) LogFeeFreeTransaction(tx FeeFreeTransaction) error {
	return fftm.Ledger.LogTransaction(tx)
}
