package transactions

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/you/yourproject/pkg/cryptography"
	"github.com/you/yourproject/pkg/synnergy_network/core/tokens/token_standards/syn3200/ledger"
	"github.com/you/yourproject/pkg/synnergy_network/core/tokens/token_standards/syn3200/assets"
	"golang.org/x/crypto/scrypt"
)

// Transaction represents a transaction within the SYN3200 standard
type Transaction struct {
	TransactionID string    `json:"transaction_id"`
	BillID        string    `json:"bill_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
	Signature     string    `json:"signature"`
	Status        string    `json:"status"`
}

// TransactionManager manages the creation and validation of transactions
type TransactionManager struct {
	ledgerManager      *ledger.LedgerManager
	billOwnershipVerif *assets.BillOwnershipVerification
}

// NewTransactionManager initializes a new TransactionManager
func NewTransactionManager(ledgerManager *ledger.LedgerManager, billOwnershipVerif *assets.BillOwnershipVerification) *TransactionManager {
	return &TransactionManager{
		ledgerManager:      ledgerManager,
		billOwnershipVerif: billOwnershipVerif,
	}
}

// CreateTransaction creates a new transaction
func (tm *TransactionManager) CreateTransaction(transaction *Transaction) error {
	if !tm.billOwnershipVerif.VerifyOwnership(transaction.BillID, transaction.From) {
		return errors.New("ownership verification failed")
	}

	transaction.Timestamp = time.Now()
	transaction.Status = "pending"

	transactionID, err := generateTransactionID(transaction)
	if err != nil {
		return err
	}
	transaction.TransactionID = transactionID

	signature, err := signTransaction(transaction)
	if err != nil {
		return err
	}
	transaction.Signature = signature

	err = tm.ledgerManager.RecordTransaction(transaction)
	if err != nil {
		return err
	}

	return nil
}

// ValidateTransaction validates a transaction
func (tm *TransactionManager) ValidateTransaction(transactionID string) error {
	transaction, err := tm.ledgerManager.GetTransaction(transactionID)
	if err != nil {
		return err
	}

	if transaction.Status != "pending" {
		return errors.New("transaction already processed or invalid status")
	}

	if !verifyTransactionSignature(transaction) {
		return errors.New("invalid transaction signature")
	}

	transaction.Status = "validated"
	err = tm.ledgerManager.UpdateTransactionStatus(transactionID, "validated")
	if err != nil {
		return err
	}

	return nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID(transaction *Transaction) (string, error) {
	data, err := json.Marshal(transaction)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return string(hash[:]), nil
}

// signTransaction signs the transaction data
func signTransaction(transaction *Transaction) (string, error) {
	key := generateKey(transaction.TransactionID)
	data, err := json.Marshal(transaction)
	if err != nil {
		return "", err
	}
	return cryptography.SignData(data, key)
}

// verifyTransactionSignature verifies the signature of the transaction
func verifyTransactionSignature(transaction *Transaction) bool {
	key := generateKey(transaction.TransactionID)
	data, err := json.Marshal(transaction)
	if err != nil {
		return false
	}
	return cryptography.VerifySignature(data, transaction.Signature, key)
}

// generateKey generates a key for signing and verifying the transaction
func generateKey(transactionID string) []byte {
	key, _ := scrypt.Key([]byte(transactionID), []byte("somesalt"), 32768, 8, 1, 32)
	return key
}
