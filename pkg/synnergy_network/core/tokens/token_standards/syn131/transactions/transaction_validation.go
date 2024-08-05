package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
)

// Transaction represents a basic transaction structure.
type Transaction struct {
	ID              string    `json:"id"`
	Sender          string    `json:"sender"`
	Receiver        string    `json:"receiver"`
	AssetID         string    `json:"asset_id"`
	Amount          float64   `json:"amount"`
	Timestamp       time.Time `json:"timestamp"`
	Signature       string    `json:"signature"`
	TransactionHash string    `json:"transaction_hash"`
}

// TransactionValidationService provides services for validating transactions.
type TransactionValidationService struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityService
}

// NewTransactionValidationService creates a new TransactionValidationService.
func NewTransactionValidationService(ledger *ledger.TransactionLedger, security *security.SecurityService) *TransactionValidationService {
	return &TransactionValidationService{ledger: ledger, security: security}
}

// ValidateTransaction checks the validity of a transaction.
func (service *TransactionValidationService) ValidateTransaction(txn *Transaction) error {
	// Verify the transaction hash
	expectedHash := service.generateTransactionHash(txn)
	if txn.TransactionHash != expectedHash {
		return errors.New("transaction hash mismatch")
	}

	// Verify the signature
	valid, err := service.security.VerifyTransaction(txn.TransactionHash, txn.Signature, txn.Sender)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid transaction signature")
	}

	// Check for double spending
	existingTxn, err := service.ledger.GetTransactionByID(txn.ID)
	if err == nil && existingTxn != nil {
		return errors.New("transaction already exists")
	}

	// Additional custom validations can be added here

	return nil
}

// ValidateTransactionTimestamp checks if the transaction timestamp is within an acceptable range.
func (service *TransactionValidationService) ValidateTransactionTimestamp(txn *Transaction, maxDrift time.Duration) error {
	now := time.Now()
	if txn.Timestamp.After(now.Add(maxDrift)) || txn.Timestamp.Before(now.Add(-maxDrift)) {
		return errors.New("transaction timestamp is out of acceptable range")
	}
	return nil
}

// generateTransactionHash generates a hash for the transaction.
func (service *TransactionValidationService) generateTransactionHash(txn *Transaction) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s%s%s%f%s", txn.Sender, txn.Receiver, txn.AssetID, txn.Amount, txn.Timestamp.String())))
	return hex.EncodeToString(hash.Sum(nil))
}

