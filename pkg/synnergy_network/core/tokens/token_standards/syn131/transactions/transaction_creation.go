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

// TransactionCreationService provides services for creating transactions.
type TransactionCreationService struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityService
}

// NewTransactionCreationService creates a new TransactionCreationService.
func NewTransactionCreationService(ledger *ledger.TransactionLedger, security *security.SecurityService) *TransactionCreationService {
	return &TransactionCreationService{ledger: ledger, security: security}
}

// CreateTransaction creates a new transaction and records it in the ledger.
func (service *TransactionCreationService) CreateTransaction(sender, receiver, assetID string, amount float64, privateKey string) (*Transaction, error) {
	// Generate a unique ID for the transaction
	hash := sha256.New()
	hash.Write([]byte(sender + receiver + assetID + time.Now().String()))
	id := hex.EncodeToString(hash.Sum(nil))

	// Create the transaction object
	txn := &Transaction{
		ID:        id,
		Sender:    sender,
		Receiver:  receiver,
		AssetID:   assetID,
		Amount:    amount,
		Timestamp: time.Now(),
	}

	// Generate a transaction hash
	txn.TransactionHash = service.generateTransactionHash(txn)

	// Sign the transaction
	signature, err := service.security.SignTransaction(txn.TransactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	txn.Signature = signature

	// Record the transaction in the ledger
	err = service.ledger.RecordTransaction(txn)
	if err != nil {
		return nil, err
	}

	return txn, nil
}

// VerifyTransaction verifies the authenticity of a transaction.
func (service *TransactionCreationService) VerifyTransaction(txn *Transaction, publicKey string) (bool, error) {
	// Verify the transaction hash
	expectedHash := service.generateTransactionHash(txn)
	if txn.TransactionHash != expectedHash {
		return false, errors.New("transaction hash mismatch")
	}

	// Verify the signature
	valid, err := service.security.VerifyTransaction(txn.TransactionHash, txn.Signature, publicKey)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// GetTransaction retrieves a transaction by ID.
func (service *TransactionCreationService) GetTransaction(id string) (*Transaction, error) {
	return service.ledger.GetTransactionByID(id)
}

// generateTransactionHash generates a hash for the transaction.
func (service *TransactionCreationService) generateTransactionHash(txn *Transaction) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s%s%s%f%s", txn.Sender, txn.Receiver, txn.AssetID, txn.Amount, txn.Timestamp.String())))
	return hex.EncodeToString(hash.Sum(nil))
}


