package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/security"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/storage"
)

// TransactionType defines the type of a transaction.
type TransactionType string

const (
	Transfer   TransactionType = "TRANSFER"
	Minting    TransactionType = "MINTING"
	Burning    TransactionType = "BURNING"
)

// Transaction represents a single transaction record in the ledger.
type Transaction struct {
	TransactionID string
	TokenID       string
	FromAddress   string
	ToAddress     string
	Amount        uint64
	Fee           uint64
	Type          TransactionType
	Timestamp     time.Time
	Signature     string
	Memo          string
}

// TransactionRecords manages all transactions in the ledger.
type TransactionRecords struct {
	transactions map[string]Transaction
	store        storage.Storage
}

// NewTransactionRecords initializes a new TransactionRecords instance.
func NewTransactionRecords(store storage.Storage) *TransactionRecords {
	return &TransactionRecords{
		transactions: make(map[string]Transaction),
		store:        store,
	}
}

// AddTransaction adds a new transaction to the ledger.
func (tr *TransactionRecords) AddTransaction(tx Transaction) error {
	if _, exists := tr.transactions[tx.TransactionID]; exists {
		return errors.New("transaction already exists in the ledger")
	}

	// Sign the transaction
	tx.Signature = tr.signTransaction(tx)

	tr.transactions[tx.TransactionID] = tx
	return tr.store.Save(tx.TransactionID, tx)
}

// GetTransaction retrieves a transaction by its ID.
func (tr *TransactionRecords) GetTransaction(transactionID string) (Transaction, error) {
	tx, exists := tr.transactions[transactionID]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}

	return tx, nil
}

// VerifyTransaction verifies the integrity of a transaction.
func (tr *TransactionRecords) VerifyTransaction(transactionID string) (bool, error) {
	tx, exists := tr.transactions[transactionID]
	if !exists {
		return false, errors.New("transaction not found")
	}

	// Verify the signature
	if !tr.verifyTransaction(tx) {
		return false, errors.New("transaction signature verification failed")
	}

	return true, nil
}

// GetTransactionsByAddress retrieves all transactions involving a specific address.
func (tr *TransactionRecords) GetTransactionsByAddress(address string) []Transaction {
	var result []Transaction
	for _, tx := range tr.transactions {
		if tx.FromAddress == address || tx.ToAddress == address {
			result = append(result, tx)
		}
	}
	return result
}

// GetTransactionsByToken retrieves all transactions involving a specific token ID.
func (tr *TransactionRecords) GetTransactionsByToken(tokenID string) []Transaction {
	var result []Transaction
	for _, tx := range tr.transactions {
		if tx.TokenID == tokenID {
			result = append(result, tx)
		}
	}
	return result
}

// signTransaction signs the transaction data.
func (tr *TransactionRecords) signTransaction(tx Transaction) string {
	data := tx.TransactionID + tx.TokenID + tx.FromAddress + tx.ToAddress + tx.Timestamp.String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// verifyTransaction verifies the transaction signature.
func (tr *TransactionRecords) verifyTransaction(tx Transaction) bool {
	expectedSignature := tr.signTransaction(tx)
	return expectedSignature == tx.Signature
}
