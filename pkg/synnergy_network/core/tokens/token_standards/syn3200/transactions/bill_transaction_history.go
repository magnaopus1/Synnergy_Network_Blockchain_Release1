package transactions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/you/yourproject/pkg/cryptography"
	"golang.org/x/crypto/scrypt"
)

// BillTransaction represents a single transaction for a bill token
type BillTransaction struct {
	TransactionID string    `json:"transaction_id"`
	BillID        string    `json:"bill_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"`
}

// BillTransactionHistory manages the history of bill transactions
type BillTransactionHistory struct {
	storagePath string
	mu          sync.Mutex
}

// NewBillTransactionHistory initializes a new BillTransactionHistory manager
func NewBillTransactionHistory(storagePath string) (*BillTransactionHistory, error) {
	err := os.MkdirAll(storagePath, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return &BillTransactionHistory{storagePath: storagePath}, nil
}

// RecordTransaction stores a new transaction in the history
func (bth *BillTransactionHistory) RecordTransaction(transaction BillTransaction) error {
	bth.mu.Lock()
	defer bth.mu.Unlock()

	transaction.Timestamp = time.Now()
	encryptedData, err := encryptTransactionData(transaction)
	if err != nil {
		return err
	}

	filename := filepath.Join(bth.storagePath, transaction.TransactionID+".json")
	return os.WriteFile(filename, encryptedData, os.ModePerm)
}

// GetTransaction retrieves a transaction by its ID
func (bth *BillTransactionHistory) GetTransaction(transactionID string) (*BillTransaction, error) {
	bth.mu.Lock()
	defer bth.mu.Unlock()

	filename := filepath.Join(bth.storagePath, transactionID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return decryptTransactionData(data)
}

// ListTransactions lists all transactions for a specific bill ID
func (bth *BillTransactionHistory) ListTransactions(billID string) ([]BillTransaction, error) {
	bth.mu.Lock()
	defer bth.mu.Unlock()

	var transactions []BillTransaction
	files, err := os.ReadDir(bth.storagePath)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(bth.storagePath, file.Name()))
		if err != nil {
			return nil, err
		}

		transaction, err := decryptTransactionData(data)
		if err != nil {
			return nil, err
		}
		if transaction.BillID == billID {
			transactions = append(transactions, *transaction)
		}
	}
	return transactions, nil
}

// DeleteTransaction deletes a transaction by its ID
func (bth *BillTransactionHistory) DeleteTransaction(transactionID string) error {
	bth.mu.Lock()
	defer bth.mu.Unlock()

	filename := filepath.Join(bth.storagePath, transactionID+".json")
	return os.Remove(filename)
}

// encryptTransactionData encrypts the transaction data using a generated key
func encryptTransactionData(transaction BillTransaction) ([]byte, error) {
	key := generateKey(transaction.TransactionID)
	data, err := json.Marshal(transaction)
	if err != nil {
		return nil, err
	}
	return cryptography.EncryptData(data, key)
}

// decryptTransactionData decrypts the transaction data using a generated key
func decryptTransactionData(data []byte) (*BillTransaction, error) {
	var encryptedTransaction map[string]interface{}
	err := json.Unmarshal(data, &encryptedTransaction)
	if err != nil {
		return nil, err
	}

	key := generateKey(encryptedTransaction["transaction_id"].(string))
	decryptedData, err := cryptography.DecryptData(data, key)
	if err != nil {
		return nil, err
	}

	var transaction BillTransaction
	err = json.Unmarshal(decryptedData, &transaction)
	if err != nil {
		return nil, err
	}
	return &transaction, nil
}

// generateKey generates a key for encryption and decryption
func generateKey(transactionID string) []byte {
	key, _ := scrypt.Key([]byte(transactionID), []byte("somesalt"), 32768, 8, 1, 32)
	return key
}
