package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Transaction represents a single transaction in the ETF history
type Transaction struct {
	TransactionID   string    `json:"transaction_id"`
	Timestamp       time.Time `json:"timestamp"`
	Sender          string    `json:"sender"`
	Receiver        string    `json:"receiver"`
	Amount          float64   `json:"amount"`
	TransactionType string    `json:"transaction_type"`
}

// ETFTransactionHistory manages the transaction history of ETFs
type ETFTransactionHistory struct {
	historyPath    string
	encryptionKey  []byte
	transactions   map[string]Transaction
}

// NewETFTransactionHistory creates a new instance of ETFTransactionHistory
func NewETFTransactionHistory(historyPath, password string) (*ETFTransactionHistory, error) {
	encryptionKey, err := generateKeyFromPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &ETFTransactionHistory{
		historyPath:   historyPath,
		encryptionKey: encryptionKey,
		transactions:  make(map[string]Transaction),
	}, nil
}

// AddTransaction adds a new transaction to the history
func (eth *ETFTransactionHistory) AddTransaction(tx Transaction) error {
	txID := generateTransactionID(tx)
	tx.TransactionID = txID
	eth.transactions[txID] = tx

	return eth.saveTransactions()
}

// GetTransaction retrieves a transaction by its ID
func (eth *ETFTransactionHistory) GetTransaction(txID string) (Transaction, error) {
	tx, exists := eth.transactions[txID]
	if !exists {
		return Transaction{}, errors.New("transaction not found")
	}
	return tx, nil
}

// GetAllTransactions retrieves all transactions
func (eth *ETFTransactionHistory) GetAllTransactions() ([]Transaction, error) {
	var allTransactions []Transaction
	for _, tx := range eth.transactions {
		allTransactions = append(allTransactions, tx)
	}
	return allTransactions, nil
}

// saveTransactions saves all transactions to disk with encryption
func (eth *ETFTransactionHistory) saveTransactions() error {
	data, err := json.Marshal(eth.transactions)
	if err != nil {
		return fmt.Errorf("failed to marshal transactions: %v", err)
	}

	encryptedData, err := eth.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt transactions: %v", err)
	}

	filePath := filepath.Join(eth.historyPath, "transactions.dat")
	err = os.WriteFile(filePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write transactions to file: %v", err)
	}

	return nil
}

// loadTransactions loads all transactions from disk with decryption
func (eth *ETFTransactionHistory) loadTransactions() error {
	filePath := filepath.Join(eth.historyPath, "transactions.dat")
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No transactions file exists yet, no problem
		}
		return fmt.Errorf("failed to read transactions from file: %v", err)
	}

	data, err := eth.decryptData(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt transactions: %v", err)
	}

	err = json.Unmarshal(data, &eth.transactions)
	if err != nil {
		return fmt.Errorf("failed to unmarshal transactions: %v", err)
	}

	return nil
}

// encryptData encrypts data using AES
func (eth *ETFTransactionHistory) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(eth.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES
func (eth *ETFTransactionHistory) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(eth.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// generateKeyFromPassword generates a key from a password using scrypt
func generateKeyFromPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	return key, nil
}

// generateTransactionID generates a unique ID for a transaction
func generateTransactionID(tx Transaction) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%v%v%v%v", tx.Timestamp, tx.Sender, tx.Receiver, tx.Amount)))
	return hex.EncodeToString(hash.Sum(nil))
}

