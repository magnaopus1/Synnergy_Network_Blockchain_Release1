package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn3000/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn3000/security"
)

// Transaction represents a basic transaction structure
type Transaction struct {
	TransactionID string
	TokenID       string
	FromAddress   string
	ToAddress     string
	Amount        float64
	Timestamp     time.Time
	Signature     string
}

// TransactionCreationHandler handles the creation of transactions
type TransactionCreationHandler struct {
	transactions []Transaction
	ledger       *ledger.Ledger
	security     *security.SecurityHandler
}

// NewTransactionCreationHandler initializes a new TransactionCreationHandler
func NewTransactionCreationHandler(ledger *ledger.Ledger, security *security.SecurityHandler) *TransactionCreationHandler {
	return &TransactionCreationHandler{
		ledger:   ledger,
		security: security,
	}
}

// CreateTransaction creates a new transaction
func (tch *TransactionCreationHandler) CreateTransaction(tokenID, fromAddress, toAddress string, amount float64, privateKey string) (*Transaction, error) {
	// Check if the fromAddress has sufficient balance
	balance, err := tch.ledger.GetBalance(fromAddress, tokenID)
	if err != nil {
		return nil, fmt.Errorf("error fetching balance: %v", err)
	}
	if balance < amount {
		return nil, errors.New("insufficient balance")
	}

	// Create the transaction
	transaction := &Transaction{
		TokenID:     tokenID,
		FromAddress: fromAddress,
		ToAddress:   toAddress,
		Amount:      amount,
		Timestamp:   time.Now(),
	}

	// Generate transaction ID
	transaction.TransactionID = generateTransactionID(transaction)

	// Sign the transaction
	signature, err := tch.security.SignTransaction(transaction, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error signing transaction: %v", err)
	}
	transaction.Signature = signature

	// Verify the transaction
	if err := tch.security.VerifyTransaction(transaction); err != nil {
		return nil, fmt.Errorf("transaction verification failed: %v", err)
	}

	// Record the transaction in the ledger
	if err := tch.ledger.RecordTransaction(transaction); err != nil {
		return nil, fmt.Errorf("error recording transaction: %v", err)
	}

	// Add transaction to handler's list
	tch.transactions = append(tch.transactions, *transaction)

	// Log transaction event
	if err := logTransactionEvent(transaction); err != nil {
		return nil, fmt.Errorf("error logging transaction event: %v", err)
	}

	return transaction, nil
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID(transaction *Transaction) string {
	data := fmt.Sprintf("%s%s%s%f%s", transaction.TokenID, transaction.FromAddress, transaction.ToAddress, transaction.Amount, transaction.Timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// logTransactionEvent logs the transaction event
func logTransactionEvent(transaction *Transaction) error {
	event := fmt.Sprintf("Transaction %s: %f tokens transferred from %s to %s on %s", transaction.TransactionID, transaction.Amount, transaction.FromAddress, transaction.ToAddress, transaction.Timestamp)
	return security.LogEvent(event)
}

// GetTransaction retrieves a transaction by ID
func (tch *TransactionCreationHandler) GetTransaction(transactionID string) (*Transaction, error) {
	for _, transaction := range tch.transactions {
		if transaction.TransactionID == transactionID {
			return &transaction, nil
		}
	}
	return nil, errors.New("transaction not found")
}

// GetTransactionsByToken retrieves transactions by token ID
func (tch *TransactionCreationHandler) GetTransactionsByToken(tokenID string) ([]Transaction, error) {
	var tokenTransactions []Transaction
	for _, transaction := range tch.transactions {
		if transaction.TokenID == tokenID {
			tokenTransactions = append(tokenTransactions, transaction)
		}
	}
	if len(tokenTransactions) == 0 {
		return nil, errors.New("no transactions found for the given token ID")
	}
	return tokenTransactions, nil
}

// GetTransactionsByAddress retrieves transactions by address
func (tch *TransactionCreationHandler) GetTransactionsByAddress(address string) ([]Transaction, error) {
	var addressTransactions []Transaction
	for _, transaction := range tch.transactions {
		if transaction.FromAddress == address || transaction.ToAddress == address {
			addressTransactions = append(addressTransactions, transaction)
		}
	}
	if len(addressTransactions) == 0 {
		return nil, errors.New("no transactions found for the given address")
	}
	return addressTransactions, nil
}
