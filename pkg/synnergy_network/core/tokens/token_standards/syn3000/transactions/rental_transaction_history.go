package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn3000/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn3000/security"
)

// RentalTransaction represents a rental transaction record
type RentalTransaction struct {
	TransactionID  string
	TokenID        string
	FromTenant     string
	ToTenant       string
	TransactionDate time.Time
	Amount         float64
	EncryptedData  string
}

// RentalTransactionHistory stores the history of rental transactions
type RentalTransactionHistory struct {
	Transactions []RentalTransaction
}

// AddTransaction adds a new rental transaction to the history
func (rth *RentalTransactionHistory) AddTransaction(tokenID, fromTenant, toTenant string, amount float64) (*RentalTransaction, error) {
	transaction := &RentalTransaction{
		TokenID:         tokenID,
		FromTenant:      fromTenant,
		ToTenant:        toTenant,
		TransactionDate: time.Now(),
		Amount:          amount,
	}

	// Encrypt transaction details
	encryptedData, err := encryptTransactionDetails(transaction)
	if err != nil {
		return nil, fmt.Errorf("error encrypting transaction details: %v", err)
	}
	transaction.EncryptedData = encryptedData

	// Generate transaction ID
	transaction.TransactionID = generateTransactionID(transaction)

	// Append transaction to history
	rth.Transactions = append(rth.Transactions, *transaction)

	// Log transaction event
	if err := logTransactionEvent(transaction); err != nil {
		return nil, fmt.Errorf("error logging transaction event: %v", err)
	}

	return transaction, nil
}

// encryptTransactionDetails encrypts the transaction details
func encryptTransactionDetails(transaction *RentalTransaction) (string, error) {
	key := sha256.Sum256([]byte("some-very-secure-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	plaintext := fmt.Sprintf("%s|%s|%s|%s|%f", transaction.TokenID, transaction.FromTenant, transaction.ToTenant, transaction.TransactionDate, transaction.Amount)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return hex.EncodeToString(ciphertext), nil
}

// decryptTransactionDetails decrypts the transaction details
func decryptTransactionDetails(encryptedData string) (*RentalTransaction, error) {
	key := sha256.Sum256([]byte("some-very-secure-key"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	plaintext := string(ciphertext)
	var tokenID, fromTenant, toTenant string
	var transactionDate time.Time
	var amount float64
	_, err = fmt.Sscanf(plaintext, "%s|%s|%s|%s|%f", &tokenID, &fromTenant, &toTenant, &transactionDate, &amount)
	if err != nil {
		return nil, err
	}

	return &RentalTransaction{
		TokenID:         tokenID,
		FromTenant:      fromTenant,
		ToTenant:        toTenant,
		TransactionDate: transactionDate,
		Amount:          amount,
	}, nil
}

// generateTransactionID generates a unique transaction ID for the transaction
func generateTransactionID(transaction *RentalTransaction) string {
	data := fmt.Sprintf("%s%s%s%s%f", transaction.TokenID, transaction.FromTenant, transaction.ToTenant, transaction.TransactionDate, transaction.Amount)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// logTransactionEvent logs the rental transaction event
func logTransactionEvent(transaction *RentalTransaction) error {
	event := fmt.Sprintf("Rental transaction %s: token %s transferred from %s to %s on %s for amount %f", transaction.TransactionID, transaction.TokenID, transaction.FromTenant, transaction.ToTenant, transaction.TransactionDate, transaction.Amount)
	return security.LogEvent(event)
}

// GetTransactionHistory retrieves the transaction history for a given token
func (rth *RentalTransactionHistory) GetTransactionHistory(tokenID string) ([]RentalTransaction, error) {
	var history []RentalTransaction
	for _, transaction := range rth.Transactions {
		if transaction.TokenID == tokenID {
			history = append(history, transaction)
		}
	}
	if len(history) == 0 {
		return nil, errors.New("no transactions found for the given token ID")
	}
	return history, nil
}

// VerifyTransaction verifies the integrity of a rental transaction
func (rth *RentalTransactionHistory) VerifyTransaction(transactionID string) (bool, error) {
	for _, transaction := range rth.Transactions {
		if transaction.TransactionID == transactionID {
			decryptedTransaction, err := decryptTransactionDetails(transaction.EncryptedData)
			if err != nil {
				return false, fmt.Errorf("error decrypting transaction details: %v", err)
			}
			expectedID := generateTransactionID(decryptedTransaction)
			return expectedID == transactionID, nil
		}
	}
	return false, errors.New("transaction not found")
}
