package transactions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Transaction represents a transaction in the SYN1700 token standard.
type Transaction struct {
	EventID       string    `json:"event_id"`
	TicketID      string    `json:"ticket_id"`
	FromOwnerID   string    `json:"from_owner_id"`
	ToOwnerID     string    `json:"to_owner_id"`
	TransactionID string    `json:"transaction_id"`
	Timestamp     time.Time `json:"timestamp"`
	Signature     string    `json:"signature"`
}

// TransactionCreation handles the creation of new transactions.
type TransactionCreation struct {
	aesKey []byte
	salt   []byte
}

// NewTransactionCreation creates a new instance of TransactionCreation.
func NewTransactionCreation(passphrase string) (*TransactionCreation, error) {
	// Derive AES key from passphrase using scrypt
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return &TransactionCreation{
		aesKey: key,
		salt:   salt,
	}, nil
}

// CreateTransaction creates a new transaction and returns the encrypted transaction data.
func (tc *TransactionCreation) CreateTransaction(eventID, ticketID, fromOwnerID, toOwnerID, signature string) (string, error) {
	transactionID := generateTransactionID()
	timestamp := time.Now()

	transaction := Transaction{
		EventID:       eventID,
		TicketID:      ticketID,
		FromOwnerID:   fromOwnerID,
		ToOwnerID:     toOwnerID,
		TransactionID: transactionID,
		Timestamp:     timestamp,
		Signature:     signature,
	}

	data, err := json.Marshal(transaction)
	if err != nil {
		return "", err
	}

	encryptedData, err := tc.encrypt(data)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// ValidateTransaction validates the encrypted transaction data and returns the Transaction object.
func (tc *TransactionCreation) ValidateTransaction(encryptedData string) (*Transaction, error) {
	decryptedData, err := tc.decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var transaction Transaction
	err = json.Unmarshal(decryptedData, &transaction)
	if err != nil {
		return nil, err
	}

	// Additional validation logic can be added here (e.g., signature verification)
	if transaction.Timestamp.After(time.Now()) {
		return nil, errors.New("transaction timestamp is in the future")
	}

	return &transaction, nil
}

// encrypt encrypts the data using AES-GCM.
func (tc *TransactionCreation) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(tc.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts the data using AES-GCM.
func (tc *TransactionCreation) decrypt(data string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(tc.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(decodedData) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedData[:gcm.NonceSize()], decodedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateTransactionID generates a unique transaction ID.
func generateTransactionID() string {
	// This is a placeholder implementation. In a real-world scenario, you might use a more sophisticated method.
	transactionID := make([]byte, 16)
	_, err := rand.Read(transactionID)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(transactionID)
}
