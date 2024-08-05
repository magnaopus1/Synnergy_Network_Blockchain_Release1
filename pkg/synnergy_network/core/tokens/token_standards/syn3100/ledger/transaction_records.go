package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// TransactionRecord represents a record of a transaction on the blockchain
type TransactionRecord struct {
	TransactionID string    `json:"transaction_id"`
	TokenID       string    `json:"token_id"`
	SenderID      string    `json:"sender_id"`
	ReceiverID    string    `json:"receiver_id"`
	Amount        float64   `json:"amount"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"` // Status could be "pending", "completed", "failed"
}

// TransactionRecords manages the records of all transactions on the blockchain
type TransactionRecords struct {
	records map[string]TransactionRecord
}

// NewTransactionRecords initializes a new TransactionRecords instance
func NewTransactionRecords() *TransactionRecords {
	return &TransactionRecords{
		records: make(map[string]TransactionRecord),
	}
}

// AddTransactionRecord adds a new transaction record to the ledger
func (tr *TransactionRecords) AddTransactionRecord(transactionID, tokenID, senderID, receiverID string, amount float64, status string) error {
	timestamp := time.Now()
	transactionRecord := TransactionRecord{
		TransactionID: transactionID,
		TokenID:       tokenID,
		SenderID:      senderID,
		ReceiverID:    receiverID,
		Amount:        amount,
		Timestamp:     timestamp,
		Status:        status,
	}

	if _, exists := tr.records[transactionID]; exists {
		return errors.New("transaction record already exists")
	}

	tr.records[transactionID] = transactionRecord
	return nil
}

// GetTransactionRecord retrieves a specific transaction record by its ID
func (tr *TransactionRecords) GetTransactionRecord(transactionID string) (TransactionRecord, error) {
	if record, exists := tr.records[transactionID]; exists {
		return record, nil
	}
	return TransactionRecord{}, errors.New("transaction record not found")
}

// GetTransactionHistory retrieves the transaction history for a specific token
func (tr *TransactionRecords) GetTransactionHistory(tokenID string) ([]TransactionRecord, error) {
	var history []TransactionRecord
	for _, record := range tr.records {
		if record.TokenID == tokenID {
			history = append(history, record)
		}
	}
	if len(history) == 0 {
		return nil, errors.New("no transaction records found for the token")
	}
	return history, nil
}

// UpdateTransactionStatus updates the status of a specific transaction
func (tr *TransactionRecords) UpdateTransactionStatus(transactionID, status string) error {
	if record, exists := tr.records[transactionID]; exists {
		record.Status = status
		tr.records[transactionID] = record
		return nil
	}
	return errors.New("transaction record not found")
}

// EncryptTransactionData encrypts the transaction data for secure storage
func (tr *TransactionRecords) EncryptTransactionData(transactionID, password string) (string, error) {
	if record, exists := tr.records[transactionID]; exists {
		dataBytes, err := json.Marshal(record)
		if err != nil {
			return "", err
		}

		encryptedData, err := security.EncryptData(dataBytes, password)
		if err != nil {
			return "", err
		}

		return encryptedData, nil
	}
	return "", errors.New("transaction record not found")
}

// DecryptTransactionData decrypts the transaction data
func (tr *TransactionRecords) DecryptTransactionData(encryptedData, password string) (TransactionRecord, error) {
	decryptedData, err := security.DecryptData(encryptedData, password)
	if err != nil {
		return TransactionRecord{}, err
	}

	var record TransactionRecord
	err = json.Unmarshal([]byte(decryptedData), &record)
	if err != nil {
		return TransactionRecord{}, err
	}

	return record, nil
}
