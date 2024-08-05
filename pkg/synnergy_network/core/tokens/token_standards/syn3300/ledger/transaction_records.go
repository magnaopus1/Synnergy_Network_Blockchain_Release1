package ledger

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
)

// TransactionRecord represents a record of a transaction for ETF shares
type TransactionRecord struct {
	TransactionID string    `json:"transaction_id"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	ETFID         string    `json:"etf_id"`
	Shares        float64   `json:"shares"`
	Timestamp     time.Time `json:"timestamp"`
	Status        string    `json:"status"`
}

// TransactionService manages the transaction records
type TransactionService struct {
	transactionRecords []TransactionRecord
	encryptionService  *encryption.EncryptionService
}

// NewTransactionService creates a new instance of TransactionService
func NewTransactionService(encryptionService *encryption.EncryptionService) *TransactionService {
	return &TransactionService{
		transactionRecords: make([]TransactionRecord, 0),
		encryptionService:  encryptionService,
	}
}

// AddTransactionRecord adds a new transaction record
func (ts *TransactionService) AddTransactionRecord(from, to, etfID string, shares float64, status string) (string, error) {
	record := TransactionRecord{
		TransactionID: generateTransactionID(),
		From:          from,
		To:            to,
		ETFID:         etfID,
		Shares:        shares,
		Timestamp:     time.Now(),
		Status:        status,
	}

	encryptedRecord, err := ts.encryptionService.EncryptData(record)
	if err != nil {
		return "", err
	}

	ts.transactionRecords = append(ts.transactionRecords, encryptedRecord)
	return record.TransactionID, nil
}

// GetTransactionRecord retrieves a transaction record by transaction ID
func (ts *TransactionService) GetTransactionRecord(transactionID string) (*TransactionRecord, error) {
	for _, record := range ts.transactionRecords {
		decryptedRecord, err := ts.encryptionService.DecryptData(record)
		if err != nil {
			return nil, err
		}

		if decryptedRecord.TransactionID == transactionID {
			return &decryptedRecord, nil
		}
	}
	return nil, errors.New("transaction record not found")
}

// GetAllTransactionRecords retrieves all transaction records
func (ts *TransactionService) GetAllTransactionRecords() ([]TransactionRecord, error) {
	allRecords := make([]TransactionRecord, 0)

	for _, record := range ts.transactionRecords {
		decryptedRecord, err := ts.encryptionService.DecryptData(record)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, decryptedRecord)
	}

	return allRecords, nil
}

// UpdateTransactionRecord updates an existing transaction record
func (ts *TransactionService) UpdateTransactionRecord(transactionID, from, to, etfID string, shares float64, status string) error {
	for i, record := range ts.transactionRecords {
		decryptedRecord, err := ts.encryptionService.DecryptData(record)
		if err != nil {
			return err
		}

		if decryptedRecord.TransactionID == transactionID {
			decryptedRecord.From = from
			decryptedRecord.To = to
			decryptedRecord.ETFID = etfID
			decryptedRecord.Shares = shares
			decryptedRecord.Status = status
			decryptedRecord.Timestamp = time.Now()

			encryptedRecord, err := ts.encryptionService.EncryptData(decryptedRecord)
			if err != nil {
				return err
			}

			ts.transactionRecords[i] = encryptedRecord
			return nil
		}
	}
	return errors.New("transaction record not found")
}

// DeleteTransactionRecord deletes a transaction record by transaction ID
func (ts *TransactionService) DeleteTransactionRecord(transactionID string) error {
	for i, record := range ts.transactionRecords {
		decryptedRecord, err := ts.encryptionService.DecryptData(record)
		if err != nil {
			return err
		}

		if decryptedRecord.TransactionID == transactionID {
			ts.transactionRecords = append(ts.transactionRecords[:i], ts.transactionRecords[i+1:]...)
			return nil
		}
	}
	return errors.New("transaction record not found")
}

// VerifyTransactionRecord verifies the integrity of a transaction record by transaction ID
func (ts *TransactionService) VerifyTransactionRecord(transactionID string) (bool, error) {
	record, err := ts.GetTransactionRecord(transactionID)
	if err != nil {
		return false, err
	}

	// Implement further verification logic if needed
	if record.TransactionID == transactionID && record.Shares > 0 {
		return true, nil
	}

	return false, errors.New("transaction record verification failed")
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	// Implement a logic to generate a unique transaction ID
	// For the purpose of this example, using a simple timestamp-based ID
	return fmt.Sprintf("txn_%d", time.Now().UnixNano())
}
