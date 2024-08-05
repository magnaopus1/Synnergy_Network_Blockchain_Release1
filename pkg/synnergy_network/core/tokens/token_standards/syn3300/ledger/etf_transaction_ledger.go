package ledger

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
)

// TransactionType defines the type of transaction
type TransactionType string

const (
	// Transfer represents a transfer transaction
	Transfer TransactionType = "TRANSFER"
	// Mint represents a minting transaction
	Mint TransactionType = "MINT"
	// Burn represents a burning transaction
	Burn TransactionType = "BURN"
)

// TransactionRecord represents a single transaction in the ledger
type TransactionRecord struct {
	ID             string            `json:"id"`
	Type           TransactionType   `json:"type"`
	Amount         float64           `json:"amount"`
	From           string            `json:"from"`
	To             string            `json:"to"`
	Timestamp      time.Time         `json:"timestamp"`
	AdditionalData map[string]string `json:"additional_data"`
}

// LedgerService manages the ETF transaction ledger
type LedgerService struct {
	transactions      []TransactionRecord
	encryptionService *encryption.EncryptionService
}

// NewLedgerService creates a new instance of LedgerService
func NewLedgerService(encryptionService *encryption.EncryptionService) *LedgerService {
	return &LedgerService{
		transactions:      make([]TransactionRecord, 0),
		encryptionService: encryptionService,
	}
}

// AddTransaction adds a new transaction to the ledger
func (ls *LedgerService) AddTransaction(transactionType TransactionType, amount float64, from string, to string, additionalData map[string]string) (string, error) {
	transaction := TransactionRecord{
		ID:             generateTransactionID(),
		Type:           transactionType,
		Amount:         amount,
		From:           from,
		To:             to,
		Timestamp:      time.Now(),
		AdditionalData: additionalData,
	}

	encryptedData, err := ls.encryptionService.EncryptData(transaction)
	if err != nil {
		return "", err
	}

	ls.transactions = append(ls.transactions, encryptedData)
	return transaction.ID, nil
}

// GetTransaction retrieves a transaction from the ledger by ID
func (ls *LedgerService) GetTransaction(transactionID string) (*TransactionRecord, error) {
	for _, tx := range ls.transactions {
		decryptedTx, err := ls.encryptionService.DecryptData(tx)
		if err != nil {
			return nil, err
		}

		if decryptedTx.ID == transactionID {
			return &decryptedTx, nil
		}
	}
	return nil, errors.New("transaction not found")
}

// GetAllTransactions retrieves all transactions from the ledger
func (ls *LedgerService) GetAllTransactions() ([]TransactionRecord, error) {
	allTransactions := make([]TransactionRecord, 0)

	for _, tx := range ls.transactions {
		decryptedTx, err := ls.encryptionService.DecryptData(tx)
		if err != nil {
			return nil, err
		}
		allTransactions = append(allTransactions, decryptedTx)
	}

	return allTransactions, nil
}

// VerifyTransaction verifies the integrity of a transaction by ID
func (ls *LedgerService) VerifyTransaction(transactionID string) (bool, error) {
	tx, err := ls.GetTransaction(transactionID)
	if err != nil {
		return false, err
	}

	// Implement further verification logic if needed
	if tx.ID == transactionID && tx.Amount > 0 {
		return true, nil
	}

	return false, errors.New("transaction verification failed")
}

// generateTransactionID generates a unique transaction ID
func generateTransactionID() string {
	return encryption.GenerateUniqueID()
}
