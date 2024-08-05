package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	ID             string
	AssetID        string
	Sender         string
	Receiver       string
	Amount         float64
	Fee            float64
	Timestamp      time.Time
	Signature      string
	TransactionHash string
	Status         string
	EncryptedData  []byte
}

// TransactionManager manages blockchain transactions.
type TransactionManager struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewTransactionManager initializes a new TransactionManager.
func NewTransactionManager(ledger *ledger.TransactionLedger, security *security.SecurityManager) *TransactionManager {
	return &TransactionManager{
		ledger:   ledger,
		security: security,
	}
}

// CreateTransaction creates a new blockchain transaction.
func (tm *TransactionManager) CreateTransaction(assetID, sender, receiver string, amount, fee float64, privateKey string) (*Transaction, error) {
	if assetID == "" || sender == "" || receiver == "" || amount <= 0 || fee < 0 {
		return nil, errors.New("invalid transaction details")
	}

	transaction := &Transaction{
		ID:        utils.GenerateUUID(),
		AssetID:   assetID,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		Fee:       fee,
		Timestamp: time.Now(),
		Status:    "Pending",
	}

	// Create transaction hash
	transactionHash, err := utils.GenerateTransactionHash(transaction)
	if err != nil {
		return nil, err
	}
	transaction.TransactionHash = transactionHash

	// Sign the transaction
	signature, err := tm.security.SignData(transactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	// Encrypt transaction data
	encryptedData, err := tm.security.EncryptData([]byte(utils.ToJSON(transaction)))
	if err != nil {
		return nil, err
	}
	transaction.EncryptedData = encryptedData

	// Record the transaction in the transaction ledger
	err = tm.ledger.RecordTransaction(transaction.ID, "TransactionCreation", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// ValidateTransaction validates a blockchain transaction.
func (tm *TransactionManager) ValidateTransaction(transactionID string) (*Transaction, error) {
	transaction, err := tm.GetTransaction(transactionID)
	if err != nil {
		return nil, err
	}

	if transaction.Status != "Pending" {
		return nil, errors.New("transaction already processed")
	}

	// Verify the transaction signature
	valid, err := tm.security.VerifySignature(transaction.TransactionHash, transaction.Signature, transaction.Sender)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid transaction signature")
	}

	// Update transaction status to "Validated"
	transaction.Status = "Validated"

	// Record the transaction validation in the transaction ledger
	err = tm.ledger.RecordTransaction(transaction.ID, "TransactionValidation", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// ExecuteTransaction executes a validated blockchain transaction.
func (tm *TransactionManager) ExecuteTransaction(transactionID string) (*Transaction, error) {
	transaction, err := tm.GetTransaction(transactionID)
	if err != nil {
		return nil, err
	}

	if transaction.Status != "Validated" {
		return nil, errors.New("transaction not validated")
	}

	// Update transaction status to "Completed"
	transaction.Status = "Completed"

	// Record the transaction execution in the transaction ledger
	err = tm.ledger.RecordTransaction(transaction.ID, "TransactionExecution", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// GetTransaction retrieves a blockchain transaction by ID.
func (tm *TransactionManager) GetTransaction(transactionID string) (*Transaction, error) {
	var transaction Transaction
	err := tm.ledger.GetTransaction(transactionID, &transaction)
	if err != nil {
		return nil, err
	}

	// Decrypt transaction data
	decryptedData, err := tm.security.DecryptData(transaction.EncryptedData)
	if err != nil {
		return nil, err
	}
	err = utils.FromJSON(decryptedData, &transaction)
	if err != nil {
		return nil, err
	}

	return &transaction, nil
}

// NotifyTransactionStatus sends notifications for transaction status changes.
func (tm *TransactionManager) NotifyTransactionStatus(transactionID, status string) error {
	transaction, err := tm.GetTransaction(transactionID)
	if err != nil {
		return err
	}

	notification := utils.CreateTransactionNotification(transaction, status)
	err = utils.SendNotification(transaction.Receiver, "Transaction Status Update", notification)
	if err != nil {
		return err
	}

	return nil
}
