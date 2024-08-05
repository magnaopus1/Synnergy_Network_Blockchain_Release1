package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// FeeFreeTransaction represents a fee-free blockchain transaction.
type FeeFreeTransaction struct {
	ID             string
	AssetID        string
	Sender         string
	Receiver       string
	Amount         float64
	Timestamp      time.Time
	Signature      string
	TransactionHash string
	Status         string
	EncryptedData  []byte
}

// FeeFreeTransactionManager manages fee-free blockchain transactions.
type FeeFreeTransactionManager struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewFeeFreeTransactionManager initializes a new FeeFreeTransactionManager.
func NewFeeFreeTransactionManager(ledger *ledger.TransactionLedger, security *security.SecurityManager) *FeeFreeTransactionManager {
	return &FeeFreeTransactionManager{
		ledger:   ledger,
		security: security,
	}
}

// CreateFeeFreeTransaction creates a new fee-free blockchain transaction.
func (ftm *FeeFreeTransactionManager) CreateFeeFreeTransaction(assetID, sender, receiver string, amount float64, privateKey string) (*FeeFreeTransaction, error) {
	if assetID == "" || sender == "" || receiver == "" || amount <= 0 {
		return nil, errors.New("invalid transaction details")
	}

	transaction := &FeeFreeTransaction{
		ID:        utils.GenerateUUID(),
		AssetID:   assetID,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
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
	signature, err := ftm.security.SignData(transactionHash, privateKey)
	if err != nil {
		return nil, err
	}
	transaction.Signature = signature

	// Encrypt transaction data
	encryptedData, err := ftm.security.EncryptData([]byte(utils.ToJSON(transaction)))
	if err != nil {
		return nil, err
	}
	transaction.EncryptedData = encryptedData

	// Record the transaction in the transaction ledger
	err = ftm.ledger.RecordTransaction(transaction.ID, "FeeFreeTransactionCreation", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// ValidateFeeFreeTransaction validates a fee-free blockchain transaction.
func (ftm *FeeFreeTransactionManager) ValidateFeeFreeTransaction(transactionID string) (*FeeFreeTransaction, error) {
	transaction, err := ftm.GetFeeFreeTransaction(transactionID)
	if err != nil {
		return nil, err
	}

	if transaction.Status != "Pending" {
		return nil, errors.New("transaction already processed")
	}

	// Verify the transaction signature
	valid, err := ftm.security.VerifySignature(transaction.TransactionHash, transaction.Signature, transaction.Sender)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid transaction signature")
	}

	// Update transaction status to "Validated"
	transaction.Status = "Validated"

	// Record the transaction validation in the transaction ledger
	err = ftm.ledger.RecordTransaction(transaction.ID, "FeeFreeTransactionValidation", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// ExecuteFeeFreeTransaction executes a validated fee-free blockchain transaction.
func (ftm *FeeFreeTransactionManager) ExecuteFeeFreeTransaction(transactionID string) (*FeeFreeTransaction, error) {
	transaction, err := ftm.GetFeeFreeTransaction(transactionID)
	if err != nil {
		return nil, err
	}

	if transaction.Status != "Validated" {
		return nil, errors.New("transaction not validated")
	}

	// Update transaction status to "Completed"
	transaction.Status = "Completed"

	// Record the transaction execution in the transaction ledger
	err = ftm.ledger.RecordTransaction(transaction.ID, "FeeFreeTransactionExecution", transaction)
	if err != nil {
		return nil, err
	}

	return transaction, nil
}

// GetFeeFreeTransaction retrieves a fee-free blockchain transaction by ID.
func (ftm *FeeFreeTransactionManager) GetFeeFreeTransaction(transactionID string) (*FeeFreeTransaction, error) {
	var transaction FeeFreeTransaction
	err := ftm.ledger.GetTransaction(transactionID, &transaction)
	if err != nil {
		return nil, err
	}

	// Decrypt transaction data
	decryptedData, err := ftm.security.DecryptData(transaction.EncryptedData)
	if err != nil {
		return nil, err
	}
	err = utils.FromJSON(decryptedData, &transaction)
	if err != nil {
		return nil, err
	}

	return &transaction, nil
}

// NotifyTransactionStatus sends notifications for fee-free transaction status changes.
func (ftm *FeeFreeTransactionManager) NotifyTransactionStatus(transactionID, status string) error {
	transaction, err := ftm.GetFeeFreeTransaction(transactionID)
	if err != nil {
		return err
	}

	notification := utils.CreateTransactionNotification(transaction, status)
	err = utils.SendNotification(transaction.Receiver, "Fee-Free Transaction Status Update", notification)
	if err != nil {
		return err
	}

	return nil
}
