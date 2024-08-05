package transactions

import (
	"errors"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// ValidationStatus represents the status of a transaction validation.
type ValidationStatus string

const (
	StatusPending    ValidationStatus = "Pending"
	StatusValidated  ValidationStatus = "Validated"
	StatusInvalid    ValidationStatus = "Invalid"
	StatusCompleted  ValidationStatus = "Completed"
)

// TransactionValidation represents the structure for transaction validation.
type TransactionValidation struct {
	ID             string
	TransactionID  string
	Validator      string
	Timestamp      time.Time
	Signature      string
	Status         ValidationStatus
	EncryptedData  []byte
}

// TransactionValidationManager manages transaction validations.
type TransactionValidationManager struct {
	ledger   *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewTransactionValidationManager initializes a new TransactionValidationManager.
func NewTransactionValidationManager(ledger *ledger.TransactionLedger, security *security.SecurityManager) *TransactionValidationManager {
	return &TransactionValidationManager{
		ledger:   ledger,
		security: security,
	}
}

// ValidateTransaction initiates the validation process for a given transaction.
func (tvm *TransactionValidationManager) ValidateTransaction(transactionID, validator, privateKey string) (*TransactionValidation, error) {
	transaction, err := tvm.getTransaction(transactionID)
	if err != nil {
		return nil, err
	}

	if transaction.Status != StatusPending {
		return nil, errors.New("transaction already processed")
	}

	// Validate the transaction signature
	valid, err := tvm.security.VerifySignature(transaction.TransactionHash, transaction.Signature, transaction.Sender)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid transaction signature")
	}

	// Create transaction validation record
	validation := &TransactionValidation{
		ID:            utils.GenerateUUID(),
		TransactionID: transactionID,
		Validator:     validator,
		Timestamp:     time.Now(),
		Status:        StatusValidated,
	}

	// Sign the validation
	validationHash, err := utils.GenerateTransactionHash(validation)
	if err != nil {
		return nil, err
	}
	signature, err := tvm.security.SignData(validationHash, privateKey)
	if err != nil {
		return nil, err
	}
	validation.Signature = signature

	// Encrypt validation data
	encryptedData, err := tvm.security.EncryptData([]byte(utils.ToJSON(validation)))
	if err != nil {
		return nil, err
	}
	validation.EncryptedData = encryptedData

	// Update transaction status to "Validated"
	transaction.Status = StatusValidated
	err = tvm.ledger.RecordTransaction(transaction.ID, "TransactionValidation", transaction)
	if err != nil {
		return nil, err
	}

	// Record the validation in the transaction ledger
	err = tvm.ledger.RecordTransaction(validation.ID, "ValidationRecord", validation)
	if err != nil {
		return nil, err
	}

	return validation, nil
}

// getTransaction retrieves a transaction by its ID.
func (tvm *TransactionValidationManager) getTransaction(transactionID string) (*Transaction, error) {
	var transaction Transaction
	err := tvm.ledger.GetTransaction(transactionID, &transaction)
	if err != nil {
		return nil, err
	}

	// Decrypt transaction data
	decryptedData, err := tvm.security.DecryptData(transaction.EncryptedData)
	if err != nil {
		return nil, err
	}
	err = utils.FromJSON(decryptedData, &transaction)
	if err != nil {
		return nil, err
	}

	return &transaction, nil
}

// getValidation retrieves a validation by its ID.
func (tvm *TransactionValidationManager) getValidation(validationID string) (*TransactionValidation, error) {
	var validation TransactionValidation
	err := tvm.ledger.GetTransaction(validationID, &validation)
	if err != nil {
		return nil, err
	}

	// Decrypt validation data
	decryptedData, err := tvm.security.DecryptData(validation.EncryptedData)
	if err != nil {
		return nil, err
	}
	err = utils.FromJSON(decryptedData, &validation)
	if err != nil {
		return nil, err
	}

	return &validation, nil
}

// notifyValidationStatus sends notifications for validation status changes.
func (tvm *TransactionValidationManager) notifyValidationStatus(validationID, status string) error {
	validation, err := tvm.getValidation(validationID)
	if err != nil {
		return err
	}

	notification := utils.CreateValidationNotification(validation, status)
	err = utils.SendNotification(validation.Validator, "Validation Status Update", notification)
	if err != nil {
		return err
	}

	return nil
}
