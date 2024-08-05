package transactions

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"synnergy_network/core/tokens/token_standards/syn11/ledger"
	"synnergy_network/core/tokens/token_standards/syn11/security"
	"synnergy_network/core/tokens/token_standards/syn11/storage"
)

// TransactionValidator handles the validation of SYN11 token transactions.
type TransactionValidator struct {
	ledger  *ledger.LedgerManager
	storage *storage.StorageManager
}

// NewTransactionValidator creates a new instance of TransactionValidator.
func NewTransactionValidator(ledger *ledger.LedgerManager, storage *storage.StorageManager) *TransactionValidator {
	return &TransactionValidator{
		ledger:  ledger,
		storage: storage,
	}
}

// ValidateTransaction validates the given transaction details.
func (tv *TransactionValidator) ValidateTransaction(transactionID string) (bool, error) {
	// Retrieve transaction details from storage
	data, err := tv.storage.GetData(transactionID)
	if err != nil {
		return false, errors.New("transaction not found")
	}

	// Decrypt transaction details
	transactionDetails, err := tv.decryptData(data)
	if err != nil {
		return false, errors.New("failed to decrypt transaction details")
	}

	// Check transaction integrity using HMAC
	if !tv.validateHMAC(transactionDetails) {
		return false, errors.New("transaction integrity validation failed")
	}

	// Verify ownership, balance, and compliance
	if err := tv.verifyTransactionDetails(transactionDetails); err != nil {
		return false, err
	}

	// Check for duplicate transactions using transaction ID or nonce
	if err := tv.checkForDuplicateTransaction(transactionDetails.Nonce); err != nil {
		return false, err
	}

	return true, nil
}

// decryptData decrypts the given encrypted transaction data.
func (tv *TransactionValidator) decryptData(data []byte) (*ledger.TransactionDetails, error) {
	decryptedData, err := security.DecryptData(data)
	if err != nil {
		return nil, err
	}

	var transactionDetails ledger.TransactionDetails
	err = json.Unmarshal(decryptedData, &transactionDetails)
	if err != nil {
		return nil, err
	}

	return &transactionDetails, nil
}

// validateHMAC checks the integrity of the transaction details using HMAC.
func (tv *TransactionValidator) validateHMAC(transactionDetails *ledger.TransactionDetails) bool {
	secret := []byte("secret-key") // Replace with a secure key management solution
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(transactionDetails.Nonce + transactionDetails.From + transactionDetails.To + transactionDetails.TokenID))
	expectedHMAC := h.Sum(nil)
	return hmac.Equal(expectedHMAC, transactionDetails.HMAC)
}

// verifyTransactionDetails verifies the transaction details such as ownership, balance, and compliance.
func (tv *TransactionValidator) verifyTransactionDetails(transactionDetails *ledger.TransactionDetails) error {
	// Verify ownership of the token
	if !tv.ledger.VerifyOwnership(transactionDetails.TokenID, transactionDetails.From) {
		return errors.New("ownership verification failed")
	}

	// Verify sufficient balance
	if !tv.ledger.VerifyBalance(transactionDetails.From, transactionDetails.Amount) {
		return errors.New("insufficient balance")
	}

	// Check KYC/AML compliance
	if !security.VerifyKYC(transactionDetails.From) || !security.VerifyKYC(transactionDetails.To) {
		return errors.New("KYC/AML verification failed")
	}

	return nil
}

// checkForDuplicateTransaction ensures the transaction is not a duplicate.
func (tv *TransactionValidator) checkForDuplicateTransaction(nonce string) error {
	// Check the ledger or a separate storage system for the nonce
	if tv.ledger.IsNonceUsed(nonce) {
		return errors.New("duplicate transaction detected")
	}
	return nil
}
