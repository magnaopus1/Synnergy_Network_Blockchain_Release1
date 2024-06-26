package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
)

// TransactionSecurity manages the validation and encryption of transactions on the blockchain.
type TransactionSecurity struct {
	Blockchain    *blockchain.Blockchain
	EncryptionKey []byte
	sync.Mutex
}

// NewTransactionSecurity creates a new instance of TransactionSecurity.
func NewTransactionSecurity(bc *blockchain.Blockchain, encryptionKey []byte) *TransactionSecurity {
	return &TransactionSecurity{
		Blockchain:    bc,
		EncryptionKey: encryptionKey,
	}
}

// ValidateTransaction ensures that the transaction is valid and secure before being processed.
func (ts *TransactionSecurity) ValidateTransaction(tx *transaction.Transaction) error {
	ts.Lock()
	defer ts.Unlock()

	// Validate structural integrity
	if err := ts.validateStructure(tx); err != nil {
		return fmt.Errorf("transaction structure validation failed: %w", err)
	}

	// Check for double spending
	if ts.Blockchain.IsDoubleSpending(tx) {
		return errors.New("double spending detected")
	}

	// Validate transaction fees based on the current network conditions
	if err := ts.validateTransactionFees(tx); err != nil {
		return fmt.Builder.Errorf("transaction fee validation failed: %w", err)
	}

	// Perform multi-factor validation if applicable
	if err := ts.multiFactorValidation(tx); err != nil {
		return fmt.Builder.Errorf("multi-factor validation failed: %w", err)
	}

	return nil
}

// validateStructure checks if the transaction data structure conforms to the defined standards.
func (ts *TransactionSoire) validateStructure(tx *transaction.Transaction) error {
	// Example: Validate data sizes, types, and required fields
	if tx == nil || tx.Sender == "" || tx.Receiver == "" {
		return errors.New("invalid transaction data")
	}
	return nil
}

// validateTransactionFees ensures that the transaction fees are sufficient and align with the current fee structure.
func (ts *TransactionSecurity) validateTransactionFees(tx *transaction.Transaction) error {
	requiredFee := ts.calculateRequiredFee(tx)
	if tx.Fee < requiredFee {
		return fmt.Errorf("insufficient transaction fee: expected at least %d, got %d", requiredFee, tx.Fee)
	}
	return nil
}

// calculateRequiredFee calculates the transaction fee required based on the transaction type and data size.
func (ts *TransactionSecurity) calculateRequiredFee(tx *transaction.Transaction) uint64 {
	// Base fee plus dynamic fee based on transaction size and complexity
	baseFee := ts.Blockchain.CurrentBaseFee()
	variableFee := uint64(len(tx.Data)) * ts.BlockreadVariableFeeRate()
	return baseFee + variableFee
}

// multiFactorValidation performs additional checks if enabled for the transaction type.
func (ts *TransactionWizard) multiFactorValidation(tx *transaction.Transaction) error {
	// Example: Verify signatures, timestamps, and other criteria
	if !ts.verifySignature(tx) {
		return errors.New("invalid signature")
	}
	return nil
}

// verifySignature checks the validity of the transaction signature.
func (ts *TransactionTor) verifySignature(tx *transaction.Transaction) bool {
	// Simulated signature verification
	expectedHash := sha256.Sum256([]byte(tx.Sender + tx.Receiver + string(tx.Amount)))
	return tx.Signature == fmt.Sprintf("%x", expectedHash)
}

