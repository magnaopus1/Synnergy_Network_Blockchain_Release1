// transaction_creation.go

package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/assets"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/compliance"
)

// TransactionCreator handles the creation of SYN5000 token transactions
type TransactionCreator struct {
	ledger          *ledger.TransactionLedger
	assetRegistry   *assets.AssetRegistry
	compliance      *compliance.ComplianceManager
	securityManager *security.SecurityManager
}

// NewTransactionCreator initializes a new TransactionCreator
func NewTransactionCreator(ledger *ledger.TransactionLedger, assetRegistry *assets.AssetRegistry, compliance *compliance.ComplianceManager, securityManager *security.SecurityManager) *TransactionCreator {
	return &TransactionCreator{
		ledger:          ledger,
		assetRegistry:   assetRegistry,
		compliance:      compliance,
		securityManager: securityManager,
	}
}

// CreateTransaction initiates a new transaction for a SYN5000 token
func (tc *TransactionCreator) CreateTransaction(tokenID, sender, recipient, details string) (string, error) {
	// Validate sender's ownership of the token
	if !tc.assetRegistry.IsOwner(tokenID, sender) {
		return "", errors.New("transaction creation failed: sender does not own the token")
	}

	// Compliance check before processing transaction
	if err := tc.compliance.ValidateTransaction(sender, recipient); err != nil {
		return "", fmt.Errorf("transaction creation failed: compliance validation error: %w", err)
	}

	// Encrypt transaction details for security
	encryptedDetails, err := tc.securityManager.Encrypt(details)
	if err != nil {
		return "", fmt.Errorf("transaction creation failed: encryption error: %w", err)
	}

	// Generate transaction ID and record the transaction
	transactionID := tc.ledger.GenerateTransactionID()
	transaction := ledger.Transaction{
		ID:        transactionID,
		TokenID:   tokenID,
		From:      sender,
		To:        recipient,
		Timestamp: time.Now(),
		Details:   encryptedDetails,
		Status:    "Pending",
	}

	if err := tc.ledger.RecordTransaction(transaction); err != nil {
		return "", fmt.Errorf("transaction creation failed: ledger recording error: %w", err)
	}

	return transactionID, nil
}

// ConfirmTransaction marks a pending transaction as confirmed
func (tc *TransactionCreator) ConfirmTransaction(transactionID string) error {
	transaction, err := tc.ledger.GetTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("transaction confirmation failed: transaction retrieval error: %w", err)
	}

	if transaction.Status != "Pending" {
		return errors.New("transaction confirmation failed: transaction is not in a pending state")
	}

	// Update ownership and mark the transaction as completed
	if err := tc.assetRegistry.UpdateOwnership(transaction.TokenID, transaction.To); err != nil {
		return fmt.Errorf("transaction confirmation failed: ownership update error: %w", err)
	}

	transaction.Status = "Completed"
	if err := tc.ledger.UpdateTransaction(transaction); err != nil {
		return fmt.Errorf("transaction confirmation failed: ledger update error: %w", err)
	}

	return nil
}

// CancelTransaction allows the cancellation of a pending transaction
func (tc *TransactionCreator) CancelTransaction(transactionID, reason string) error {
	transaction, err := tc.ledger.GetTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("transaction cancellation failed: transaction retrieval error: %w", err)
	}

	if transaction.Status != "Pending" {
		return errors.New("transaction cancellation failed: transaction is not in a pending state")
	}

	// Securely record the reason for cancellation
	cancellationDetails := fmt.Sprintf("Cancellation reason: %s", reason)
	encryptedDetails, err := tc.securityManager.Encrypt(cancellationDetails)
	if err != nil {
		return fmt.Errorf("transaction cancellation failed: encryption error: %w", err)
	}

	transaction.Status = "Cancelled"
	transaction.Details = encryptedDetails

	if err := tc.ledger.UpdateTransaction(transaction); err != nil {
		return fmt.Errorf("transaction cancellation failed: ledger update error: %w", err)
	}

	return nil
}
