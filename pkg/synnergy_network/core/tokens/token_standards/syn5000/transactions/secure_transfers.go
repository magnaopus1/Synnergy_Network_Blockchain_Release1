// secure_transfers.go

package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/security"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/assets"
	"github.com/synnergy_network/compliance"
)

// SecureTransferManager handles secure transfers of SYN5000 tokens
type SecureTransferManager struct {
	ledger        *ledger.TransactionLedger
	assetRegistry *assets.AssetRegistry
	compliance    *compliance.ComplianceManager
	encryption    *security.Encryption
}

// NewSecureTransferManager initializes a new SecureTransferManager
func NewSecureTransferManager(ledger *ledger.TransactionLedger, assetRegistry *assets.AssetRegistry, compliance *compliance.ComplianceManager, encryption *security.Encryption) *SecureTransferManager {
	return &SecureTransferManager{
		ledger:        ledger,
		assetRegistry: assetRegistry,
		compliance:    compliance,
		encryption:    encryption,
	}
}

// InitiateTransfer initiates a secure transfer of a SYN5000 token
func (stm *SecureTransferManager) InitiateTransfer(tokenID, sender, recipient string, transferDetails string) error {
	// Validate ownership and compliance
	if !stm.assetRegistry.IsOwner(tokenID, sender) {
		return errors.New("transfer initiation failed: sender does not own the token")
	}

	if err := stm.compliance.ValidateTransfer(sender, recipient); err != nil {
		return fmt.Errorf("transfer initiation failed: compliance validation error: %w", err)
	}

	// Encrypt transfer details for secure storage
	encryptedDetails, err := stm.encryption.Encrypt(transferDetails)
	if err != nil {
		return fmt.Errorf("transfer initiation failed: encryption error: %w", err)
	}

	transaction := ledger.Transaction{
		ID:        stm.ledger.GenerateTransactionID(),
		TokenID:   tokenID,
		From:      sender,
		To:        recipient,
		Timestamp: time.Now(),
		Details:   encryptedDetails,
		Status:    "Pending",
	}

	if err := stm.ledger.RecordTransaction(transaction); err != nil {
		return fmt.Errorf("transfer initiation failed: ledger recording error: %w", err)
	}

	return nil
}

// ConfirmTransfer confirms a pending token transfer
func (stm *SecureTransferManager) ConfirmTransfer(transactionID string) error {
	// Retrieve and verify the transaction
	transaction, err := stm.ledger.GetTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("transfer confirmation failed: transaction retrieval error: %w", err)
	}

	if transaction.Status != "Pending" {
		return errors.New("transfer confirmation failed: transaction is not in a pending state")
	}

	// Update ownership in the asset registry
	if err := stm.assetRegistry.UpdateOwnership(transaction.TokenID, transaction.To); err != nil {
		return fmt.Errorf("transfer confirmation failed: ownership update error: %w", err)
	}

	// Update transaction status
	transaction.Status = "Completed"
	if err := stm.ledger.UpdateTransaction(transaction); err != nil {
		return fmt.Errorf("transfer confirmation failed: ledger update error: %w", err)
	}

	return nil
}

// CancelTransfer cancels a pending token transfer
func (stm *SecureTransferManager) CancelTransfer(transactionID, reason string) error {
	// Retrieve and verify the transaction
	transaction, err := stm.ledger.GetTransaction(transactionID)
	if err != nil {
		return fmt.Errorf("transfer cancellation failed: transaction retrieval error: %w", err)
	}

	if transaction.Status != "Pending" {
		return errors.New("transfer cancellation failed: transaction is not in a pending state")
	}

	// Record the cancellation reason securely
	cancellationDetails := fmt.Sprintf("Cancellation reason: %s", reason)
	encryptedDetails, err := stm.encryption.Encrypt(cancellationDetails)
	if err != nil {
		return fmt.Errorf("transfer cancellation failed: encryption error: %w", err)
	}

	transaction.Status = "Cancelled"
	transaction.Details = encryptedDetails

	if err := stm.ledger.UpdateTransaction(transaction); err != nil {
		return fmt.Errorf("transfer cancellation failed: ledger update error: %w", err)
	}

	return nil
}
