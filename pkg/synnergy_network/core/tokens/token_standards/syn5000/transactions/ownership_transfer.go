// ownership_transfer.go

package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/security"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/assets"
)

// OwnershipTransferManager handles the transfer of ownership for SYN5000 tokens
type OwnershipTransferManager struct {
	ledger        *ledger.TransactionLedger
	assetRegistry *assets.AssetRegistry
	encryption    *security.Encryption
}

// NewOwnershipTransferManager initializes a new OwnershipTransferManager
func NewOwnershipTransferManager(ledger *ledger.TransactionLedger, assetRegistry *assets.AssetRegistry, encryption *security.Encryption) *OwnershipTransferManager {
	return &OwnershipTransferManager{
		ledger:        ledger,
		assetRegistry: assetRegistry,
		encryption:    encryption,
	}
}

// TransferOwnership facilitates the transfer of ownership of a SYN5000 token
func (otm *OwnershipTransferManager) TransferOwnership(tokenID, fromOwner, toOwner string) error {
	// Validate ownership
	if !otm.assetRegistry.IsOwner(tokenID, fromOwner) {
		return errors.New("invalid ownership: fromOwner does not own the token")
	}

	// Record the transfer in the ledger
	transferDetails := fmt.Sprintf("Transfer of token %s from %s to %s", tokenID, fromOwner, toOwner)
	encryptedDetails, err := otm.encryption.Encrypt(transferDetails)
	if err != nil {
		return fmt.Errorf("failed to encrypt transfer details: %w", err)
	}

	transaction := ledger.Transaction{
		ID:        otm.ledger.GenerateTransactionID(),
		TokenID:   tokenID,
		From:      fromOwner,
		To:        toOwner,
		Timestamp: time.Now(),
		Details:   encryptedDetails,
	}

	if err := otm.ledger.RecordTransaction(transaction); err != nil {
		return fmt.Errorf("failed to record transaction: %w", err)
	}

	// Update ownership in the asset registry
	if err := otm.assetRegistry.UpdateOwnership(tokenID, toOwner); err != nil {
		return fmt.Errorf("failed to update ownership: %w", err)
	}

	return nil
}

// VerifyOwnership verifies if a user is the current owner of a given token
func (otm *OwnershipTransferManager) VerifyOwnership(tokenID, owner string) (bool, error) {
	isOwner, err := otm.assetRegistry.IsOwner(tokenID, owner)
	if err != nil {
		return false, fmt.Errorf("failed to verify ownership: %w", err)
	}
	return isOwner, nil
}

// GetTransferHistory retrieves the transaction history of a specific SYN5000 token
func (otm *OwnershipTransferManager) GetTransferHistory(tokenID string) ([]ledger.Transaction, error) {
	history, err := otm.ledger.GetTransactionHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transaction history: %w", err)
	}

	// Decrypt transaction details
	for i := range history {
		decryptedDetails, err := otm.encryption.Decrypt(history[i].Details)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt transaction details: %w", err)
		}
		history[i].Details = decryptedDetails
	}

	return history, nil
}
