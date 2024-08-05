// sale_history.go

package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/security"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/assets"
)

// SaleHistoryManager manages the sale history of SYN5000 tokens
type SaleHistoryManager struct {
	ledger        *ledger.TransactionLedger
	assetRegistry *assets.AssetRegistry
	encryption    *security.Encryption
}

// NewSaleHistoryManager initializes a new SaleHistoryManager
func NewSaleHistoryManager(ledger *ledger.TransactionLedger, assetRegistry *assets.AssetRegistry, encryption *security.Encryption) *SaleHistoryManager {
	return &SaleHistoryManager{
		ledger:        ledger,
		assetRegistry: assetRegistry,
		encryption:    encryption,
	}
}

// RecordSale records a sale of a SYN5000 token
func (shm *SaleHistoryManager) RecordSale(tokenID, seller, buyer string, salePrice float64) error {
	// Validate ownership
	if !shm.assetRegistry.IsOwner(tokenID, seller) {
		return errors.New("invalid ownership: seller does not own the token")
	}

	// Record the sale in the ledger
	saleDetails := fmt.Sprintf("Sale of token %s from %s to %s for %f", tokenID, seller, buyer, salePrice)
	encryptedDetails, err := shm.encryption.Encrypt(saleDetails)
	if err != nil {
		return fmt.Errorf("failed to encrypt sale details: %w", err)
	}

	transaction := ledger.Transaction{
		ID:        shm.ledger.GenerateTransactionID(),
		TokenID:   tokenID,
		From:      seller,
		To:        buyer,
		Timestamp: time.Now(),
		Details:   encryptedDetails,
	}

	if err := shm.ledger.RecordTransaction(transaction); err != nil {
		return fmt.Errorf("failed to record transaction: %w", err)
	}

	// Update ownership in the asset registry
	if err := shm.assetRegistry.UpdateOwnership(tokenID, buyer); err != nil {
		return fmt.Errorf("failed to update ownership: %w", err)
	}

	return nil
}

// GetSaleHistory retrieves the sale history of a specific SYN5000 token
func (shm *SaleHistoryManager) GetSaleHistory(tokenID string) ([]ledger.Transaction, error) {
	history, err := shm.ledger.GetTransactionHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transaction history: %w", err)
	}

	// Decrypt transaction details
	for i := range history {
		decryptedDetails, err := shm.encryption.Decrypt(history[i].Details)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt transaction details: %w", err)
		}
		history[i].Details = decryptedDetails
	}

	return history, nil
}
