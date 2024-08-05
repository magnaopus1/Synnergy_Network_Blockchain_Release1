package factory

import (
	"errors"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/assets"
	"synnergy_network/core/tokens/token_standards/syn12/compliance"
	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/security"
	"synnergy_network/core/tokens/token_standards/syn12/transactions"
	"synnergy_network/core/tokens/token_standards/syn12/storage"
)

// TokenFactory is responsible for the creation, management, and destruction of SYN12 tokens.
type TokenFactory struct {
	ledgerManager      *ledger.LedgerManager
	storageManager     *storage.StorageManager
	complianceManager  *compliance.ComplianceManager
	securityManager    *security.SecurityManager
	transactionManager *transactions.TransactionManager
}

// NewTokenFactory creates a new instance of TokenFactory.
func NewTokenFactory(ledgerManager *ledger.LedgerManager, storageManager *storage.StorageManager, complianceManager *compliance.ComplianceManager, securityManager *security.SecurityManager, transactionManager *transactions.TransactionManager) *TokenFactory {
	return &TokenFactory{
		ledgerManager:      ledgerManager,
		storageManager:     storageManager,
		complianceManager:  complianceManager,
		securityManager:    securityManager,
		transactionManager: transactionManager,
	}
}

// CreateToken creates a new SYN12 token with the specified metadata and initial owner.
func (tf *TokenFactory) CreateToken(metadata assets.TBillMetadata, ownerID string) (*assets.TBillToken, error) {
	// Validate metadata
	if err := tf.validateMetadata(metadata); err != nil {
		return nil, err
	}

	// Compliance and security checks
	if err := tf.complianceManager.ValidateIssuance(metadata); err != nil {
		return nil, err
	}
	if err := tf.securityManager.VerifyIssuer(metadata.Issuer); err != nil {
		return nil, err
	}

	// Create token
	token := &assets.TBillToken{
		Metadata:   metadata,
		OwnerID:    ownerID,
		CreatedAt:  time.Now(),
		IsRedeemed: false,
	}

	// Store token in the ledger and storage
	if err := tf.ledgerManager.RecordNewToken(token); err != nil {
		return nil, err
	}
	if err := tf.storageManager.SaveMetadata(&metadata); err != nil {
		return nil, err
	}

	return token, nil
}

// validateMetadata ensures the token metadata is complete and adheres to SYN12 standards.
func (tf *TokenFactory) validateMetadata(metadata assets.TBillMetadata) error {
	if metadata.TokenID == "" {
		return errors.New("token ID cannot be empty")
	}
	if metadata.GiltCode == "" {
		return errors.New("gilt code cannot be empty")
	}
	if metadata.TotalSupply <= 0 {
		return errors.New("total supply must be greater than zero")
	}
	if metadata.CouponRate < 0 {
		return errors.New("coupon rate cannot be negative")
	}
	return nil
}

// DestroyToken marks a token as destroyed, ensuring it can no longer be transferred or redeemed.
func (tf *TokenFactory) DestroyToken(tokenID string, destroyerID string) error {
	// Retrieve the token from the ledger
	token, err := tf.ledgerManager.GetToken(tokenID)
	if err != nil {
		return err
	}

	// Security checks
	if err := tf.securityManager.ValidateDestruction(token, destroyerID); err != nil {
		return err
	}

	// Mark the token as destroyed
	token.IsRedeemed = true

	// Update the ledger and log the event
	if err := tf.ledgerManager.UpdateToken(token); err != nil {
		return err
	}
	tf.ledgerManager.LogEvent("Token Destroyed", tokenID)

	return nil
}

// UpdateMetadata allows updating of token metadata, such as discount rate, provided compliance and security are ensured.
func (tf *TokenFactory) UpdateMetadata(tokenID string, newMetadata assets.TBillMetadata, updaterID string) error {
	// Retrieve the token from the ledger
	token, err := tf.ledgerManager.GetToken(tokenID)
	if err != nil {
		return err
	}

	// Compliance and security checks
	if err := tf.complianceManager.ValidateMetadataUpdate(token.Metadata, newMetadata, updaterID); err != nil {
		return err
	}
	if err := tf.securityManager.ValidateMetadataUpdate(token.Metadata, newMetadata, updaterID); err != nil {
		return err
	}

	// Update the token metadata
	token.Metadata = newMetadata

	// Store the updated metadata
	if err := tf.storageManager.UpdateMetadata(&newMetadata); err != nil {
		return err
	}

	// Update the ledger
	if err := tf.ledgerManager.UpdateToken(token); err != nil {
		return err
	}

	// Log the update event
	tf.ledgerManager.LogEvent("Token Metadata Updated", tokenID)

	return nil
}
