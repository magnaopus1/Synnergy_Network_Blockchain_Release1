package factory

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/transactions"
)

// TokenFactory handles the creation and issuance of SYN11 tokens.
type TokenFactory struct {
	mu              sync.Mutex
	assetRegistry   *assets.AssetRegistry
	compliance      *compliance.ComplianceService
	ledger          *ledger.Ledger
	security        *security.SecurityService
	ownershipSvc    *ledger.OwnershipService
	transactionSvc  *transactions.TransactionService
}

// NewTokenFactory creates a new TokenFactory.
func NewTokenFactory(assetRegistry *assets.AssetRegistry, compliance *compliance.ComplianceService, ledger *ledger.Ledger, security *security.SecurityService, ownershipSvc *ledger.OwnershipService, transactionSvc *transactions.TransactionService) *TokenFactory {
	return &TokenFactory{
		assetRegistry:   assetRegistry,
		compliance:      compliance,
		ledger:          ledger,
		security:        security,
		ownershipSvc:    ownershipSvc,
		transactionSvc:  transactionSvc,
	}
}

// IssueToken handles the issuance of new SYN11 tokens.
func (factory *TokenFactory) IssueToken(giltCode string, issuerID string, amount uint64, maturityDate time.Time, couponRate float64) (string, error) {
	factory.mu.Lock()
	defer factory.mu.Unlock()

	// Compliance and Security Checks
	if err := factory.compliance.ValidateIssuer(issuerID); err != nil {
		return "", fmt.Errorf("issuer validation failed: %w", err)
	}

	if err := factory.security.AuthorizeTokenIssuance(issuerID, amount); err != nil {
		return "", fmt.Errorf("authorization failed: %w", err)
	}

	// Create and Register the Token
	tokenID := fmt.Sprintf("SYN11-%d-%s", time.Now().UnixNano(), giltCode)
	assetMetadata := assets.AssetMetadata{
		TokenID:         tokenID,
		CurrencyCode:    "USD", // Assuming USD for simplicity; could be parameterized
		Issuer:          assets.IssuerInfo{ID: issuerID},
		MaturityDate:    maturityDate,
		TotalSupply:     amount,
		CouponRate:      couponRate,
		CreationDate:    time.Now(),
	}
	if err := factory.assetRegistry.RegisterAsset(assetMetadata); err != nil {
		return "", fmt.Errorf("asset registration failed: %w", err)
	}

	// Record the Issuance in the Ledger
	if err := factory.ledger.RecordIssuance(tokenID, issuerID, amount); err != nil {
		return "", fmt.Errorf("ledger recording failed: %w", err)
	}

	// Update Ownership Records
	if err := factory.ownershipSvc.AssignOwnership(tokenID, issuerID, amount); err != nil {
		return "", fmt.Errorf("ownership assignment failed: %w", err)
	}

	log.Printf("Successfully issued token with ID: %s", tokenID)
	return tokenID, nil
}

// BurnToken handles the burning of SYN11 tokens, effectively removing them from circulation.
func (factory *TokenFactory) BurnToken(tokenID string, amount uint64, burnerID string) error {
	factory.mu.Lock()
	defer factory.mu.Unlock()

	// Ownership and Compliance Check
	if err := factory.ownershipSvc.VerifyOwnership(tokenID, burnerID, amount); err != nil {
		return fmt.Errorf("ownership verification failed: %w", err)
	}

	if err := factory.compliance.ValidateBurning(tokenID, amount); err != nil {
		return fmt.Errorf("burning validation failed: %w", err)
	}

	// Perform Security Check
	if err := factory.security.AuthorizeTokenBurning(tokenID, amount, burnerID); err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	// Burn the Tokens
	if err := factory.assetRegistry.BurnAsset(tokenID, amount); err != nil {
		return fmt.Errorf("asset burning failed: %w", err)
	}

	// Update the Ledger
	if err := factory.ledger.RecordBurning(tokenID, burnerID, amount); err != nil {
		return fmt.Errorf("ledger recording failed: %w", err)
	}

	// Update Ownership Records
	if err := factory.ownershipSvc.ReduceOwnership(tokenID, burnerID, amount); err != nil {
		return fmt.Errorf("ownership reduction failed: %w", err)
	}

	log.Printf("Successfully burned %d tokens of ID: %s", amount, tokenID)
	return nil
}

// ListTokens returns a list of all active tokens.
func (factory *TokenFactory) ListTokens() ([]assets.AssetMetadata, error) {
	tokens, err := factory.assetRegistry.ListAssets()
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	return tokens, nil
}

// TransferOwnership handles the transfer of token ownership between entities.
func (factory *TokenFactory) TransferOwnership(tokenID string, fromID string, toID string, amount uint64) error {
	factory.mu.Lock()
	defer factory.mu.Unlock()

	// Verify Ownership and Compliance
	if err := factory.ownershipSvc.VerifyOwnership(tokenID, fromID, amount); err != nil {
		return fmt.Errorf("ownership verification failed: %w", err)
	}

	if err := factory.compliance.ValidateTransfer(fromID, toID, amount); err != nil {
		return fmt.Errorf("transfer validation failed: %w", err)
	}

	// Execute Transfer
	if err := factory.transactionSvc.Transfer(tokenID, fromID, toID, amount); err != nil {
		return fmt.Errorf("transfer failed: %w", err)
	}

	// Update Ownership Records
	if err := factory.ownershipSvc.TransferOwnership(tokenID, fromID, toID, amount); err != nil {
		return fmt.Errorf("ownership update failed: %w", err)
	}

	log.Printf("Successfully transferred %d tokens of ID: %s from %s to %s", amount, tokenID, fromID, toID)
	return nil
}
