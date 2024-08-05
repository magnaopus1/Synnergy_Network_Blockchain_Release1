package factory

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/transactions"
)

// RedemptionService manages the redemption of SYN11 tokens.
type RedemptionService struct {
	mu             sync.Mutex
	assetRegistry  *assets.AssetRegistry
	ledger         *ledger.Ledger
	ownershipSvc   *ledger.OwnershipService
	tokenValidator *transactions.TokenValidator
	security       *security.SecurityService
}

// NewRedemptionService creates a new RedemptionService.
func NewRedemptionService(assetRegistry *assets.AssetRegistry, ledger *ledger.Ledger, ownershipSvc *ledger.OwnershipService, tokenValidator *transactions.TokenValidator, security *security.SecurityService) *RedemptionService {
	return &RedemptionService{
		assetRegistry:  assetRegistry,
		ledger:         ledger,
		ownershipSvc:   ownershipSvc,
		tokenValidator: tokenValidator,
		security:       security,
	}
}

// RedeemToken handles the redemption of a SYN11 token for fiat currency.
func (svc *RedemptionService) RedeemToken(tokenID string, amount uint64, redeemerID string) (string, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	// Validate the token's existence and legitimacy
	if !svc.tokenValidator.ValidateToken(tokenID) {
		return "", errors.New("token validation failed")
	}

	// Check ownership and authorization
	owner, err := svc.ownershipSvc.GetOwner(tokenID)
	if err != nil || owner.ID != redeemerID {
		return "", errors.New("unauthorized redemption attempt")
	}

	// Check if the token is eligible for redemption
	if !svc.assetRegistry.IsRedeemable(tokenID) {
		return "", errors.New("token is not redeemable at this time")
	}

	// Perform security check before redemption
	if err := svc.security.AuthorizeRedemption(tokenID, amount, redeemerID); err != nil {
		return "", fmt.Errorf("authorization failed: %w", err)
	}

	// Process the redemption
	redemptionID, err := svc.processRedemption(tokenID, amount)
	if err != nil {
		return "", fmt.Errorf("redemption processing failed: %w", err)
	}

	// Update the ledger with redemption details
	if err := svc.ledger.RecordRedemption(redemptionID, tokenID, amount, redeemerID); err != nil {
		return "", fmt.Errorf("ledger recording failed: %w", err)
	}

	// Remove the token from the registry
	if err := svc.assetRegistry.RemoveAsset(tokenID); err != nil {
		return "", fmt.Errorf("asset removal failed: %w", err)
	}

	log.Printf("Successfully redeemed token with ID: %s", tokenID)
	return redemptionID, nil
}

// processRedemption handles the actual redemption process including fiat transfer.
func (svc *RedemptionService) processRedemption(tokenID string, amount uint64) (string, error) {
	// Simulate fiat transfer and generate a unique redemption ID
	redemptionID := fmt.Sprintf("redeem-%d-%s", time.Now().UnixNano(), tokenID)
	// Implement fiat transfer logic here (e.g., API call to a banking system)
	// ...

	// For demonstration purposes, we assume the transfer is always successful
	log.Printf("Processed redemption for token ID: %s, amount: %d", tokenID, amount)
	return redemptionID, nil
}

// CancelRedemption handles the cancellation of a redemption request.
func (svc *RedemptionService) CancelRedemption(redemptionID string) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	// Validate the redemption ID
	if !svc.ledger.ValidateRedemptionID(redemptionID) {
		return errors.New("invalid redemption ID")
	}

	// Perform security check before cancellation
	if err := svc.security.AuthorizeCancellation(redemptionID); err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	// Cancel the redemption and update the ledger
	if err := svc.ledger.CancelRedemption(redemptionID); err != nil {
		return fmt.Errorf("ledger update failed: %w", err)
	}

	log.Printf("Successfully canceled redemption with ID: %s", redemptionID)
	return nil
}
