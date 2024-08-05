package factory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/transactions"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
)

// IssuanceService manages the issuance of new SYN11 tokens.
type IssuanceService struct {
	mu             sync.Mutex
	assetRegistry  *assets.AssetRegistry
	ledger         *ledger.Ledger
	amlKycService  *compliance.AMLKYCService
	ownershipSvc   *ledger.OwnershipService
	tokenValidator *transactions.TokenValidator
	security       *security.SecurityService
}

// NewIssuanceService creates a new IssuanceService.
func NewIssuanceService(assetRegistry *assets.AssetRegistry, ledger *ledger.Ledger, amlKycService *compliance.AMLKYCService, ownershipSvc *ledger.OwnershipService, tokenValidator *transactions.TokenValidator, security *security.SecurityService) *IssuanceService {
	return &IssuanceService{
		assetRegistry:  assetRegistry,
		ledger:         ledger,
		amlKycService:  amlKycService,
		ownershipSvc:   ownershipSvc,
		tokenValidator: tokenValidator,
		security:       security,
	}
}

// IssueToken handles the issuance of a new SYN11 token.
func (svc *IssuanceService) IssueToken(request assets.AssetMetadata) (string, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	// Verify AML/KYC compliance
	if err := svc.amlKycService.VerifyIssuer(request.Issuer); err != nil {
		return "", fmt.Errorf("AML/KYC verification failed: %w", err)
	}

	// Generate a unique Token ID
	tokenID, err := svc.generateTokenID(request)
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create the asset and register it
	request.TokenID = tokenID
	if err := svc.assetRegistry.RegisterAsset(request); err != nil {
		return "", fmt.Errorf("asset registration failed: %w", err)
	}

	// Log the issuance in the ledger
	if err := svc.ledger.RecordIssuance(request); err != nil {
		return "", fmt.Errorf("ledger recording failed: %w", err)
	}

	// Update ownership records
	if err := svc.ownershipSvc.AddInitialOwnership(tokenID, request.Issuer); err != nil {
		return "", fmt.Errorf("ownership update failed: %w", err)
	}

	log.Printf("Successfully issued token with ID: %s", tokenID)
	return tokenID, nil
}

// generateTokenID creates a unique identifier for the token based on the asset metadata.
func (svc *IssuanceService) generateTokenID(metadata assets.AssetMetadata) (string, error) {
	data := fmt.Sprintf("%s:%s:%s:%d", metadata.Issuer.Name, metadata.GiltCode, metadata.CurrencyCode, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	tokenID := hex.EncodeToString(hash[:])
	return tokenID, nil
}

// CancelToken handles the cancellation of an existing SYN11 token.
func (svc *IssuanceService) CancelToken(tokenID string, reason string) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	// Validate the token's existence
	if !svc.tokenValidator.ValidateToken(tokenID) {
		return errors.New("token validation failed")
	}

	// Perform security check before cancellation
	if err := svc.security.AuthorizeCancellation(tokenID); err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	// Remove the asset from the registry
	if err := svc.assetRegistry.RemoveAsset(tokenID); err != nil {
		return fmt.Errorf("asset removal failed: %w", err)
	}

	// Update the ledger with cancellation details
	if err := svc.ledger.RecordCancellation(tokenID, reason); err != nil {
		return fmt.Errorf("ledger recording failed: %w", err)
	}

	// Remove ownership records
	if err := svc.ownershipSvc.RemoveOwnership(tokenID); err != nil {
		return fmt.Errorf("ownership removal failed: %w", err)
	}

	log.Printf("Successfully canceled token with ID: %s for reason: %s", tokenID, reason)
	return nil
}
