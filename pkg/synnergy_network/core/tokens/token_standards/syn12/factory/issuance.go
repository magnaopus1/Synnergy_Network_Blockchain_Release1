package factory

import (
	"errors"
	"fmt"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/assets"
	"synnergy_network/core/tokens/token_standards/syn12/compliance"
	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/security"
)

// IssuanceManager handles the issuance of SYN12 tokens.
type IssuanceManager struct {
	ledgerManager     *ledger.LedgerManager
	complianceManager *compliance.ComplianceManager
	securityManager   *security.SecurityManager
}

// NewIssuanceManager creates a new IssuanceManager.
func NewIssuanceManager(ledger *ledger.LedgerManager, compliance *compliance.ComplianceManager, security *security.SecurityManager) *IssuanceManager {
	return &IssuanceManager{
		ledgerManager:     ledger,
		complianceManager: compliance,
		securityManager:   security,
	}
}

// IssueToken issues a new SYN12 token with the provided metadata.
func (im *IssuanceManager) IssueToken(metadata assets.TBillMetadata, fiatDepositAmount float64) (*assets.TBillToken, error) {
	// Validate inputs
	if fiatDepositAmount <= 0 {
		return nil, errors.New("fiat deposit amount must be positive")
	}
	if err := im.validateMetadata(metadata); err != nil {
		return nil, fmt.Errorf("invalid metadata: %v", err)
	}

	// Compliance and security checks
	if err := im.complianceManager.VerifyIssuer(metadata.Issuer); err != nil {
		return nil, fmt.Errorf("compliance check failed: %v", err)
	}
	if err := im.securityManager.ValidateCollateral(metadata, fiatDepositAmount); err != nil {
		return nil, fmt.Errorf("security check failed: %v", err)
	}

	// Create the token
	token := &assets.TBillToken{
		Metadata:     metadata,
		IssueDate:    time.Now(),
		Owner:        metadata.Issuer.Name, // Initially owned by the issuer
		IsRedeemed:   false,
		FaceValue:    fiatDepositAmount,
		CurrentValue: fiatDepositAmount,
	}

	// Record the token in the ledger
	if err := im.ledgerManager.RecordToken(token); err != nil {
		return nil, fmt.Errorf("failed to record token: %v", err)
	}

	// Log the issuance event
	im.ledgerManager.LogEvent("Token Issued", fmt.Sprintf("Token ID: %s, Issuer: %s", metadata.TokenID, metadata.Issuer.Name))

	return token, nil
}

// validateMetadata validates the metadata for a T-Bill token.
func (im *IssuanceManager) validateMetadata(metadata assets.TBillMetadata) error {
	if metadata.TokenID == "" || metadata.TBillCode == "" {
		return errors.New("token ID and T-Bill code are required")
	}
	if metadata.MaturityDate.Before(time.Now()) {
		return errors.New("maturity date must be in the future")
	}
	if metadata.Issuer.Name == "" || metadata.Issuer.Location == "" {
		return errors.New("issuer information is incomplete")
	}
	return nil
}

// RedeemToken handles the redemption of a SYN12 token.
func (im *IssuanceManager) RedeemToken(tokenID string, redeemer string) (*assets.TBillToken, error) {
	token, err := im.ledgerManager.GetToken(tokenID)
	if err != nil {
		return nil, fmt.Errorf("token not found: %v", err)
	}

	if token.IsRedeemed {
		return nil, errors.New("token has already been redeemed")
	}

	// Compliance and security checks
	if err := im.complianceManager.VerifyRedeemer(token, redeemer); err != nil {
		return nil, fmt.Errorf("compliance check failed: %v", err)
	}
	if err := im.securityManager.ValidateRedemption(token); err != nil {
		return nil, fmt.Errorf("security check failed: %v", err)
	}

	// Mark the token as redeemed
	token.IsRedeemed = true
	token.RedemptionDate = time.Now()

	// Update the ledger
	if err := im.ledgerManager.UpdateToken(token); err != nil {
		return nil, fmt.Errorf("failed to update token status: %v", err)
	}

	// Log the redemption event
	im.ledgerManager.LogEvent("Token Redeemed", fmt.Sprintf("Token ID: %s, Redeemer: %s", tokenID, redeemer))

	return token, nil
}
