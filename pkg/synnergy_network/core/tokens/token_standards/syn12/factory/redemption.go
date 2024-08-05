package factory

import (
	"errors"
	"fmt"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/assets"
	"synnergy_network/core/tokens/token_standards/syn12/compliance"
	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/security"
	"synnergy_network/core/tokens/token_standards/syn12/transactions"
)

// RedemptionManager handles the redemption of SYN12 tokens.
type RedemptionManager struct {
	ledgerManager       *ledger.LedgerManager
	complianceManager   *compliance.ComplianceManager
	securityManager     *security.SecurityManager
	transactionManager  *transactions.TransactionManager
}

// NewRedemptionManager creates a new RedemptionManager.
func NewRedemptionManager(ledger *ledger.LedgerManager, compliance *compliance.ComplianceManager, security *security.SecurityManager, transactions *transactions.TransactionManager) *RedemptionManager {
	return &RedemptionManager{
		ledgerManager:       ledger,
		complianceManager:   compliance,
		securityManager:     security,
		transactionManager:  transactions,
	}
}

// RedeemToken redeems a SYN12 token, converting it back into fiat currency.
func (rm *RedemptionManager) RedeemToken(tokenID string, redeemerID string) (*assets.TBillToken, error) {
	// Retrieve the token from the ledger
	token, err := rm.ledgerManager.GetToken(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token: %v", err)
	}

	// Check if the token is already redeemed
	if token.IsRedeemed {
		return nil, errors.New("token has already been redeemed")
	}

	// Compliance and security checks
	if err := rm.complianceManager.VerifyRedeemer(token, redeemerID); err != nil {
		return nil, fmt.Errorf("compliance verification failed: %v", err)
	}
	if err := rm.securityManager.ValidateRedemption(token, redeemerID); err != nil {
		return nil, fmt.Errorf("security verification failed: %v", err)
	}

	// Process the redemption
	token.IsRedeemed = true
	token.RedemptionDate = time.Now()
	token.RedeemerID = redeemerID

	// Update the ledger
	if err := rm.ledgerManager.UpdateToken(token); err != nil {
		return nil, fmt.Errorf("failed to update token status in ledger: %v", err)
	}

	// Log the redemption event
	rm.ledgerManager.LogEvent("Token Redeemed", fmt.Sprintf("Token ID: %s, Redeemer: %s", tokenID, redeemerID))

	// Handle fiat currency withdrawal
	if err := rm.processFiatWithdrawal(token); err != nil {
		return nil, fmt.Errorf("failed to process fiat withdrawal: %v", err)
	}

	return token, nil
}

// processFiatWithdrawal handles the conversion of the redeemed token value to fiat currency.
func (rm *RedemptionManager) processFiatWithdrawal(token *assets.TBillToken) error {
	// Implement the logic for processing fiat withdrawals here
	// This may include interacting with banking APIs, updating financial records, etc.
	// For this example, we'll assume the process is successful.
	fmt.Printf("Processing fiat withdrawal for token %s with value %.2f\n", token.Metadata.TokenID, token.CurrentValue)
	return nil
}
