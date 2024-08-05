package management

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/factory"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/compliance"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn12/assets"
)

// UserInterface provides an interface for interacting with the SYN12 token system.
type UserInterface struct {
	TokenFactory *factory.TokenFactory
	Ledger       *ledger.TransactionLedger
	Compliance   *compliance.ComplianceManager
}

// NewUserInterface initializes a new UserInterface.
func NewUserInterface(factory *factory.TokenFactory, ledger *ledger.TransactionLedger, compliance *compliance.ComplianceManager) *UserInterface {
	return &UserInterface{
		TokenFactory: factory,
		Ledger:       ledger,
		Compliance:   compliance,
	}
}

// IssueTBillTokens handles the issuance of new T-Bill tokens to a user.
func (ui *UserInterface) IssueTBillTokens(userID string, fiatAmount float64) (string, error) {
	if err := ui.Compliance.PerformKYC(userID); err != nil {
		return "", fmt.Errorf("KYC failed: %v", err)
	}

	tokenID, err := ui.TokenFactory.IssueTokens(fiatAmount)
	if err != nil {
		return "", fmt.Errorf("token issuance failed: %v", err)
	}

	if err := ui.Ledger.RecordTransaction(tokenID, userID, fiatAmount, "issuance"); err != nil {
		return "", fmt.Errorf("transaction recording failed: %v", err)
	}

	return tokenID, nil
}

// RedeemTBillTokens handles the redemption of T-Bill tokens by a user.
func (ui *UserInterface) RedeemTBillTokens(userID, tokenID string) (float64, error) {
	if err := ui.Compliance.PerformKYC(userID); err != nil {
		return 0, fmt.Errorf("KYC failed: %v", err)
	}

	fiatAmount, err := ui.TokenFactory.RedeemTokens(tokenID)
	if err != nil {
		return 0, fmt.Errorf("token redemption failed: %v", err)
	}

	if err := ui.Ledger.RecordTransaction(tokenID, userID, fiatAmount, "redemption"); err != nil {
		return 0, fmt.Errorf("transaction recording failed: %v", err)
	}

	return fiatAmount, nil
}

// GetTBillMetadata retrieves the metadata of a specific T-Bill token.
func (ui *UserInterface) GetTBillMetadata(tokenID string) (assets.TBillMetadata, error) {
	metadata, err := ui.TokenFactory.GetTokenMetadata(tokenID)
	if err != nil {
		return assets.TBillMetadata{}, fmt.Errorf("failed to get token metadata: %v", err)
	}
	return metadata, nil
}

// TransferTBillTokens handles the transfer of T-Bill tokens between users.
func (ui *UserInterface) TransferTBillTokens(fromUserID, toUserID, tokenID string) error {
	if err := ui.Compliance.PerformKYC(fromUserID); err != nil {
		return fmt.Errorf("KYC failed for sender: %v", err)
	}
	if err := ui.Compliance.PerformKYC(toUserID); err != nil {
		return fmt.Errorf("KYC failed for recipient: %v", err)
	}

	if err := ui.TokenFactory.TransferTokens(tokenID, fromUserID, toUserID); err != nil {
		return fmt.Errorf("token transfer failed: %v", err)
	}

	if err := ui.Ledger.RecordTransaction(tokenID, toUserID, 0, "transfer"); err != nil {
		return fmt.Errorf("transaction recording failed: %v", err)
	}

	return nil
}

// GetTransactionHistory retrieves the transaction history for a specific user.
func (ui *UserInterface) GetTransactionHistory(userID string) ([]ledger.TransactionRecord, error) {
	history, err := ui.Ledger.GetTransactionHistory(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction history: %v", err)
	}
	return history, nil
}

// MonitorDiscountRates provides real-time updates of discount rates for T-Bills.
func (ui *UserInterface) MonitorDiscountRates(tokenID string) (float64, error) {
	rate, err := ui.TokenFactory.GetCurrentDiscountRate(tokenID)
	if err != nil {
		return 0, fmt.Errorf("failed to get discount rate: %v", err)
	}
	return rate, nil
}

// ScheduleMaturityPayments schedules automatic payments for matured T-Bills.
func (ui *UserInterface) ScheduleMaturityPayments(tokenID, userID string, maturityDate time.Time) error {
	err := ui.TokenFactory.ScheduleMaturityPayment(tokenID, userID, maturityDate)
	if err != nil {
		return fmt.Errorf("failed to schedule maturity payment: %v", err)
	}
	return nil
}
