package management

import (
	"errors"
	"fmt"
	"log"

	"github.com/synnergy_network/core/tokens/token_standards/syn11/compliance"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn11/smart_contracts"
)

// UserInterface manages the interaction layer for users interacting with SYN11 tokens.
type UserInterface struct {
	ledger             *ledger.TransactionLedger
	complianceService  *compliance.ComplianceService
	securityService    *security.SecurityService
	contractManager    *SmartContractManager
}

// NewUserInterface creates a new instance of UserInterface.
func NewUserInterface(
	ledger *ledger.TransactionLedger,
	compService *compliance.ComplianceService,
	secService *security.SecurityService,
	contractManager *SmartContractManager) *UserInterface {

	return &UserInterface{
		ledger:            ledger,
		complianceService: compService,
		securityService:   secService,
		contractManager:   contractManager,
	}
}

// ViewBalance allows users to view their token balance.
func (ui *UserInterface) ViewBalance(userID string) (float64, error) {
	balance, err := ui.ledger.GetBalance(userID)
	if err != nil {
		return 0, fmt.Errorf("error retrieving balance: %v", err)
	}
	return balance, nil
}

// TransferTokens facilitates the transfer of tokens from one user to another.
func (ui *UserInterface) TransferTokens(fromUserID, toUserID string, amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	// Check compliance requirements before proceeding
	if err := ui.complianceService.CheckTransferCompliance(fromUserID, toUserID, amount); err != nil {
		return fmt.Errorf("compliance check failed: %v", err)
	}

	// Perform the transfer
	if err := ui.ledger.Transfer(fromUserID, toUserID, amount); err != nil {
		return fmt.Errorf("transfer failed: %v", err)
	}

	log.Printf("Transferred %f tokens from %s to %s", amount, fromUserID, toUserID)
	return nil
}

// VoteOnProposal allows users to vote on governance proposals.
func (ui *UserInterface) VoteOnProposal(userID, proposalID string, vote bool) error {
	if !ui.securityService.IsVerifiedUser(userID) {
		return errors.New("user verification failed")
	}

	if err := ui.complianceService.VerifyKYC(userID); err != nil {
		return fmt.Errorf("KYC verification failed: %v", err)
	}

	if err := ui.contractManager.ExecuteContract(proposalID, map[string]interface{}{
		"voter": userID,
		"vote":  vote,
	}); err != nil {
		return fmt.Errorf("voting failed: %v", err)
	}

	log.Printf("User %s voted on proposal %s", userID, proposalID)
	return nil
}

// SubmitProposal allows users to submit new governance proposals.
func (ui *UserInterface) SubmitProposal(userID, title, description, contractCode string) (string, error) {
	if !ui.securityService.IsVerifiedUser(userID) {
		return "", errors.New("user verification failed")
	}

	proposalID := ui.generateProposalID()
	err := ui.contractManager.DeployContract(proposalID, contractCode, userID)
	if err != nil {
		return "", fmt.Errorf("proposal submission failed: %v", err)
	}

	log.Printf("User %s submitted proposal %s", userID, proposalID)
	return proposalID, nil
}

// generateProposalID generates a unique ID for each proposal.
func (ui *UserInterface) generateProposalID() string {
	// Generate a unique proposal ID (simplified for demonstration)
	return fmt.Sprintf("proposal_%d", len(ui.contractManager.contractRepository)+1)
}

// ParticipateInGovernance allows users to participate in governance by proposing and voting.
func (ui *UserInterface) ParticipateInGovernance(userID, action string, params map[string]interface{}) error {
	switch action {
	case "vote":
		proposalID, ok := params["proposalID"].(string)
		if !ok {
			return errors.New("invalid proposalID parameter")
		}
		vote, ok := params["vote"].(bool)
		if !ok {
			return errors.New("invalid vote parameter")
		}
		return ui.VoteOnProposal(userID, proposalID, vote)
	case "submit":
		title, ok := params["title"].(string)
		if !ok {
			return errors.New("invalid title parameter")
		}
		description, ok := params["description"].(string)
		if !ok {
			return errors.New("invalid description parameter")
		}
		contractCode, ok := params["contractCode"].(string)
		if !ok {
			return errors.New("invalid contractCode parameter")
		}
		_, err := ui.SubmitProposal(userID, title, description, contractCode)
		return err
	default:
		return errors.New("invalid governance action")
	}
}

// ListUserTransactions lists all transactions related to a user.
func (ui *UserInterface) ListUserTransactions(userID string) ([]ledger.Transaction, error) {
	transactions, err := ui.ledger.GetTransactionsForUser(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transactions: %v", err)
	}
	return transactions, nil
}

// RequestRedemption allows users to redeem SYN11 tokens for fiat currency.
func (ui *UserInterface) RequestRedemption(userID string, amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be greater than zero")
	}

	// Compliance and security checks
	if err := ui.complianceService.VerifyKYC(userID); err != nil {
		return fmt.Errorf("KYC verification failed: %v", err)
	}
	if err := ui.complianceService.CheckRedemptionCompliance(userID, amount); err != nil {
		return fmt.Errorf("compliance check failed: %v", err)
	}

	// Process redemption
	if err := ui.ledger.RedeemTokens(userID, amount); err != nil {
		return fmt.Errorf("redemption failed: %v", err)
	}

	log.Printf("User %s requested redemption of %f tokens", userID, amount)
	return nil
}

// HandleNotifications manages notifications to users regarding their transactions and activities.
func (ui *UserInterface) HandleNotifications(userID string, notifications []string) error {
	// Process and send notifications (simplified)
	for _, notification := range notifications {
		log.Printf("Notifying user %s: %s", userID, notification)
	}
	return nil
}

