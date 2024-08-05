package management

import (
	"encoding/json"
	"errors"
	"time"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn845"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// NodeType represents different types of nodes in the network
type NodeType string

const (
	GovernmentNode NodeType = "government"
	CreditorNode   NodeType = "creditor"
	CentralBankNode NodeType = "central_bank"
	BankingNode    NodeType = "banking"
)

// DebtIssuanceManager manages the issuance of debt instruments
type DebtIssuanceManager struct {
	mu sync.Mutex
	nodeType NodeType
}

// NewDebtIssuanceManager creates a new instance of DebtIssuanceManager
func NewDebtIssuanceManager(nodeType NodeType) *DebtIssuanceManager {
	return &DebtIssuanceManager{
		nodeType: nodeType,
	}
}

// IssueDebt creates a new debt instrument and records it in the ledger
func (dim *DebtIssuanceManager) IssueDebt(ownerID string, principalAmount, interestRate, penaltyRate float64, repaymentPeriod int, collateralID string) (string, error) {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	if !dim.isAuthorized() {
		return "", errors.New("unauthorized node type for issuing debt")
	}

	debtID, err := syn845.CreateSYN845(ownerID, principalAmount, interestRate, penaltyRate, repaymentPeriod, collateralID)
	if err != nil {
		return "", err
	}

	_, err = recordLedgerEntry(debtID, "debt issuance", principalAmount, principalAmount, 0, 0)
	if err != nil {
		return "", err
	}

	return debtID, nil
}

// UpdateDebt updates an existing debt instrument
func (dim *DebtIssuanceManager) UpdateDebt(debtID, ownerID string, principalAmount, interestRate, penaltyRate float64, repaymentPeriod int, collateralID, status string) error {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	if !dim.isAuthorized() {
		return errors.New("unauthorized node type for updating debt")
	}

	err := syn845.UpdateSYN845(debtID, principalAmount, interestRate, penaltyRate, repaymentPeriod, collateralID, status)
	if err != nil {
		return err
	}

	_, err = recordLedgerEntry(debtID, "debt update", principalAmount, principalAmount, 0, 0)
	if err != nil {
		return err
	}

	return nil
}

// RetrieveDebt retrieves a debt instrument by ID
func (dim *DebtIssuanceManager) RetrieveDebt(debtID string) (syn845.SYN845, error) {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	return syn845.GetSYN845(debtID)
}

// RemoveDebt removes a debt instrument by ID
func (dim *DebtIssuanceManager) RemoveDebt(debtID string) error {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	if !dim.isAuthorized() {
		return errors.New("unauthorized node type for removing debt")
	}

	return syn845.DeleteSYN845(debtID)
}

// isAuthorized checks if the current node type is authorized to perform debt issuance management actions
func (dim *DebtIssuanceManager) isAuthorized() bool {
	switch dim.nodeType {
	case GovernmentNode, CreditorNode, CentralBankNode, BankingNode:
		return true
	default:
		return false
	}
}

// recordLedgerEntry records a ledger entry for debt-related transactions
func recordLedgerEntry(debtID, transaction string, amount, balance, interest, principal float64) (string, error) {
	l := ledger.NewLedger()
	return l.RecordEntry(debtID, transaction, amount, balance, interest, principal)
}
