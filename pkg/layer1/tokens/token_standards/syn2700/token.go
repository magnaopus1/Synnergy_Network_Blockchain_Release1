package syn2700

import (
	"errors"
	"fmt"
	"time"
)

// PensionToken represents a tokenized unit of pension funds.
type PensionToken struct {
	TokenID         string    `json:"tokenId"`
	Owner           string    `json:"owner"`
	Balance         float64   `json:"balance"`
	PensionPlanID   string    `json:"pensionPlanId"`
	IssueDate       time.Time `json:"issueDate"`
	MaturityDate    time.Time `json:"maturityDate"`
	IsActive        bool      `json:"isActive"`
	VestingSchedule []VestingPoint
}

// VestingPoint represents a point in time when certain benefits or amounts become available.
type VestingPoint struct {
	Date   time.Time `json:"date"`
	Amount float64   `json:"amount"`
}

// PensionLedger manages the lifecycle and ownership of pension tokens.
type PensionLedger struct {
	Tokens map[string]PensionToken
}

// NewPensionLedger initializes a new ledger.
func NewPensionLedger() *PensionLedger {
	return &PensionLedger{
		Tokens: make(map[string]PensionToken),
	}
}

// IssueToken creates a new pension token with a vesting schedule.
func (pl *PensionLedger) IssueToken(owner, pensionPlanId string, balance float64, vesting []VestingPoint) (*PensionToken, error) {
	tokenID := fmt.Sprintf("PT-%s-%s", pensionPlanId, owner)
	if _, exists := pl.Tokens[tokenID]; exists {
		return nil, fmt.Errorf("token with ID %s already exists", tokenID)
	}

	newToken := PensionToken{
		TokenID:         tokenID,
		Owner:           owner,
		Balance:         balance,
		PensionPlanID:   pensionPlanId,
		IssueDate:       time.Now(),
		MaturityDate:    time.Now().AddDate(20, 0, 0),
		IsActive:        true,
		VestingSchedule: vesting,
	}
	pl.Tokens[tokenID] = newToken
	pl.logEvent("TokenIssued", tokenID)
	return &newToken, nil
}

// logEvent helps in logging various events to the ledger for transparency and audit purposes.
func (pl *PensionLedger) logEvent(eventType string, details interface{}) {
	fmt.Printf("Event: %s, Details: %v\n", eventType, details)
}

// TransferToken facilitates the transfer of token ownership.
func (pl *PensionLedger) TransferToken(tokenID, newOwner string) error {
	token, exists := pl.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	if !token.IsActive {
		return errors.New("token is inactive")
	}

	token.Owner = newOwner
	pl.Tokens[tokenID] = token
	pl.logEvent("TokenTransferred", tokenID)
	return nil
}

// RedeemToken manages the redemption process of tokens, considering vesting.
func (pl *PensionLedger) RedeemToken(tokenID string) error {
	token, exists := pl.Tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	now := time.Now()
	for _, point := range token.VestingSchedule {
		if now.After(point.Date) {
			token.Balance -= point.Amount
			if token.Balance <= 0 {
				token.IsActive = false
				break
			}
		}
	}

	if token.IsActive {
		return fmt.Errorf("token %s has unvested amounts", tokenID)
	}

	pl.Tokens[tokenID] = token
	pl.logEvent("TokenRedeemed", tokenID)
	return nil
}
