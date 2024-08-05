package management

import (
	"errors"
	"time"

	"pkg/synnergy_network/core/tokens/token_standards/syn1967/assets"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/ledger"
	"pkg/synnergy_network/core/tokens/token_standards/syn1967/security"
)

// UserInterfaceManager handles the interactions between the users and the SYN1967 token system
type UserInterfaceManager struct {
	ledger           *ledger.Ledger
	stakeholders     *StakeholderEngagementManager
	collateral       *assets.CollateralManager
	commodityPegging *assets.CommodityPeggingManager
	accessControl    *security.AccessControlManager
}

// NewUserInterfaceManager creates a new user interface manager
func NewUserInterfaceManager(ledger *ledger.Ledger, stakeholders *StakeholderEngagementManager, collateral *assets.CollateralManager, commodityPegging *assets.CommodityPeggingManager, accessControl *security.AccessControlManager) *UserInterfaceManager {
	return &UserInterfaceManager{
		ledger:           ledger,
		stakeholders:     stakeholders,
		collateral:       collateral,
		commodityPegging: commodityPegging,
		accessControl:    accessControl,
	}
}

// RegisterUser registers a new user in the system
func (uim *UserInterfaceManager) RegisterUser(id, name, address, email, role string, initialBalance float64) error {
	if err := uim.stakeholders.AddStakeholder(id, name, address, email, role, initialBalance); err != nil {
		return err
	}

	// Assign role-based access permissions
	if err := uim.accessControl.AssignRole(id, role); err != nil {
		return err
	}

	return nil
}

// RemoveUser removes a user from the system
func (uim *UserInterfaceManager) RemoveUser(id string) error {
	if err := uim.stakeholders.RemoveStakeholder(id); err != nil {
		return err
	}

	// Remove role-based access permissions
	if err := uim.accessControl.RevokeRole(id); err != nil {
		return err
	}

	return nil
}

// UpdateUser updates the details of an existing user
func (uim *UserInterfaceManager) UpdateUser(id, name, address, email, role string) error {
	if err := uim.stakeholders.UpdateStakeholder(id, name, address, email, role); err != nil {
		return err
	}

	// Update role-based access permissions
	if err := uim.accessControl.UpdateRole(id, role); err != nil {
		return err
	}

	return nil
}

// GetUser retrieves the details of a specific user
func (uim *UserInterfaceManager) GetUser(id string) (Stakeholder, error) {
	return uim.stakeholders.GetStakeholder(id)
}

// ListUsers lists all users in the system
func (uim *UserInterfaceManager) ListUsers() []Stakeholder {
	return uim.stakeholders.ListStakeholders()
}

// TransferTokens transfers tokens from one user to another
func (uim *UserInterfaceManager) TransferTokens(fromID, toID string, amount float64) error {
	fromStakeholder, err := uim.stakeholders.GetStakeholder(fromID)
	if err != nil {
		return err
	}

	toStakeholder, err := uim.stakeholders.GetStakeholder(toID)
	if err != nil {
		return err
	}

	if fromStakeholder.Balance < amount {
		return errors.New("insufficient balance")
	}

	fromStakeholder.Balance -= amount
	toStakeholder.Balance += amount

	uim.stakeholders.UpdateStakeholder(fromID, fromStakeholder.Name, fromStakeholder.Address, fromStakeholder.Email, fromStakeholder.Role)
	uim.stakeholders.UpdateStakeholder(toID, toStakeholder.Name, toStakeholder.Address, toStakeholder.Email, toStakeholder.Role)

	// Log the transfer in the ledger
	uim.ledger.LogEvent(events.Event{
		Timestamp: time.Now(),
		Type:      events.EventTypeTokensTransferred,
		Details: map[string]interface{}{
			"from":   fromID,
			"to":     toID,
			"amount": amount,
		},
	})

	return nil
}

// PegTokensToCommodity pegs a specific number of tokens to a commodity
func (uim *UserInterfaceManager) PegTokensToCommodity(userID, commodityID string, amount float64) error {
	// Ensure the user has sufficient balance
	stakeholder, err := uim.stakeholders.GetStakeholder(userID)
	if err != nil {
		return err
	}

	if stakeholder.Balance < amount {
		return errors.New("insufficient balance")
	}

	// Peg tokens to the commodity
	if err := uim.commodityPegging.PegTokens(commodityID, amount); err != nil {
		return err
	}

	stakeholder.Balance -= amount
	uim.stakeholders.UpdateStakeholder(userID, stakeholder.Name, stakeholder.Address, stakeholder.Email, stakeholder.Role)

	// Log the pegging event in the ledger
	uim.ledger.LogEvent(events.Event{
		Timestamp: time.Now(),
		Type:      events.EventTypeTokensPegged,
		Details: map[string]interface{}{
			"user":      userID,
			"commodity": commodityID,
			"amount":    amount,
		},
	})

	return nil
}

// RedeemTokensFromCommodity redeems a specific number of tokens from a commodity
func (uim *UserInterfaceManager) RedeemTokensFromCommodity(userID, commodityID string, amount float64) error {
	// Redeem tokens from the commodity
	if err := uim.commodityPegging.RedeemTokens(commodityID, amount); err != nil {
		return err
	}

	stakeholder, err := uim.stakeholders.GetStakeholder(userID)
	if err != nil {
		return err
	}

	stakeholder.Balance += amount
	uim.stakeholders.UpdateStakeholder(userID, stakeholder.Name, stakeholder.Address, stakeholder.Email, stakeholder.Role)

	// Log the redemption event in the ledger
	uim.ledger.LogEvent(events.Event{
		Timestamp: time.Now(),
		Type:      events.EventTypeTokensRedeemed,
		Details: map[string]interface{}{
			"user":      userID,
			"commodity": commodityID,
			"amount":    amount,
		},
	})

	return nil
}

// GetCommodityPrice retrieves the current price of a commodity
func (uim *UserInterfaceManager) GetCommodityPrice(commodityID string) (float64, error) {
	return uim.commodityPegging.GetCurrentPrice(commodityID)
}

// ListCommodities lists all commodities and their prices
func (uim *UserInterfaceManager) ListCommodities() ([]assets.Commodity, error) {
	return uim.commodityPegging.ListCommodities()
}
