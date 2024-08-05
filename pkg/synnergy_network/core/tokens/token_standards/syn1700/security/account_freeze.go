package security

import (
	"errors"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/ledger"
)

// AccountFreeze handles freezing and unfreezing user accounts
type AccountFreeze struct {
	Ledger *ledger.Ledger
}

// NewAccountFreeze creates a new instance of AccountFreeze
func NewAccountFreeze(ledger *ledger.Ledger) *AccountFreeze {
	return &AccountFreeze{Ledger: ledger}
}

// FreezeAccount freezes a user's account, preventing any ticket-related actions
func (af *AccountFreeze) FreezeAccount(userID string) error {
	user, err := af.Ledger.GetUser(userID)
	if err != nil {
		return err
	}

	if user.IsFrozen {
		return errors.New("account is already frozen")
	}

	user.IsFrozen = true
	return af.Ledger.UpdateUser(user)
}

// UnfreezeAccount unfreezes a user's account, allowing ticket-related actions to proceed
func (af *AccountFreeze) UnfreezeAccount(userID string) error {
	user, err := af.Ledger.GetUser(userID)
	if err != nil {
		return err
	}

	if !user.IsFrozen {
		return errors.New("account is not frozen")
	}

	user.IsFrozen = false
	return af.Ledger.UpdateUser(user)
}

// IsAccountFrozen checks if a user's account is frozen
func (af *AccountFreeze) IsAccountFrozen(userID string) (bool, error) {
	user, err := af.Ledger.GetUser(userID)
	if err != nil {
		return false, err
	}

	return user.IsFrozen, nil
}

// FreezeTicket freezes a specific ticket, preventing its use
func (af *AccountFreeze) FreezeTicket(ticketID string) error {
	ticket, err := af.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	if ticket.IsFrozen {
		return errors.New("ticket is already frozen")
	}

	ticket.IsFrozen = true
	return af.Ledger.UpdateTicket(ticket)
}

// UnfreezeTicket unfreezes a specific ticket, allowing its use
func (af *AccountFreeze) UnfreezeTicket(ticketID string) error {
	ticket, err := af.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	if !ticket.IsFrozen {
		return errors.New("ticket is not frozen")
	}

	ticket.IsFrozen = false
	return af.Ledger.UpdateTicket(ticket)
}

// IsTicketFrozen checks if a specific ticket is frozen
func (af *AccountFreeze) IsTicketFrozen(ticketID string) (bool, error) {
	ticket, err := af.Ledger.GetTicket(ticketID)
	if err != nil {
		return false, err
	}

	return ticket.IsFrozen, nil
}
