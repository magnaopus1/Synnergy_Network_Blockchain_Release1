package security

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn1700/ledger"
)

// AccessControl handles access rights management for event tickets
type AccessControl struct {
	Ledger *ledger.Ledger
}

// NewAccessControl creates a new instance of AccessControl
func NewAccessControl(ledger *ledger.Ledger) *AccessControl {
	return &AccessControl{Ledger: ledger}
}

// VerifyOwnership verifies if a user is the owner of a ticket
func (ac *AccessControl) VerifyOwnership(ticketID, userID string) (bool, error) {
	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return false, err
	}
	if ticket.OwnerID != userID {
		return false, errors.New("user does not own the ticket")
	}
	return true, nil
}

// GrantAccess grants access to a ticket holder for an event
func (ac *AccessControl) GrantAccess(ticketID, userID string) (bool, error) {
	valid, err := ac.VerifyOwnership(ticketID, userID)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("access denied: invalid ticket ownership")
	}

	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return false, err
	}

	if ticket.TimeLock != nil && time.Now().Before(*ticket.TimeLock) {
		return false, errors.New("access denied: ticket is time-locked")
	}

	if ticket.IsRevoked {
		return false, errors.New("access denied: ticket is revoked")
	}

	return true, nil
}

// RevokeAccess revokes access to a ticket holder
func (ac *AccessControl) RevokeAccess(ticketID string) error {
	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	ticket.IsRevoked = true
	return ac.Ledger.UpdateTicket(ticket)
}

// DelegateAccess delegates access rights to another user
func (ac *AccessControl) DelegateAccess(ticketID, fromUserID, toUserID string) error {
	valid, err := ac.VerifyOwnership(ticketID, fromUserID)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("delegation failed: invalid ticket ownership")
	}

	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	ticket.OwnerID = toUserID
	return ac.Ledger.UpdateTicket(ticket)
}

// TimeLockAccess sets a time-lock on a ticket
func (ac *AccessControl) TimeLockAccess(ticketID string, until time.Time) error {
	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	ticket.TimeLock = &until
	return ac.Ledger.UpdateTicket(ticket)
}

// RemoveTimeLock removes the time-lock from a ticket
func (ac *AccessControl) RemoveTimeLock(ticketID string) error {
	ticket, err := ac.Ledger.GetTicket(ticketID)
	if err != nil {
		return err
	}

	ticket.TimeLock = nil
	return ac.Ledger.UpdateTicket(ticket)
}

// FreezeAccount freezes a user's account
func (ac *AccessControl) FreezeAccount(userID string) error {
	user, err := ac.Ledger.GetUser(userID)
	if err != nil {
		return err
	}

	user.IsFrozen = true
	return ac.Ledger.UpdateUser(user)
}

// UnfreezeAccount unfreezes a user's account
func (ac *AccessControl) UnfreezeAccount(userID string) error {
	user, err := ac.Ledger.GetUser(userID)
	if err != nil {
		return err
	}

	user.IsFrozen = false
	return ac.Ledger.UpdateUser(user)
}
