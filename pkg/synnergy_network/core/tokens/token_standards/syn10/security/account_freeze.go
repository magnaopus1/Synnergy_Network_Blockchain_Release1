package security

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/logging"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/utilities"
)

// FreezeReason provides predefined reasons for account freezing.
type FreezeReason string

const (
	SuspiciousActivity FreezeReason = "Suspicious Activity"
	RegulatoryOrder    FreezeReason = "Regulatory Order"
	UserRequest        FreezeReason = "User Request"
	Other              FreezeReason = "Other"
)

// FreezeAction represents a record of a freeze or unfreeze action on an account.
type FreezeAction struct {
	ActionID   string
	AccountID  string
	AdminID    string
	Timestamp  time.Time
	Action     string
	Reason     FreezeReason
	Notes      string
}

// AccountFreezeManager manages freezing and unfreezing of accounts.
type AccountFreezeManager struct {
	ledger      ledger.Ledger
	log         logging.Logger
	actionsLog  map[string]FreezeAction // In-memory store for freeze actions; should be persisted in a production system
}

// NewAccountFreezeManager initializes a new AccountFreezeManager.
func NewAccountFreezeManager(ledger ledger.Ledger, log logging.Logger) *AccountFreezeManager {
	return &AccountFreezeManager{
		ledger:     ledger,
		log:        log,
		actionsLog: make(map[string]FreezeAction),
	}
}

// FreezeAccount freezes a specified account with a given reason and notes.
func (afm *AccountFreezeManager) FreezeAccount(accountID, adminID string, reason FreezeReason, notes string) error {
	if err := afm.ledger.SetAccountStatus(accountID, ledger.AccountStatusFrozen); err != nil {
		return err
	}

	action := FreezeAction{
		ActionID:  utilities.GenerateUUID(),
		AccountID: accountID,
		AdminID:   adminID,
		Timestamp: time.Now(),
		Action:    "freeze",
		Reason:    reason,
		Notes:     notes,
	}

	afm.actionsLog[action.ActionID] = action
	afm.logAction(action)
	return nil
}

// UnfreezeAccount unfreezes a specified account.
func (afm *AccountFreezeManager) UnfreezeAccount(accountID, adminID string, notes string) error {
	if err := afm.ledger.SetAccountStatus(accountID, ledger.AccountStatusActive); err != nil {
		return err
	}

	action := FreezeAction{
		ActionID:  utilities.GenerateUUID(),
		AccountID: accountID,
		AdminID:   adminID,
		Timestamp: time.Now(),
		Action:    "unfreeze",
		Reason:    Other,
		Notes:     notes,
	}

	afm.actionsLog[action.ActionID] = action
	afm.logAction(action)
	return nil
}

// IsAccountFrozen checks if an account is currently frozen.
func (afm *AccountFreezeManager) IsAccountFrozen(accountID string) (bool, error) {
	status, err := afm.ledger.GetAccountStatus(accountID)
	if err != nil {
		return false, err
	}
	return status == ledger.AccountStatusFrozen, nil
}

// GetFreezeActions returns a list of freeze and unfreeze actions for an account.
func (afm *AccountFreezeManager) GetFreezeActions(accountID string) ([]FreezeAction, error) {
	var actions []FreezeAction
	for _, action := range afm.actionsLog {
		if action.AccountID == accountID {
			actions = append(actions, action)
		}
	}
	if actions == nil {
		return nil, errors.New("no actions found for account")
	}
	return actions, nil
}

// logAction logs a freeze or unfreeze action.
func (afm *AccountFreezeManager) logAction(action FreezeAction) {
	afm.log.Infof("Action: %s, AccountID: %s, AdminID: %s, Reason: %s, Timestamp: %s, Notes: %s",
		action.Action, action.AccountID, action.AdminID, action.Reason, action.Timestamp.Format(time.RFC3339), action.Notes)
}


