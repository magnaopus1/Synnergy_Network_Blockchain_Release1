package security

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// AccountFreezeManager manages the freezing and unfreezing of accounts.
type AccountFreezeManager struct {
	frozenAccounts map[string]*FrozenAccount
	mutex          sync.RWMutex
}

// FrozenAccount represents an account that has been frozen.
type FrozenAccount struct {
	AccountID  string
	FreezeTime time.Time
	Reason     string
}

// NewAccountFreezeManager initializes a new AccountFreezeManager.
func NewAccountFreezeManager() *AccountFreezeManager {
	return &AccountFreezeManager{
		frozenAccounts: make(map[string]*FrozenAccount),
	}
}

// FreezeAccount freezes the specified account with a reason.
func (afm *AccountFreezeManager) FreezeAccount(accountID, reason string) error {
	afm.mutex.Lock()
	defer afm.mutex.Unlock()

	if _, exists := afm.frozenAccounts[accountID]; exists {
		return fmt.Errorf("account %s is already frozen", accountID)
	}

	afm.frozenAccounts[accountID] = &FrozenAccount{
		AccountID:  accountID,
		FreezeTime: time.Now(),
		Reason:     reason,
	}

	logFreezeAction(accountID, reason, "froze")
	return nil
}

// UnfreezeAccount unfreezes the specified account.
func (afm *AccountFreezeManager) UnfreezeAccount(accountID string) error {
	afm.mutex.Lock()
	defer afm.mutex.Unlock()

	if _, exists := afm.frozenAccounts[accountID]; !exists {
		return fmt.Errorf("account %s is not frozen", accountID)
	}

	delete(afm.frozenAccounts, accountID)
	logFreezeAction(accountID, "", "unfroze")
	return nil
}

// IsAccountFrozen checks if the specified account is frozen.
func (afm *AccountFreezeManager) IsAccountFrozen(accountID string) (bool, *FrozenAccount) {
	afm.mutex.RLock()
	defer afm.mutex.RUnlock()

	frozenAccount, exists := afm.frozenAccounts[accountID]
	return exists, frozenAccount
}

// ListFrozenAccounts lists all currently frozen accounts.
func (afm *AccountFreezeManager) ListFrozenAccounts() []*FrozenAccount {
	afm.mutex.RLock()
	defer afm.mutex.RUnlock()

	accounts := make([]*FrozenAccount, 0, len(afm.frozenAccounts))
	for _, account := range afm.frozenAccounts {
		accounts = append(accounts, account)
	}
	return accounts
}

// logFreezeAction logs the freezing or unfreezing of an account.
func logFreezeAction(accountID, reason, action string) {
	// This function can be extended to log to a more sophisticated logging system
	logMessage := fmt.Sprintf("Account %s was %s at %s", accountID, action, time.Now().Format(time.RFC3339))
	if reason != "" {
		logMessage += fmt.Sprintf(" for reason: %s", reason)
	}
	fmt.Println(logMessage)
}
