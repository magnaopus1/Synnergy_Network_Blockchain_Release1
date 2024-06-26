package zero_fee_transactions

import (
	"errors"
	"sync"
)

// ZeroFeePolicy defines the conditions under which zero-fee transactions are allowed
type ZeroFeePolicy struct {
	sync.Mutex
	allowedAccounts map[string]bool // Accounts that are allowed to make zero-fee transactions
	thresholdAmount int64           // Transactions below this amount can be zero-fee
}

// NewZeroFeePolicy initializes a new ZeroFeePolicy
func NewZeroFeePolicy(thresholdAmount int64) *ZeroFeePolicy {
	return &ZeroFeePolicy{
		allowedAccounts: make(map[string]bool),
		thresholdAmount: thresholdAmount,
	}
}

// AddAllowedAccount adds an account to the list of allowed zero-fee accounts
func (zfp *ZeroFeePolicy) AddAllowedAccount(account string) {
	zfp.Lock()
	defer zfp.Unlock()
	zfp.allowedAccounts[account] = true
}

// RemoveAllowedAccount removes an account from the list of allowed zero-fee accounts
func (zfp *ZeroFeePolicy) RemoveAllowedAccount(account string) {
	zfp.Lock()
	defer zfp.Unlock()
	delete(zfp.allowedAccounts, account)
}

// IsZeroFeeAllowed checks if a given transaction can be zero-fee based on the account and transaction amount
func (zfp *ZeroFeePolicy) IsZeroFeeAllowed(account string, amount int64) (bool, error) {
	if account == "" {
		return false, errors.New("account cannot be empty")
	}
	if amount < 0 {
		return false, errors.New("transaction amount cannot be negative")
	}

	zfp.Lock()
	defer zfp.Unlock()

	// Check if the account is allowed or if the transaction amount is below the threshold
	if zfp.allowedAccounts[account] || amount <= zfp.thresholdAmount {
		return true, nil
	}
	return false, nil
}

// SetThresholdAmount sets the threshold amount for zero-fee transactions
func (zfp *ZeroFeePolicy) SetThresholdAmount(amount int64) {
	zfp.Lock()
	defer zfp.Unlock()
	zfp.thresholdAmount = amount
}

// GetThresholdAmount retrieves the threshold amount for zero-fee transactions
func (zfp *ZeroFeePolicy) GetThresholdAmount() int64 {
	zfp.Lock()
	defer zfp.Unlock()
	return zfp.thresholdAmount
}

// ListAllowedAccounts lists all accounts that are allowed to make zero-fee transactions
func (zfp *ZeroFeePolicy) ListAllowedAccounts() []string {
	zfp.Lock()
	defer zfp.Unlock()
	accounts := make([]string, 0, len(zfp.allowedAccounts))
	for account := range zfp.allowedAccounts {
		accounts = append(accounts, account)
	}
	return accounts
}
