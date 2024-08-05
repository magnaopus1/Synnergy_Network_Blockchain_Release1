package security

import (
	"errors"
	"sync"
	"time"
)

// AntiFraudMeasures struct to handle all anti-fraud functionalities
type AntiFraudMeasures struct {
	loginAttempts   map[string]int
	blockedAccounts map[string]time.Time
	mutex           sync.Mutex
	maxAttempts     int
	blockDuration   time.Duration
}

// NewAntiFraudMeasures initializes and returns a new AntiFraudMeasures instance
func NewAntiFraudMeasures(maxAttempts int, blockDuration time.Duration) *AntiFraudMeasures {
	return &AntiFraudMeasures{
		loginAttempts:   make(map[string]int),
		blockedAccounts: make(map[string]time.Time),
		maxAttempts:     maxAttempts,
		blockDuration:   blockDuration,
	}
}

// RecordLoginAttempt records a login attempt and checks if the account should be blocked
func (af *AntiFraudMeasures) RecordLoginAttempt(accountID string) error {
	af.mutex.Lock()
	defer af.mutex.Unlock()

	// Check if account is already blocked
	if blockTime, blocked := af.blockedAccounts[accountID]; blocked {
		if time.Since(blockTime) < af.blockDuration {
			return errors.New("account is temporarily blocked due to suspicious activity")
		}
		// Unblock the account after the block duration has passed
		delete(af.blockedAccounts, accountID)
	}

	// Record the login attempt
	af.loginAttempts[accountID]++

	// Block account if max attempts exceeded
	if af.loginAttempts[accountID] > af.maxAttempts {
		af.blockedAccounts[accountID] = time.Now()
		delete(af.loginAttempts, accountID)
		return errors.New("account temporarily blocked due to multiple failed login attempts")
	}

	return nil
}

// ResetLoginAttempts resets the login attempts counter for a given account
func (af *AntiFraudMeasures) ResetLoginAttempts(accountID string) {
	af.mutex.Lock()
	defer af.mutex.Unlock()
	delete(af.loginAttempts, accountID)
}

// IsAccountBlocked checks if an account is currently blocked
func (af *AntiFraudMeasures) IsAccountBlocked(accountID string) bool {
	af.mutex.Lock()
	defer af.mutex.Unlock()

	blockTime, blocked := af.blockedAccounts[accountID]
	if !blocked {
		return false
	}

	if time.Since(blockTime) < af.blockDuration {
		return true
	}

	// Unblock the account after the block duration has passed
	delete(af.blockedAccounts, accountID)
	return false
}

// DetectAnomalousBehavior detects and handles suspicious activities such as rapid transactions
func (af *AntiFraudMeasures) DetectAnomalousBehavior(accountID string, transactionCount int, duration time.Duration) error {
	af.mutex.Lock()
	defer af.mutex.Unlock()

	// Detect if transactions exceed a certain threshold within a given time period
	// This is a simplified example and can be extended with more complex anomaly detection logic
	if transactionCount > 100 { // Example threshold
		af.blockedAccounts[accountID] = time.Now()
		return errors.New("account temporarily blocked due to anomalous transaction activity")
	}

	return nil
}
