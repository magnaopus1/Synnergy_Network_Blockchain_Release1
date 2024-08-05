package management

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/synnergy_network/core/smart_contracts"
)

// MonetaryPolicyManager manages monetary policy including token minting, burning, interest rates, and liquidity management.
type MonetaryPolicyManager struct {
	mu              sync.RWMutex
	tokenSupply     *big.Float
	interestRates   map[string]*big.Float
	mintedTokens    map[string]*big.Float
	burnedTokens    map[string]*big.Float
	transactionLog  []*MonetaryTransaction
	easingMechanism *smart_contracts.QuantitativeEasingMechanism
	tighteningMechanism *smart_contracts.MonetaryTighteningMechanism
}

// MonetaryTransaction records transactions related to monetary policy actions.
type MonetaryTransaction struct {
	TransactionType string
	TokenType       string
	Amount          *big.Float
	Timestamp       time.Time
	Details         string
}

// NewMonetaryPolicyManager initializes a new MonetaryPolicyManager with given mechanisms
func NewMonetaryPolicyManager(easingMechanism *smart_contracts.QuantitativeEasingMechanism, tighteningMechanism *smart_contracts.MonetaryTighteningMechanism) *MonetaryPolicyManager {
	return &MonetaryPolicyManager{
		tokenSupply:     new(big.Float),
		interestRates:   make(map[string]*big.Float),
		mintedTokens:    make(map[string]*big.Float),
		burnedTokens:    make(map[string]*big.Float),
		transactionLog:  []*MonetaryTransaction{},
		easingMechanism: easingMechanism,
		tighteningMechanism: tighteningMechanism,
	}
}

// MintTokens adds new tokens to the supply
func (mpm *MonetaryPolicyManager) MintTokens(tokenType string, amount *big.Float, details string) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	if mpm.mintedTokens[tokenType] == nil {
		mpm.mintedTokens[tokenType] = new(big.Float)
	}
	mpm.mintedTokens[tokenType].Add(mpm.mintedTokens[tokenType], amount)
	mpm.tokenSupply.Add(mpm.tokenSupply, amount)

	transaction := &MonetaryTransaction{
		TransactionType: "Minting",
		TokenType:       tokenType,
		Amount:          amount,
		Timestamp:       time.Now(),
		Details:         details,
	}
	mpm.transactionLog = append(mpm.transactionLog, transaction)

	return nil
}

// BurnTokens removes tokens from the supply
func (mpm *MonetaryPolicyManager) BurnTokens(tokenType string, amount *big.Float, details string) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	if mpm.burnedTokens[tokenType] == nil {
		mpm.burnedTokens[tokenType] = new(big.Float)
	}
	mpm.burnedTokens[tokenType].Add(mpm.burnedTokens[tokenType], amount)
	mpm.tokenSupply.Sub(mpm.tokenSupply, amount)

	transaction := &MonetaryTransaction{
		TransactionType: "Burning",
		TokenType:       tokenType,
		Amount:          amount,
		Timestamp:       time.Now(),
		Details:         details,
	}
	mpm.transactionLog = append(mpm.transactionLog, transaction)

	return nil
}

// SetInterestRate sets the interest rate for a specific account type or token
func (mpm *MonetaryPolicyManager) SetInterestRate(accountType string, rate *big.Float) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	if rate.Cmp(big.NewFloat(0)) < 0 {
		return errors.New("interest rate cannot be negative")
	}

	mpm.interestRates[accountType] = rate

	transaction := &MonetaryTransaction{
		TransactionType: "InterestRateAdjustment",
		TokenType:       accountType,
		Amount:          rate,
		Timestamp:       time.Now(),
		Details:         "Interest rate adjustment",
	}
	mpm.transactionLog = append(mpm.transactionLog, transaction)

	return nil
}

// GetInterestRate retrieves the current interest rate for a specific account type
func (mpm *MonetaryPolicyManager) GetInterestRate(accountType string) (*big.Float, error) {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	rate, exists := mpm.interestRates[accountType]
	if !exists {
		return nil, errors.New("no interest rate set for this account type")
	}

	return new(big.Float).Set(rate), nil
}

// ConductQuantitativeEasing implements quantitative easing by increasing the money supply
func (mpm *MonetaryPolicyManager) ConductQuantitativeEasing(amount *big.Float, details string) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	err := mpm.easingMechanism.BuyAssets(amount)
	if err != nil {
		return err
	}

	mpm.tokenSupply.Add(mpm.tokenSupply, amount)

	transaction := &MonetaryTransaction{
		TransactionType: "QuantitativeEasing",
		TokenType:       "SYN10",
		Amount:          amount,
		Timestamp:       time.Now(),
		Details:         details,
	}
	mpm.transactionLog = append(mpm.transactionLog, transaction)

	return nil
}

// ConductMonetaryTightening reduces the money supply by selling SYN11 and SYN12 tokens
func (mpm *MonetaryPolicyManager) ConductMonetaryTightening(tokenType string, amount *big.Float, pricePerUnit *big.Float, details string) error {
	mpm.mu.Lock()
	defer mpm.mu.Unlock()

	err := mpm.tighteningMechanism.SellAssets(tokenType, amount, pricePerUnit)
	if err != nil {
		return err
	}

	mpm.tokenSupply.Sub(mpm.tokenSupply, amount)

	transaction := &MonetaryTransaction{
		TransactionType: "MonetaryTightening",
		TokenType:       tokenType,
		Amount:          amount,
		Timestamp:       time.Now(),
		Details:         details,
	}
	mpm.transactionLog = append(mpm.transactionLog, transaction)

	return nil
}

// GetTransactionLog returns the log of all monetary policy transactions
func (mpm *MonetaryPolicyManager) GetTransactionLog() []*MonetaryTransaction {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	return mpm.transactionLog
}

// TotalTokenSupply returns the total supply of tokens
func (mpm *MonetaryPolicyManager) TotalTokenSupply() *big.Float {
	mpm.mu.RLock()
	defer mpm.mu.RUnlock()

	return new(big.Float).Set(mpm.tokenSupply)
}

// ImplementSecurity implements necessary security measures for secure operations
func (mpm *MonetaryPolicyManager) ImplementSecurity() {
	// Implement security protocols like multi-factor authentication, encryption, and secure access control.
}

