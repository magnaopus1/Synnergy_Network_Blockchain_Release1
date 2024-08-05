package smart_contracts

import (
    "errors"
    "math/big"
    "sync"
    "time"
)

// InterestRateManager manages the calculation and application of various interest rates
type InterestRateManager struct {
    mu                      sync.RWMutex
    savingsBaseRate         *big.Float
    commercialBorrowingRate *big.Float
    userBorrowingRate       *big.Float
    rateUpdateInterval      time.Duration
    lastUpdated             time.Time
}

// NewInterestRateManager initializes an InterestRateManager with the given base rates and update interval
func NewInterestRateManager(savingsRate, commercialRate, userRate *big.Float, updateInterval time.Duration) *InterestRateManager {
    return &InterestRateManager{
        savingsBaseRate:         savingsRate,
        commercialBorrowingRate: commercialRate,
        userBorrowingRate:       userRate,
        rateUpdateInterval:      updateInterval,
        lastUpdated:             time.Now(),
    }
}

// UpdateRates updates the interest rates based on market data or central bank policies
// This function should be called periodically or triggered by specific events
func (irm *InterestRateManager) UpdateRates(savingsRate, commercialRate, userRate *big.Float) error {
    irm.mu.Lock()
    defer irm.mu.Unlock()

    if time.Since(irm.lastUpdated) < irm.rateUpdateInterval {
        return errors.New("rate update interval has not elapsed")
    }

    irm.savingsBaseRate = savingsRate
    irm.commercialBorrowingRate = commercialRate
    irm.userBorrowingRate = userRate
    irm.lastUpdated = time.Now()

    return nil
}

// GetSavingsRate returns the current savings interest rate
func (irm *InterestRateManager) GetSavingsRate() *big.Float {
    irm.mu.RLock()
    defer irm.mu.RUnlock()
    return irm.savingsBaseRate
}

// GetCommercialBorrowingRate returns the current borrowing rate for commercial banks
func (irm *InterestRateManager) GetCommercialBorrowingRate() *big.Float {
    irm.mu.RLock()
    defer irm.mu.RUnlock()
    return irm.commercialBorrowingRate
}

// GetUserBorrowingRate returns the current borrowing rate for users
func (irm *InterestRateManager) GetUserBorrowingRate() *big.Float {
    irm.mu.RLock()
    defer irm.mu.RUnlock()
    return irm.userBorrowingRate
}

// ApplyInterest calculates the interest based on the principal and the rate type (savings, commercial, user)
// and returns the total amount after applying interest
func (irm *InterestRateManager) ApplyInterest(principal *big.Float, rateType string) (*big.Float, error) {
    var rate *big.Float
    irm.mu.RLock()
    switch rateType {
    case "savings":
        rate = irm.savingsBaseRate
    case "commercial":
        rate = irm.commercialBorrowingRate
    case "user":
        rate = irm.userBorrowingRate
    default:
        irm.mu.RUnlock()
        return nil, errors.New("invalid rate type")
    }
    irm.mu.RUnlock()

    interest := new(big.Float).Mul(principal, rate)
    total := new(big.Float).Add(principal, interest)
    return total, nil
}

// SetUpdateInterval sets a new rate update interval
func (irm *InterestRateManager) SetUpdateInterval(interval time.Duration) {
    irm.mu.Lock()
    defer irm.mu.Unlock()
    irm.rateUpdateInterval = interval
}

