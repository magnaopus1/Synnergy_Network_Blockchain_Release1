package liquidity

import (
	"errors"
	"sync"
	"time"
)

// FeeAdjustment manages the adjustment of fees within the liquidity sidechain
type FeeAdjustment struct {
	mu              sync.RWMutex
	fees            map[string]float64
	adjustmentRules map[string]func(float64) float64
}

// NewFeeAdjustment creates a new FeeAdjustment instance
func NewFeeAdjustment() *FeeAdjustment {
	return &FeeAdjustment{
		fees:            make(map[string]float64),
		adjustmentRules: make(map[string]func(float64) float64),
	}
}

// SetFee sets the fee for a specific transaction type
func (fa *FeeAdjustment) SetFee(transactionType string, fee float64) error {
	if fee < 0 {
		return errors.New("fee cannot be negative")
	}

	fa.mu.Lock()
	defer fa.mu.Unlock()

	fa.fees[transactionType] = fee
	return nil
}

// GetFee gets the fee for a specific transaction type
func (fa *FeeAdjustment) GetFee(transactionType string) (float64, error) {
	fa.mu.RLock()
	defer fa.mu.RUnlock()

	fee, exists := fa.fees[transactionType]
	if !exists {
		return 0, errors.New("transaction type not found")
	}

	return fee, nil
}

// SetAdjustmentRule sets the adjustment rule for a specific transaction type
func (fa *FeeAdjustment) SetAdjustmentRule(transactionType string, rule func(float64) float64) error {
	if rule == nil {
		return errors.New("adjustment rule cannot be nil")
	}

	fa.mu.Lock()
	defer fa.mu.Unlock()

	fa.adjustmentRules[transactionType] = rule
	return nil
}

// AdjustFee adjusts the fee for a specific transaction type based on the adjustment rule
func (fa *FeeAdjustment) AdjustFee(transactionType string) error {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	fee, exists := fa.fees[transactionType]
	if !exists {
		return errors.New("transaction type not found")
	}

	rule, exists := fa.adjustmentRules[transactionType]
	if !exists {
		return errors.New("adjustment rule not found for transaction type")
	}

	fa.fees[transactionType] = rule(fee)
	return nil
}

// PeriodicAdjustment periodically adjusts fees based on adjustment rules
func (fa *FeeAdjustment) PeriodicAdjustment(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		fa.mu.Lock()
		for transactionType, rule := range fa.adjustmentRules {
			if fee, exists := fa.fees[transactionType]; exists {
				fa.fees[transactionType] = rule(fee)
			}
		}
		fa.mu.Unlock()
	}
}

// ExampleAdjustmentRule is an example of an adjustment rule
func ExampleAdjustmentRule(fee float64) float64 {
	// Example logic: increase fee by 1%
	return fee * 1.01
}

// ValidateFee ensures that the fee is within acceptable limits
func ValidateFee(fee float64) error {
	if fee < 0 {
		return errors.New("fee cannot be negative")
	}
	if fee > 100 {
		return errors.New("fee cannot exceed 100 units")
	}
	return nil
}

// CalculateFeeWithDiscount calculates the fee with a discount applied
func CalculateFeeWithDiscount(fee, discount float64) (float64, error) {
	if discount < 0 || discount > 1 {
		return 0, errors.New("invalid discount rate")
	}
	return fee * (1 - discount), nil
}
