package smart_contracts

import (
	"errors"
	"fmt"
	"time"
)

// CouponPaymentManager manages the automated distribution of coupon payments.
type CouponPaymentManager struct {
	contracts map[string]*CouponContract
}

// CouponContract represents a smart contract for managing coupon payments.
type CouponContract struct {
	GiltID           string
	Principal        float64
	CouponRate       float64
	LastPaymentDate  time.Time
	PaymentFrequency time.Duration
	NextPaymentDate  time.Time
	AccruedCoupon    float64
}

// NewCouponPaymentManager initializes a new CouponPaymentManager.
func NewCouponPaymentManager() *CouponPaymentManager {
	return &CouponPaymentManager{
		contracts: make(map[string]*CouponContract),
	}
}

// RegisterContract registers a new coupon payment contract for a gilt.
func (cpm *CouponPaymentManager) RegisterContract(giltID string, principal, couponRate float64, paymentFrequency time.Duration) error {
	if principal <= 0 || couponRate < 0 {
		return errors.New("invalid principal or coupon rate")
	}
	cpm.contracts[giltID] = &CouponContract{
		GiltID:           giltID,
		Principal:        principal,
		CouponRate:       couponRate,
		LastPaymentDate:  time.Now(),
		PaymentFrequency: paymentFrequency,
		NextPaymentDate:  time.Now().Add(paymentFrequency),
	}
	return nil
}

// CalculateAccruedCoupon calculates the accrued coupon for a specific contract.
func (cpm *CouponPaymentManager) CalculateAccruedCoupon(giltID string) (float64, error) {
	contract, exists := cpm.contracts[giltID]
	if !exists {
		return 0, fmt.Errorf("contract for gilt %s not found", giltID)
	}

	timeElapsed := time.Since(contract.LastPaymentDate)
	annualCoupon := contract.Principal * (contract.CouponRate / 100)
	couponAccrued := annualCoupon * (float64(timeElapsed.Hours()) / (365 * 24))

	contract.AccruedCoupon += couponAccrued
	return couponAccrued, nil
}

// DistributeCouponPayments distributes the accrued coupon to the gilt holders.
func (cpm *CouponPaymentManager) DistributeCouponPayments(giltID string) error {
	contract, exists := cpm.contracts[giltID]
	if !exists {
		return fmt.Errorf("contract for gilt %s not found", giltID)
	}

	if time.Now().Before(contract.NextPaymentDate) {
		return fmt.Errorf("coupon payment not due yet for gilt %s", giltID)
	}

	couponToPay := contract.AccruedCoupon
	contract.AccruedCoupon = 0
	contract.LastPaymentDate = time.Now()
	contract.NextPaymentDate = contract.LastPaymentDate.Add(contract.PaymentFrequency)

	// Actual transfer of coupon payments should occur here
	// Placeholder: fmt.Printf("Paying %f coupon for gilt %s\n", couponToPay, giltID)

	logCouponPayment(giltID, couponToPay)
	return nil
}

// UpdateCouponRate updates the coupon rate for a specific gilt.
func (cpm *CouponPaymentManager) UpdateCouponRate(giltID string, newCouponRate float64) error {
	contract, exists := cpm.contracts[giltID]
	if !exists {
		return fmt.Errorf("contract for gilt %s not found", giltID)
	}

	if newCouponRate < 0 {
		return errors.New("invalid coupon rate")
	}

	contract.CouponRate = newCouponRate
	return nil
}

// logCouponPayment logs the details of a coupon payment.
func logCouponPayment(giltID string, amount float64) {
	// This function can be extended to log to a more sophisticated logging system
	fmt.Printf("Coupon payment of %f made for gilt %s at %s\n", amount, giltID, time.Now().Format(time.RFC3339))
}
