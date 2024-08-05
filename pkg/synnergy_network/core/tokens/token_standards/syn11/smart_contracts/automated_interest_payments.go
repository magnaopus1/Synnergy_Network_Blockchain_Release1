package smart_contracts

import (
	"errors"
	"fmt"
	"time"
)

// InterestPaymentManager manages the automated distribution of interest payments.
type InterestPaymentManager struct {
	contracts map[string]*InterestContract
}

// InterestContract represents a smart contract for managing interest payments.
type InterestContract struct {
	GiltID            string
	Principal         float64
	CouponRate        float64
	LastPaymentDate   time.Time
	PaymentFrequency  time.Duration
	NextPaymentDate   time.Time
	AccruedInterest   float64
}

// NewInterestPaymentManager initializes a new InterestPaymentManager.
func NewInterestPaymentManager() *InterestPaymentManager {
	return &InterestPaymentManager{
		contracts: make(map[string]*InterestContract),
	}
}

// RegisterContract registers a new interest payment contract for a gilt.
func (ipm *InterestPaymentManager) RegisterContract(giltID string, principal, couponRate float64, paymentFrequency time.Duration) error {
	if principal <= 0 || couponRate < 0 {
		return errors.New("invalid principal or coupon rate")
	}
	ipm.contracts[giltID] = &InterestContract{
		GiltID:           giltID,
		Principal:        principal,
		CouponRate:       couponRate,
		LastPaymentDate:  time.Now(),
		PaymentFrequency: paymentFrequency,
		NextPaymentDate:  time.Now().Add(paymentFrequency),
	}
	return nil
}

// CalculateAccruedInterest calculates the accrued interest for a specific contract.
func (ipm *InterestPaymentManager) CalculateAccruedInterest(giltID string) (float64, error) {
	contract, exists := ipm.contracts[giltID]
	if !exists {
		return 0, fmt.Errorf("contract for gilt %s not found", giltID)
	}

	timeElapsed := time.Since(contract.LastPaymentDate)
	annualInterest := contract.Principal * (contract.CouponRate / 100)
	interestAccrued := annualInterest * (float64(timeElapsed.Hours()) / (365 * 24))

	contract.AccruedInterest += interestAccrued
	return interestAccrued, nil
}

// DistributeInterestPayments distributes the accrued interest to the gilt holders.
func (ipm *InterestPaymentManager) DistributeInterestPayments(giltID string) error {
	contract, exists := ipm.contracts[giltID]
	if !exists {
		return fmt.Errorf("contract for gilt %s not found", giltID)
	}

	if time.Now().Before(contract.NextPaymentDate) {
		return fmt.Errorf("interest payment not due yet for gilt %s", giltID)
	}

	interestToPay := contract.AccruedInterest
	contract.AccruedInterest = 0
	contract.LastPaymentDate = time.Now()
	contract.NextPaymentDate = contract.LastPaymentDate.Add(contract.PaymentFrequency)

	// This is where the actual transfer of interest would occur
	// Placeholder: fmt.Printf("Paying %f interest for gilt %s\n", interestToPay, giltID)

	logInterestPayment(giltID, interestToPay)
	return nil
}

// UpdateCouponRate updates the coupon rate for a specific gilt.
func (ipm *InterestPaymentManager) UpdateCouponRate(giltID string, newCouponRate float64) error {
	contract, exists := ipm.contracts[giltID]
	if !exists {
		return fmt.Errorf("contract for gilt %s not found", giltID)
	}

	if newCouponRate < 0 {
		return errors.New("invalid coupon rate")
	}

	contract.CouponRate = newCouponRate
	return nil
}

// logInterestPayment logs the details of an interest payment.
func logInterestPayment(giltID string, amount float64) {
	// This function can be extended to log to a more sophisticated logging system
	fmt.Printf("Interest payment of %f made for gilt %s at %s\n", amount, giltID, time.Now().Format(time.RFC3339))
}
