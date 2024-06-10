package syn845

import (
	"errors"
	"log"
	"sync"
	"time"
)

type DebtInstrument struct {
	ID               string
	Owner            string
	OriginalAmount   float64
	RemainingAmount  float64
	InterestRate     float64
	RepaymentPeriod  time.Duration
	NextPaymentDate  time.Time
	Payments         []Payment
	Status           string
	PenaltyRate      float64
	mutex            sync.Mutex
}

type Payment struct {
	Amount      float64
	Date        time.Time
	Interest    float64
	Principal   float64
	Remaining   float64
}

func NewDebtInstrument(id, owner string, amount, interestRate, penaltyRate float64, repaymentPeriod time.Duration) *DebtInstrument {
	return &DebtInstrument{
		ID:              id,
		Owner:           owner,
		OriginalAmount:  amount,
		RemainingAmount: amount,
		InterestRate:    interestRate / 100, // Convert to decimal
		RepaymentPeriod: repaymentPeriod,
		NextPaymentDate: time.Now().Add(repaymentPeriod),
		Status:          "Active",
		PenaltyRate:     penaltyRate,
	}
}

func (di *DebtInstrument) MakePayment(amount float64) error {
	di.mutex.Lock()
	defer di.mutex.Unlock()

	if di.Status != "Active" {
		return errors.New("payment attempt on non-active loan")
	}

	currentInterest := di.calculateInterest()
	principalPayment := amount - currentInterest
	if principalPayment < 0 {
		return errors.New("payment does not cover the accrued interest")
	}

	di.RemainingAmount -= principalPayment
	di.Payments = append(di.Payments, Payment{
		Amount:    amount,
		Date:      time.Now(),
		Interest:  currentInterest,
		Principal: principalPayment,
		Remaining: di.RemainingAmount,
	})

	if di.RemainingAmount <= 0 {
		di.Status = "Paid Off"
		di.RemainingAmount = 0
	}

	di.NextPaymentDate = di.NextPaymentDate.Add(di.RepaymentPeriod)
	log.Printf("Payment made: %v, Interest: %v, Principal: %v, Remaining: %v", amount, currentInterest, principalPayment, di.RemainingAmount)
	return nil
}

func (di *DebtInstrument) calculateInterest() float64 {
	// Interest calculated for the period since last payment
	daysSinceLastPayment := time.Now().Sub(di.NextPaymentDate.Add(-di.RepaymentPeriod)).Hours() / 24
	interest := di.RemainingAmount * (di.InterestRate / 365 * daysSinceLastPayment)
	return interest
}

func (di *DebtInstrument) GetDetails() map[string]interface{} {
	di.mutex.Lock()
	defer di.mutex.Unlock()

	details := map[string]interface{}{
		"ID":              di.ID,
		"Owner":           di.Owner,
		"OriginalAmount":  di.OriginalAmount,
		"RemainingAmount": di.RemainingAmount,
		"InterestRate":    di.InterestRate * 100,
		"NextPaymentDate": di.NextPaymentDate,
		"Status":          di.Status,
		"Payments":        di.Payments,
	}
	log.Printf("Loan details retrieved: %+v", details)
	return details
}
