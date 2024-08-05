package transactions

import (
	"errors"
	"sync"
	"time"
)

// DebtInstrument represents a debt instrument
type DebtInstrument struct {
	ID                   string
	Owner                string
	Principal            float64
	InterestRate         float64
	OriginalTerm         int // in months
	RemainingTerm        int // in months
	NextPaymentDate      time.Time
	Status               string
	PaymentHistory       []PaymentRecord
	RepaymentSchedule    []PaymentRecord
	RefinancingHistory   []RefinancingRecord
}

// PaymentRecord represents a record of a payment
type PaymentRecord struct {
	Date      time.Time
	Amount    float64
	Principal float64
	Interest  float64
	Balance   float64
}

// RefinancingRecord represents a record of refinancing
type RefinancingRecord struct {
	RefinancedDate time.Time
	NewPrincipal   float64
	NewTerm        int
	NewRate        float64
}

// RepaymentHandler manages the repayment schedules of debt instruments
type RepaymentHandler struct {
	debts map[string]*DebtInstrument
	mu    sync.RWMutex
}

// NewRepaymentHandler creates a new RepaymentHandler instance
func NewRepaymentHandler() *RepaymentHandler {
	return &RepaymentHandler{
		debts: make(map[string]*DebtInstrument),
	}
}

// AddDebtInstrument adds a new debt instrument to the manager
func (rh *RepaymentHandler) AddDebtInstrument(id, owner string, principal, interestRate float64, originalTerm int, nextPaymentDate time.Time) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	rh.debts[id] = &DebtInstrument{
		ID:              id,
		Owner:           owner,
		Principal:       principal,
		InterestRate:    interestRate,
		OriginalTerm:    originalTerm,
		RemainingTerm:   originalTerm,
		NextPaymentDate: nextPaymentDate,
		Status:          "active",
	}
}

// GenerateRepaymentSchedule generates a repayment schedule for a debt instrument
func (rh *RepaymentHandler) GenerateRepaymentSchedule(instrumentID string) ([]PaymentRecord, error) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	if debt.Status != "active" {
		return nil, errors.New("only active debt instruments can have schedules generated")
	}

	monthlyRate := debt.InterestRate / 12 / 100
	monthlyPayment := (debt.Principal * monthlyRate) / (1 - (1 / (1 + monthlyRate)))

	schedule := make([]PaymentRecord, debt.RemainingTerm)

	for i := 0; i < debt.RemainingTerm; i++ {
		interest := debt.Principal * monthlyRate
		principal := monthlyPayment - interest
		debt.Principal -= principal
		schedule[i] = PaymentRecord{
			Date:      debt.NextPaymentDate.AddDate(0, i, 0),
			Amount:    monthlyPayment,
			Principal: principal,
			Interest:  interest,
			Balance:   debt.Principal,
		}
	}

	debt.RepaymentSchedule = schedule

	return schedule, nil
}

// GetRepaymentSchedule returns the repayment schedule of a debt instrument by ID
func (rh *RepaymentHandler) GetRepaymentSchedule(instrumentID string) ([]PaymentRecord, error) {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	return debt.RepaymentSchedule, nil
}

// RecordPayment records a payment made towards a debt instrument
func (rh *RepaymentHandler) RecordPayment(instrumentID string, paymentAmount float64) error {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	if debt.Status != "active" {
		return errors.New("only active debt instruments can have payments recorded")
	}

	if debt.NextPaymentDate.After(time.Now()) {
		return errors.New("payment cannot be recorded before the next payment date")
	}

	monthlyRate := debt.InterestRate / 12 / 100
	interest := debt.Principal * monthlyRate
	principal := paymentAmount - interest
	debt.Principal -= principal

	debt.PaymentHistory = append(debt.PaymentHistory, PaymentRecord{
		Date:      time.Now(),
		Amount:    paymentAmount,
		Principal: principal,
		Interest:  interest,
		Balance:   debt.Principal,
	})

	// Update the repayment schedule
	for i, record := range debt.RepaymentSchedule {
		if record.Date.After(time.Now()) {
			debt.RepaymentSchedule[i].Balance = debt.Principal
			break
		}
	}

	return nil
}

// GetPaymentHistory returns the payment history of a debt instrument by ID
func (rh *RepaymentHandler) GetPaymentHistory(instrumentID string) ([]PaymentRecord, error) {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	return debt.PaymentHistory, nil
}

// EarlyRepaymentPenalty calculates and applies an early repayment penalty for paying off a debt instrument early
func (rh *RepaymentHandler) EarlyRepaymentPenalty(instrumentID string, earlyPaymentAmount float64) (float64, error) {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return 0, errors.New("debt instrument not found")
	}

	if debt.Status != "active" {
		return 0, errors.New("only active debt instruments can have penalties applied")
	}

	penaltyRate := 0.02 // Example penalty rate of 2%
	penalty := earlyPaymentAmount * penaltyRate

	debt.Principal -= earlyPaymentAmount - penalty
	debt.PaymentHistory = append(debt.PaymentHistory, PaymentRecord{
		Date:      time.Now(),
		Amount:    earlyPaymentAmount,
		Principal: earlyPaymentAmount - penalty,
		Interest:  0,
		Balance:   debt.Principal,
	})

	return penalty, nil
}

