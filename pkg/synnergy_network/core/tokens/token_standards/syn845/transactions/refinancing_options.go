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

// RefinancingHandler manages the refinancing of debt instruments
type RefinancingHandler struct {
	debts map[string]*DebtInstrument
	mu    sync.RWMutex
}

// NewRefinancingHandler creates a new RefinancingHandler instance
func NewRefinancingHandler() *RefinancingHandler {
	return &RefinancingHandler{
		debts: make(map[string]*DebtInstrument),
	}
}

// AddDebtInstrument adds a new debt instrument to the manager
func (rh *RefinancingHandler) AddDebtInstrument(id, owner string, principal, interestRate float64, originalTerm int, nextPaymentDate time.Time) {
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

// RefinanceDebtInstrument refinances an existing debt instrument
func (rh *RefinancingHandler) RefinanceDebtInstrument(instrumentID string, newPrincipal, newRate float64, newTerm int) error {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	if debt.Status != "active" {
		return errors.New("only active debt instruments can be refinanced")
	}

	// Record the refinancing
	debt.RefinancingHistory = append(debt.RefinancingHistory, RefinancingRecord{
		RefinancedDate: time.Now(),
		NewPrincipal:   newPrincipal,
		NewTerm:        newTerm,
		NewRate:        newRate,
	})

	// Update debt instrument details
	debt.Principal = newPrincipal
	debt.InterestRate = newRate
	debt.RemainingTerm = newTerm

	return nil
}

// GetDebtInstrument returns details of a debt instrument by ID
func (rh *RefinancingHandler) GetDebtInstrument(id string) (*DebtInstrument, error) {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	debt, exists := rh.debts[id]
	if !exists {
		return nil, errors.New("debt instrument not found")
	}

	return debt, nil
}

// CalculateNewPayment calculates the new monthly payment for a refinanced debt instrument
func (rh *RefinancingHandler) CalculateNewPayment(instrumentID string) (float64, error) {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return 0, errors.New("debt instrument not found")
	}

	if debt.Status != "active" {
		return 0, errors.New("only active debt instruments can have payments calculated")
	}

	monthlyRate := debt.InterestRate / 12 / 100
	monthlyPayment := (debt.Principal * monthlyRate) / (1 - (1 / (1 + monthlyRate)))

	return monthlyPayment, nil
}

// RecordRefinancing records the application of refinancing
func (rh *RefinancingHandler) RecordRefinancing(instrumentID string, newPrincipal, newRate float64, newTerm int) error {
	rh.mu.Lock()
	defer rh.mu.Unlock()

	debt, exists := rh.debts[instrumentID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	debt.Principal = newPrincipal
	debt.InterestRate = newRate
	debt.RemainingTerm = newTerm

	return nil
}

// GenerateRefinancingSchedule generates a repayment schedule for a refinanced debt instrument
func (rh *RefinancingHandler) GenerateRefinancingSchedule(instrumentID string) ([]PaymentRecord, error) {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

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

	return schedule, nil
}
