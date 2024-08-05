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
    LastPaymentDate      time.Time
    NextPaymentDate      time.Time
    LatePaymentPenalty   float64
    EarlyRepaymentPenalty float64
    Status               string
}

// PenaltyHandler manages the calculation and application of penalties
type PenaltyHandler struct {
    debts map[string]*DebtInstrument
    mu    sync.RWMutex
}

// NewPenaltyHandler creates a new PenaltyHandler instance
func NewPenaltyHandler() *PenaltyHandler {
    return &PenaltyHandler{
        debts: make(map[string]*DebtInstrument),
    }
}

// AddDebtInstrument adds a new debt instrument to the manager
func (ph *PenaltyHandler) AddDebtInstrument(id, owner string, principal, interestRate, latePaymentPenalty, earlyRepaymentPenalty float64, nextPaymentDate time.Time) {
    ph.mu.Lock()
    defer ph.mu.Unlock()

    ph.debts[id] = &DebtInstrument{
        ID:                   id,
        Owner:                owner,
        Principal:            principal,
        InterestRate:         interestRate,
        LatePaymentPenalty:   latePaymentPenalty,
        EarlyRepaymentPenalty: earlyRepaymentPenalty,
        NextPaymentDate:      nextPaymentDate,
        Status:               "active",
    }
}

// ApplyLatePaymentPenalty applies a late payment penalty to a debt instrument
func (ph *PenaltyHandler) ApplyLatePaymentPenalty(instrumentID string) error {
    ph.mu.Lock()
    defer ph.mu.Unlock()

    debt, exists := ph.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    if debt.Status != "active" {
        return errors.New("penalty application is only allowed for active debt instruments")
    }

    if time.Now().After(debt.NextPaymentDate) {
        debt.Principal += debt.LatePaymentPenalty
        debt.LastPaymentDate = time.Now()
        debt.NextPaymentDate = debt.NextPaymentDate.AddDate(0, 1, 0) // assuming monthly payments
        return nil
    }

    return errors.New("no late payment penalty to apply")
}

// ApplyEarlyRepaymentPenalty applies an early repayment penalty to a debt instrument
func (ph *PenaltyHandler) ApplyEarlyRepaymentPenalty(instrumentID string, repaymentAmount float64) error {
    ph.mu.Lock()
    defer ph.mu.Unlock()

    debt, exists := ph.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    if debt.Status != "active" {
        return errors.New("penalty application is only allowed for active debt instruments")
    }

    if repaymentAmount >= debt.Principal {
        penalty := repaymentAmount * debt.EarlyRepaymentPenalty / 100
        debt.Principal = 0
        debt.Status = "repaid"
        debt.Principal += penalty
        return nil
    }

    return errors.New("repayment amount is less than the principal")
}

// GetDebtInstrument returns details of a debt instrument by ID
func (ph *PenaltyHandler) GetDebtInstrument(id string) (*DebtInstrument, error) {
    ph.mu.RLock()
    defer ph.mu.RUnlock()

    debt, exists := ph.debts[id]
    if !exists {
        return nil, errors.New("debt instrument not found")
    }

    return debt, nil
}

// CalculatePenalty calculates the penalty for a given debt instrument based on the type
func (ph *PenaltyHandler) CalculatePenalty(instrumentID string, penaltyType string) (float64, error) {
    ph.mu.RLock()
    defer ph.mu.RUnlock()

    debt, exists := ph.debts[instrumentID]
    if !exists {
        return 0, errors.New("debt instrument not found")
    }

    if debt.Status != "active" {
        return 0, errors.New("penalty calculation is only allowed for active debt instruments")
    }

    switch penaltyType {
    case "late":
        if time.Now().After(debt.NextPaymentDate) {
            return debt.LatePaymentPenalty, nil
        }
    case "early":
        return debt.Principal * debt.EarlyRepaymentPenalty / 100, nil
    default:
        return 0, errors.New("invalid penalty type")
    }

    return 0, nil
}

// RecordPenalty records the application of a penalty
func (ph *PenaltyHandler) RecordPenalty(instrumentID string, penaltyAmount float64, penaltyType string) error {
    ph.mu.Lock()
    defer ph.mu.Unlock()

    debt, exists := ph.debts[instrumentID]
    if !exists {
        return errors.New("debt instrument not found")
    }

    switch penaltyType {
    case "late":
        debt.Principal += penaltyAmount
    case "early":
        debt.Principal += penaltyAmount
    default:
        return errors.New("invalid penalty type")
    }

    debt.LastPaymentDate = time.Now()
    return nil
}
