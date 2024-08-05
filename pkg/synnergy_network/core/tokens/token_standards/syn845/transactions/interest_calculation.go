package transactions

import (
    "errors"
    "math"
    "sync"
    "time"
)

// InterestType defines the type of interest - fixed or variable
type InterestType int

const (
    Fixed InterestType = iota
    Variable
)

// InterestRate defines the structure for interest rate details
type InterestRate struct {
    Type          InterestType
    FixedRate     float64 // Used if the interest rate is fixed
    VariableRate  float64 // Used if the interest rate is variable
    AdjustmentFunc func(float64) float64 // Function to adjust the variable rate
}

// DebtInstrument represents a debt instrument
type DebtInstrument struct {
    ID             string
    Principal      float64
    InterestRate   InterestRate
    Compounded     bool
    LastInterestAccrual time.Time
    AccruedInterest    float64
}

// DebtManager manages debt instruments and their interest calculations
type DebtManager struct {
    debts map[string]*DebtInstrument
    mu    sync.RWMutex
}

// NewDebtManager creates a new DebtManager instance
func NewDebtManager() *DebtManager {
    return &DebtManager{
        debts: make(map[string]*DebtInstrument),
    }
}

// AddDebtInstrument adds a new debt instrument to the manager
func (dm *DebtManager) AddDebtInstrument(id string, principal float64, rate InterestRate, compounded bool) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    dm.debts[id] = &DebtInstrument{
        ID:             id,
        Principal:      principal,
        InterestRate:   rate,
        Compounded:     compounded,
        LastInterestAccrual: time.Now(),
        AccruedInterest: 0,
    }
}

// CalculateInterest calculates the interest for a given debt instrument
func (dm *DebtManager) CalculateInterest(id string) (float64, error) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    debt, exists := dm.debts[id]
    if !exists {
        return 0, errors.New("debt instrument not found")
    }

    now := time.Now()
    duration := now.Sub(debt.LastInterestAccrual).Hours() / 24 / 365 // Convert duration to years
    interest := 0.0

    switch debt.InterestRate.Type {
    case Fixed:
        if debt.Compounded {
            interest = debt.Principal * math.Pow(1+debt.InterestRate.FixedRate, duration) - debt.Principal
        } else {
            interest = debt.Principal * debt.InterestRate.FixedRate * duration
        }
    case Variable:
        adjustedRate := debt.InterestRate.VariableRate
        if debt.InterestRate.AdjustmentFunc != nil {
            adjustedRate = debt.InterestRate.AdjustmentFunc(adjustedRate)
        }
        if debt.Compounded {
            interest = debt.Principal * math.Pow(1+adjustedRate, duration) - debt.Principal
        } else {
            interest = debt.Principal * adjustedRate * duration
        }
    }

    debt.AccruedInterest += interest
    debt.LastInterestAccrual = now

    return interest, nil
}

// AdjustInterestRate adjusts the interest rate of a debt instrument based on a predefined function
func (dm *DebtManager) AdjustInterestRate(id string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    debt, exists := dm.debts[id]
    if !exists {
        return errors.New("debt instrument not found")
    }

    if debt.InterestRate.Type == Variable && debt.InterestRate.AdjustmentFunc != nil {
        debt.InterestRate.VariableRate = debt.InterestRate.AdjustmentFunc(debt.InterestRate.VariableRate)
    }

    return nil
}

// GetAccruedInterest returns the accrued interest for a given debt instrument
func (dm *DebtManager) GetAccruedInterest(id string) (float64, error) {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    debt, exists := dm.debts[id]
    if !exists {
        return 0, errors.New("debt instrument not found")
    }

    return debt.AccruedInterest, nil
}

// ResetAccruedInterest resets the accrued interest for a given debt instrument
func (dm *DebtManager) ResetAccruedInterest(id string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    debt, exists := dm.debts[id]
    if !exists {
        return errors.New("debt instrument not found")
    }

    debt.AccruedInterest = 0
    return nil
}

// CalculateTotalInterest calculates the total interest for a given debt instrument over its entire period
func (dm *DebtManager) CalculateTotalInterest(id string, durationInYears float64) (float64, error) {
    dm.mu.RLock()
    defer dm.mu.RUnlock()

    debt, exists := dm.debts[id]
    if !exists {
        return 0, errors.New("debt instrument not found")
    }

    interest := 0.0
    switch debt.InterestRate.Type {
    case Fixed:
        if debt.Compounded {
            interest = debt.Principal * math.Pow(1+debt.InterestRate.FixedRate, durationInYears) - debt.Principal
        } else {
            interest = debt.Principal * debt.InterestRate.FixedRate * durationInYears
        }
    case Variable:
        adjustedRate := debt.InterestRate.VariableRate
        if debt.InterestRate.AdjustmentFunc != nil {
            adjustedRate = debt.InterestRate.AdjustmentFunc(adjustedRate)
        }
        if debt.Compounded {
            interest = debt.Principal * math.Pow(1+adjustedRate, durationInYears) - debt.Principal
        } else {
            interest = debt.Principal * adjustedRate * durationInYears
        }
    }

    return interest, nil
}
