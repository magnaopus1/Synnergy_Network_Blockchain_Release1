package loanpool

import (
	"sync"
	"time"

	"github.com/pkg/errors"
)

// LoanPool represents the pool of funds available for loans.
type LoanPool struct {
	sync.RWMutex
	FundsAvailable float64
	LoansIssued    map[string]float64
}

// NewLoanPool initializes a new LoanPool with specified starting funds.
func NewLoanPool(initialFunds float64) *LoanPool {
	return &LoanPool{
		FundsAvailable: initialFunds,
		LoansIssued:    make(map[string]float64),
	}
}

// AddFunds adds funds to the loan pool, typically from gas fees.
func (lp *LoanPool) AddFunds(amount float64) error {
	lp.Lock()
	defer lp.Unlock()

	if amount <= 0 {
		return errors.New("invalid amount: must be positive")
	}

	lp.FundsAvailable += amount
	return nil
}

// IssueLoan attempts to issue a loan to a project if sufficient funds are available.
func (lp *LoanPool) IssueLoan(projectID string, amount float64) error {
	lp.Lock()
	defer lp.Unlock()

	if amount <= 0 {
		return errors.New("invalid loan amount: must be positive")
	}
	if amount > lp.FundsAvailable {
		return errors.New("insufficient funds in the loan pool")
	}

	lp.FundsAvailable -= amount
	lp.LoansIssued[projectID] += amount
	return nil
}

// RepayLoan processes the repayment of a loan, returning funds to the pool.
func (lp *LoanPool) RepayLoan(projectID string, amount float64) error {
	lp.Lock()
	defer lp.Unlock()

	if loan, exists := lp.LoansIssued[projectID]; exists && amount > 0 {
		if amount > loan {
			return errors.New("repayment amount exceeds the loan value")
		}
		lp.FundsAvailable += amount
		lp.LoansIssued[projectID] -= amount
		if lp.LoansIssued[projectID] == 0 {
			delete(lp.LoansIssued, projectID)
		}
		return nil
	}
	return errors.New("loan does not exist or invalid repayment amount")
}

// GetLoanBalance retrieves the balance of a loan for a given project.
func (lp *LoanPool) GetLoanBalance(projectID string) (float64, error) {
	lp.RLock()
	defer lp.RUnlock()

	if loan, exists := lp.LoansIssued[projectID]; exists {
		return loan, nil
	}
	return 0, errors.New("loan not found")
}

// TotalLoans calculates the total amount of active loans.
func (lp *LoanPool) TotalLoans() float64 {
	lp.RLock()
	defer lp.RUnlock()

	total := 0.0
	for _, amount := range lp.LoansIssued {
		total += amount
	}
	return total
}
