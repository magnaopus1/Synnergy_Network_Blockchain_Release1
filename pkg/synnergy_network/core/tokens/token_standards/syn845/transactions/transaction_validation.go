package transactions

import (
    "errors"
    "sync"
    "time"
)

// TransactionValidator handles the validation of transactions
type TransactionValidator struct {
    allowedTypes map[TransactionType]bool
    mu           sync.RWMutex
}

// NewTransactionValidator creates a new TransactionValidator instance
func NewTransactionValidator() *TransactionValidator {
    return &TransactionValidator{
        allowedTypes: map[TransactionType]bool{
            Issuance:    true,
            Repayment:   true,
            Refinancing: true,
            Transfer:    true,
        },
    }
}

// ValidateTransaction validates a transaction
func (tv *TransactionValidator) ValidateTransaction(tx *Transaction) error {
    tv.mu.RLock()
    defer tv.mu.RUnlock()

    if tx == nil {
        return errors.New("transaction cannot be nil")
    }

    if !tv.allowedTypes[tx.Type] {
        return errors.New("transaction type is not allowed")
    }

    if tx.Amount <= 0 {
        return errors.New("transaction amount must be greater than zero")
    }

    if tx.Date.After(time.Now()) {
        return errors.New("transaction date cannot be in the future")
    }

    if tx.From == "" || tx.To == "" {
        return errors.New("transaction must have valid 'From' and 'To' fields")
    }

    // Add additional validation rules based on business logic
    switch tx.Type {
    case Issuance:
        return tv.validateIssuance(tx)
    case Repayment:
        return tv.validateRepayment(tx)
    case Refinancing:
        return tv.validateRefinancing(tx)
    case Transfer:
        return tv.validateTransfer(tx)
    default:
        return errors.New("unknown transaction type")
    }
}

func (tv *TransactionValidator) validateIssuance(tx *Transaction) error {
    if tx.InterestRate <= 0 {
        return errors.New("issuance transaction must have a positive interest rate")
    }
    return nil
}

func (tv *TransactionValidator) validateRepayment(tx *Transaction) error {
    // Add specific validation for repayment transactions
    return nil
}

func (tv *TransactionValidator) validateRefinancing(tx *Transaction) error {
    if tx.InterestRate <= 0 {
        return errors.New("refinancing transaction must have a positive interest rate")
    }
    return nil
}

func (tv *TransactionValidator) validateTransfer(tx *Transaction) error {
    // Add specific validation for transfer transactions
    return nil
}
