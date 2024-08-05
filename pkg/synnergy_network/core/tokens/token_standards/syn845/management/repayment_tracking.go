package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn845"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// RepaymentStatus represents the status of a repayment
type RepaymentStatus string

const (
	RepaymentPending   RepaymentStatus = "pending"
	RepaymentCompleted RepaymentStatus = "completed"
	RepaymentLate      RepaymentStatus = "late"
)

// RepaymentEntry represents an entry in the repayment schedule
type RepaymentEntry struct {
	RepaymentID  string          `json:"repayment_id"`
	DebtID       string          `json:"debt_id"`
	Amount       float64         `json:"amount"`
	DueDate      time.Time       `json:"due_date"`
	Status       RepaymentStatus `json:"status"`
	PaidDate     *time.Time      `json:"paid_date,omitempty"`
	Interest     float64         `json:"interest"`
	Principal    float64         `json:"principal"`
}

// RepaymentTracking manages the repayment tracking for debt instruments
type RepaymentTracking struct {
	mu sync.Mutex
	repayments map[string]RepaymentEntry
}

// NewRepaymentTracking creates a new instance of RepaymentTracking
func NewRepaymentTracking() *RepaymentTracking {
	return &RepaymentTracking{
		repayments: make(map[string]RepaymentEntry),
	}
}

// CreateRepaymentSchedule creates a repayment schedule for a debt instrument
func (rt *RepaymentTracking) CreateRepaymentSchedule(debtID string, principalAmount, interestRate float64, repaymentPeriod int) ([]string, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	schedule := generateRepaymentSchedule(principalAmount, interestRate, repaymentPeriod)
	var repaymentIDs []string

	for _, entry := range schedule {
		repaymentID := generateRepaymentID()
		entry.RepaymentID = repaymentID
		entry.DebtID = debtID

		rt.repayments[repaymentID] = entry
		repaymentIDs = append(repaymentIDs, repaymentID)

		err := saveRepaymentEntryToStorage(entry)
		if err != nil {
			return nil, err
		}
	}

	return repaymentIDs, nil
}

// RecordRepayment records a repayment for a debt instrument
func (rt *RepaymentTracking) RecordRepayment(repaymentID string, amount float64) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entry, exists := rt.repayments[repaymentID]
	if !exists {
		return errors.New("repayment entry not found")
	}

	if entry.Status != RepaymentPending {
		return errors.New("repayment is not in a pending state")
	}

	paymentDate := time.Now()
	entry.Status = RepaymentCompleted
	entry.PaidDate = &paymentDate

	rt.repayments[repaymentID] = entry
	err := saveRepaymentEntryToStorage(entry)
	if err != nil {
		return err
	}

	_, err = recordLedgerEntry(entry.DebtID, "repayment", amount, entry.Amount, entry.Interest, entry.Principal)
	if err != nil {
		return err
	}

	return nil
}

// HandleLatePayments checks for and updates the status of late payments
func (rt *RepaymentTracking) HandleLatePayments() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for _, entry := range rt.repayments {
		if entry.Status == RepaymentPending && entry.DueDate.Before(time.Now()) {
			entry.Status = RepaymentLate
			rt.repayments[entry.RepaymentID] = entry
			err := saveRepaymentEntryToStorage(entry)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GetRepayment retrieves a repayment entry by ID
func (rt *RepaymentTracking) GetRepayment(repaymentID string) (RepaymentEntry, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entry, exists := rt.repayments[repaymentID]
	if !exists {
		return RepaymentEntry{}, errors.New("repayment entry not found")
	}

	return entry, nil
}

// GetRepaymentsByDebtID retrieves all repayment entries for a specific debt ID
func (rt *RepaymentTracking) GetRepaymentsByDebtID(debtID string) ([]RepaymentEntry, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var entries []RepaymentEntry
	for _, entry := range rt.repayments {
		if entry.DebtID == debtID {
			entries = append(entries, entry)
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("no repayment entries found for the specified debt ID")
	}

	return entries, nil
}

// generateRepaymentID generates a unique ID for the repayment entry
func generateRepaymentID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-repayment-id"
}

// generateRepaymentSchedule generates a repayment schedule for the debt instrument
func generateRepaymentSchedule(principalAmount, interestRate float64, repaymentPeriod int) []RepaymentEntry {
	var schedule []RepaymentEntry
	dueDate := time.Now().AddDate(0, 1, 0)
	monthlyPayment := principalAmount / float64(repaymentPeriod)
	monthlyInterest := (principalAmount * interestRate) / float64(repaymentPeriod)
	monthlyPrincipal := monthlyPayment - monthlyInterest

	for i := 0; i < repaymentPeriod; i++ {
		schedule = append(schedule, RepaymentEntry{
			Amount:    monthlyPayment,
			DueDate:   dueDate.AddDate(0, i, 0),
			Status:    RepaymentPending,
			Interest:  monthlyInterest,
			Principal: monthlyPrincipal,
		})
	}

	return schedule
}

// saveRepaymentEntryToStorage securely stores repayment entry data
func saveRepaymentEntryToStorage(entry RepaymentEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("repaymentEntry", entry.RepaymentID, encryptedData)
}

// recordLedgerEntry records a ledger entry for debt-related transactions
func recordLedgerEntry(debtID, transaction string, amount, balance, interest, principal float64) (string, error) {
	l := ledger.NewLedger()
	return l.RecordEntry(debtID, transaction, amount, balance, interest, principal)
}

// deleteRepaymentEntryFromStorage deletes repayment entry data from storage
func deleteRepaymentEntryFromStorage(repaymentID string) error {
	return storage.Delete("repaymentEntry", repaymentID)
}
