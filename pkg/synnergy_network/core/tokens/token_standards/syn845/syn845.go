package syn845

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// DebtStatus represents the status of the debt instrument
type DebtStatus string

const (
	Active    DebtStatus = "active"
	Defaulted DebtStatus = "defaulted"
	Repaid    DebtStatus = "repaid"
)

// SYN845 represents the SYN845 debt instrument standard
type SYN845 struct {
	DebtID               string           `json:"debt_id"`
	LoanerID             string           `json:"loaner_id"`
	LoaneeID             string           `json:"loanee_id"`
	PrincipalAmount      float64          `json:"principal_amount"`
	InterestRate         float64          `json:"interest_rate"`
	RepaymentPeriod      int              `json:"repayment_period"` // in months
	PenaltyRate          float64          `json:"penalty_rate"`
	CollateralID         string           `json:"collateral_id"`
	Status               DebtStatus       `json:"status"`
	CreationDate         time.Time        `json:"creation_date"`
	LastUpdatedDate      time.Time        `json:"last_updated_date"`
	AccruedInterest      float64          `json:"accrued_interest"`
	RepaymentSchedule    []RepaymentEntry `json:"repayment_schedule"`
	PaymentHistory       []PaymentEntry   `json:"payment_history"`
	EarlyRepaymentPenalty float64         `json:"early_repayment_penalty"`
	SettlementHistory    []SettlementEntry `json:"settlement_history"`
}

// RepaymentEntry represents an entry in the repayment schedule
type RepaymentEntry struct {
	DueDate  time.Time `json:"due_date"`
	Amount   float64   `json:"amount"`
	Paid     bool      `json:"paid"`
}

// PaymentEntry represents a payment made towards the debt instrument
type PaymentEntry struct {
	PaymentDate time.Time `json:"payment_date"`
	Amount      float64   `json:"amount"`
	Interest    float64   `json:"interest"`
	Principal   float64   `json:"principal"`
	Balance     float64   `json:"balance"`
}

// SettlementEntry represents an entry in the settlement history
type SettlementEntry struct {
	SettlementDate time.Time `json:"settlement_date"`
	SettledBy      string    `json:"settled_by"` // LoanerID or LoaneeID
	SettledAmount  float64   `json:"settled_amount"`
}

var (
	syn845Store = make(map[string]SYN845)
	mutex       = &sync.Mutex{}
)

// CreateSYN845 creates a new SYN845 debt instrument for both loaner and loanee
func CreateSYN845(loanerID, loaneeID string, principalAmount, interestRate, penaltyRate, earlyRepaymentPenalty float64, repaymentPeriod int, collateralID string) (string, error) {
	mutex.Lock()
	defer mutex.Unlock()

	debtID := generateDebtID()
	creationDate := time.Now()

	repaymentSchedule := generateRepaymentSchedule(principalAmount, interestRate, repaymentPeriod)

	syn845 := SYN845{
		DebtID:               debtID,
		LoanerID:             loanerID,
		LoaneeID:             loaneeID,
		PrincipalAmount:      principalAmount,
		InterestRate:         interestRate,
		RepaymentPeriod:      repaymentPeriod,
		PenaltyRate:          penaltyRate,
		CollateralID:         collateralID,
		Status:               Active,
		CreationDate:         creationDate,
		LastUpdatedDate:      creationDate,
		AccruedInterest:      0,
		RepaymentSchedule:    repaymentSchedule,
		PaymentHistory:       []PaymentEntry{},
		EarlyRepaymentPenalty: earlyRepaymentPenalty,
		SettlementHistory:    []SettlementEntry{},
	}

	syn845Store[debtID] = syn845
	err := saveSYN845ToStorage(syn845)
	if err != nil {
		return "", err
	}

	return debtID, nil
}

// UpdateSYN845 updates an existing SYN845 debt instrument
func UpdateSYN845(debtID string, principalAmount, interestRate, penaltyRate, earlyRepaymentPenalty float64, repaymentPeriod int, collateralID string, status DebtStatus) error {
	mutex.Lock()
	defer mutex.Unlock()

	syn845, exists := syn845Store[debtID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	syn845.PrincipalAmount = principalAmount
	syn845.InterestRate = interestRate
	syn845.RepaymentPeriod = repaymentPeriod
	syn845.PenaltyRate = penaltyRate
	syn845.CollateralID = collateralID
	syn845.Status = status
	syn845.EarlyRepaymentPenalty = earlyRepaymentPenalty
	syn845.LastUpdatedDate = time.Now()

	syn845Store[debtID] = syn845
	err := saveSYN845ToStorage(syn845)
	if err != nil {
		return err
	}

	return nil
}

// GetSYN845 retrieves a SYN845 debt instrument by ID
func GetSYN845(debtID string) (SYN845, error) {
	mutex.Lock()
	defer mutex.Unlock()

	syn845, exists := syn845Store[debtID]
	if !exists {
		return SYN845{}, errors.New("debt instrument not found")
	}

	return syn845, nil
}

// DeleteSYN845 deletes a SYN845 debt instrument by ID
func DeleteSYN845(debtID string) error {
	mutex.Lock()
	defer mutex.Unlock()

	_, exists := syn845Store[debtID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	delete(syn845Store, debtID)
	return deleteSYN845FromStorage(debtID)
}

// AddPayment records a payment for a SYN845 debt instrument
func AddPayment(debtID string, amount, interest, principal float64) error {
	mutex.Lock()
	defer mutex.Unlock()

	syn845, exists := syn845Store[debtID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	paymentDate := time.Now()
	balance := syn845.PrincipalAmount - principal
	syn845.AccruedInterest += interest

	paymentEntry := PaymentEntry{
		PaymentDate: paymentDate,
		Amount:      amount,
		Interest:    interest,
		Principal:   principal,
		Balance:     balance,
	}

	syn845.PaymentHistory = append(syn845.PaymentHistory, paymentEntry)
	syn845.LastUpdatedDate = paymentDate

	for i, entry := range syn845.RepaymentSchedule {
		if !entry.Paid && entry.DueDate.Before(paymentDate) {
			syn845.RepaymentSchedule[i].Paid = true
		}
	}

	syn845Store[debtID] = syn845
	return saveSYN845ToStorage(syn845)
}

// SettleDebt settles a SYN845 debt instrument
func SettleDebt(debtID, settledBy string, settledAmount float64) error {
	mutex.Lock()
	defer mutex.Unlock()

	syn845, exists := syn845Store[debtID]
	if !exists {
		return errors.New("debt instrument not found")
	}

	settlementDate := time.Now()

	settlementEntry := SettlementEntry{
		SettlementDate: settlementDate,
		SettledBy:      settledBy,
		SettledAmount:  settledAmount,
	}

	syn845.SettlementHistory = append(syn845.SettlementHistory, settlementEntry)
	syn845.LastUpdatedDate = settlementDate

	// Check if the debt is fully settled
	if settledAmount >= syn845.PrincipalAmount+syn845.AccruedInterest {
		syn845.Status = Repaid
	}

	syn845Store[debtID] = syn845
	return saveSYN845ToStorage(syn845)
}

// generateDebtID generates a unique ID for the debt instrument
func generateDebtID() string {
	return uuid.New().String()
}

// generateRepaymentSchedule generates a repayment schedule for the debt instrument
func generateRepaymentSchedule(principalAmount, interestRate float64, repaymentPeriod int) []RepaymentEntry {
	var schedule []RepaymentEntry
	dueDate := time.Now().AddDate(0, 1, 0)
	monthlyPayment := principalAmount / float64(repaymentPeriod)
	for i := 0; i < repaymentPeriod; i++ {
		schedule = append(schedule, RepaymentEntry{
			DueDate: dueDate.AddDate(0, i, 0),
			Amount:  monthlyPayment,
			Paid:    false,
		})
	}
	return schedule
}

// saveSYN845ToStorage securely stores SYN845 debt instrument data
func saveSYN845ToStorage(syn845 SYN845) error {
	data, err := json.Marshal(syn845)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("syn845", syn845.DebtID, encryptedData)
}

// deleteSYN845FromStorage deletes SYN845 debt instrument data from storage
func deleteSYN845FromStorage(debtID string) error {
	return storage.Delete("syn845", debtID)
}
