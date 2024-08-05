package factory

import (
	"errors"
	"time"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn845/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn845"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// TokenFactory manages the creation and lifecycle of SYN845 tokens
type TokenFactory struct {
	mu sync.Mutex
}

// NewTokenFactory creates a new instance of TokenFactory
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{}
}

// CreateDebtInstrument creates a new SYN845 debt instrument
func (tf *TokenFactory) CreateDebtInstrument(ownerID string, principalAmount, interestRate, penaltyRate float64, repaymentPeriod int, collateralID string) (string, error) {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	debtID := generateDebtID()
	creationDate := time.Now()

	repaymentSchedule := generateRepaymentSchedule(principalAmount, interestRate, repaymentPeriod)

	debtInstrument := syn845.SYN845{
		DebtID:            debtID,
		OwnerID:           ownerID,
		PrincipalAmount:   principalAmount,
		InterestRate:      interestRate,
		RepaymentPeriod:   repaymentPeriod,
		PenaltyRate:       penaltyRate,
		CollateralID:      collateralID,
		Status:            "active",
		CreationDate:      creationDate,
		LastUpdatedDate:   creationDate,
		AccruedInterest:   0,
		RepaymentSchedule: repaymentSchedule,
		PaymentHistory:    []syn845.PaymentEntry{},
	}

	if err := saveDebtInstrumentToStorage(debtInstrument); err != nil {
		return "", err
	}

	return debtID, nil
}

// UpdateDebtInstrument updates an existing SYN845 debt instrument
func (tf *TokenFactory) UpdateDebtInstrument(debtID string, principalAmount, interestRate, penaltyRate float64, repaymentPeriod int, collateralID, status string) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	debtInstrument, err := syn845.GetSYN845(debtID)
	if err != nil {
		return err
	}

	debtInstrument.PrincipalAmount = principalAmount
	debtInstrument.InterestRate = interestRate
	debtInstrument.RepaymentPeriod = repaymentPeriod
	debtInstrument.PenaltyRate = penaltyRate
	debtInstrument.CollateralID = collateralID
	debtInstrument.Status = status
	debtInstrument.LastUpdatedDate = time.Now()

	return saveDebtInstrumentToStorage(debtInstrument)
}

// AddCollateral adds collateral to a debt instrument
func (tf *TokenFactory) AddCollateral(debtID, assetID, ownerID string, value float64, status string) (string, error) {
	collateralID, err := assets.CreateCollateral(assetID, ownerID, value, status)
	if err != nil {
		return "", err
	}

	debtInstrument, err := syn845.GetSYN845(debtID)
	if err != nil {
		return "", err
	}

	debtInstrument.CollateralID = collateralID
	debtInstrument.LastUpdatedDate = time.Now()

	if err := saveDebtInstrumentToStorage(debtInstrument); err != nil {
		return "", err
	}

	return collateralID, nil
}

// RecordPayment records a payment for a SYN845 debt instrument
func (tf *TokenFactory) RecordPayment(debtID string, amount, interest, principal float64) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	return syn845.AddPayment(debtID, amount, interest, principal)
}

// RetrieveDebtInstrument retrieves a debt instrument by ID
func (tf *TokenFactory) RetrieveDebtInstrument(debtID string) (syn845.SYN845, error) {
	return syn845.GetSYN845(debtID)
}

// RemoveDebtInstrument deletes a debt instrument by ID
func (tf *TokenFactory) RemoveDebtInstrument(debtID string) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	return syn845.DeleteSYN845(debtID)
}

// generateDebtID generates a unique ID for the debt instrument
func generateDebtID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-debt-id"
}

// generateRepaymentSchedule generates a repayment schedule for the debt instrument
func generateRepaymentSchedule(principalAmount, interestRate float64, repaymentPeriod int) []syn845.RepaymentEntry {
	var schedule []syn845.RepaymentEntry
	dueDate := time.Now().AddDate(0, 1, 0)
	monthlyPayment := principalAmount / float64(repaymentPeriod)
	for i := 0; i < repaymentPeriod; i++ {
		schedule = append(schedule, syn845.RepaymentEntry{
			DueDate: dueDate.AddDate(0, i, 0),
			Amount:  monthlyPayment,
			Paid:    false,
		})
	}
	return schedule
}

// saveDebtInstrumentToStorage securely stores SYN845 debt instrument data
func saveDebtInstrumentToStorage(debtInstrument syn845.SYN845) error {
	data, err := json.Marshal(debtInstrument)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("syn845", debtInstrument.DebtID, encryptedData)
}
