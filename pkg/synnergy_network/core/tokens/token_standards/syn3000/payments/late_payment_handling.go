package payments

import (
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/events"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/transactions"
)

// LatePaymentHandling handles late payments and associated penalties
type LatePaymentHandling struct {
	Ledger            ledger.Ledger
	AssetManager      assets.AssetManager
	EventLogger       events.EventLogger
	TransactionSystem transactions.TransactionSystem
}

// NewLatePaymentHandling creates a new instance of LatePaymentHandling
func NewLatePaymentHandling(ledger ledger.Ledger, assetManager assets.AssetManager, eventLogger events.EventLogger, transactionSystem transactions.TransactionSystem) *LatePaymentHandling {
	return &LatePaymentHandling{
		Ledger:            ledger,
		AssetManager:      assetManager,
		EventLogger:       eventLogger,
		TransactionSystem: transactionSystem,
	}
}

// LatePayment represents a late payment transaction
type LatePayment struct {
	TokenID     string
	Amount      float64
	Timestamp   time.Time
	DueDate     time.Time
	Penalty     float64
	Status      string // "pending", "resolved"
}

// PenaltyPolicy defines the policy for late payment penalties
type PenaltyPolicy struct {
	PenaltyRate  float64
	GracePeriod  time.Duration
	PenaltyCap   float64
}

// DefaultPenaltyPolicy defines the default penalty policy
var DefaultPenaltyPolicy = PenaltyPolicy{
	PenaltyRate: 0.05,
	GracePeriod: 7 * 24 * time.Hour,
	PenaltyCap:  100.0,
}

// HandleLatePayment processes a late payment and applies penalties
func (lph *LatePaymentHandling) HandleLatePayment(tokenID string, amount float64, dueDate time.Time) error {
	now := time.Now()
	lateDays := now.Sub(dueDate).Hours() / 24

	if lateDays <= 0 {
		return nil // Not late yet
	}

	penalty := lateDays * DefaultPenaltyPolicy.PenaltyRate * amount
	if penalty > DefaultPenaltyPolicy.PenaltyCap {
		penalty = DefaultPenaltyPolicy.PenaltyCap
	}

	latePayment := LatePayment{
		TokenID:   tokenID,
		Amount:    amount,
		Timestamp: now,
		DueDate:   dueDate,
		Penalty:   penalty,
		Status:    "pending",
	}

	if err := lph.Ledger.StoreLatePayment(latePayment); err != nil {
		return err
	}

	lph.EventLogger.LogEvent(events.Event{
		Type:      "LatePaymentRecorded",
		Timestamp: now,
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": amount, "penalty": penalty},
	})

	return nil
}

// ResolveLatePayment resolves a late payment and updates the ledger
func (lph *LatePaymentHandling) ResolveLatePayment(tokenID string) error {
	latePayment, err := lph.Ledger.GetLatePayment(tokenID)
	if err != nil {
		return err
	}

	if latePayment.Status != "pending" {
		return errors.New("late payment is not currently pending")
	}

	latePayment.Status = "resolved"
	if err := lph.Ledger.UpdateLatePayment(latePayment); err != nil {
		return err
	}

	payment := transactions.PaymentRecord{
		TokenID:   tokenID,
		Amount:    latePayment.Amount + latePayment.Penalty,
		Timestamp: time.Now(),
		Type:      "Late Payment",
	}

	if err := lph.TransactionSystem.ProcessPayment(payment, "landlord"); err != nil {
		return err
	}

	lph.EventLogger.LogEvent(events.Event{
		Type:      "LatePaymentResolved",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": latePayment.Amount, "penalty": latePayment.Penalty},
	})

	return nil
}
