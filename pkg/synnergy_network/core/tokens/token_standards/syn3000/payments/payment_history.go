package payments

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/events"
)

// PaymentHistory manages the history of rent payments
type PaymentHistory struct {
	ledger       ledger.Ledger
	eventLogger  events.EventLogger
	assetManager assets.AssetManager
	mutex        sync.Mutex
}

// PaymentRecord represents a single payment transaction
type PaymentRecord struct {
	TokenID   string
	Amount    float64
	Timestamp time.Time
	Status    string // "completed", "pending", "failed"
}

// NewPaymentHistory creates a new instance of PaymentHistory
func NewPaymentHistory(ledger ledger.Ledger, eventLogger events.EventLogger, assetManager assets.AssetManager) *PaymentHistory {
	return &PaymentHistory{
		ledger:       ledger,
		eventLogger:  eventLogger,
		assetManager: assetManager,
		mutex:        sync.Mutex{},
	}
}

// AddPaymentRecord adds a new payment record to the history
func (ph *PaymentHistory) AddPaymentRecord(tokenID string, amount float64, status string) error {
	ph.mutex.Lock()
	defer ph.mutex.Unlock()

	if tokenID == "" || amount <= 0 || status == "" {
		return errors.New("invalid payment record details")
	}

	record := PaymentRecord{
		TokenID:   tokenID,
		Amount:    amount,
		Timestamp: time.Now(),
		Status:    status,
	}

	if err := ph.ledger.StorePaymentRecord(record); err != nil {
		return err
	}

	ph.eventLogger.LogEvent(events.Event{
		Type:      "PaymentRecordAdded",
		Timestamp: record.Timestamp,
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": amount, "status": status},
	})

	return nil
}

// GetPaymentHistory retrieves the payment history for a specific token ID
func (ph *PaymentHistory) GetPaymentHistory(tokenID string) ([]PaymentRecord, error) {
	ph.mutex.Lock()
	defer ph.mutex.Unlock()

	if tokenID == "" {
		return nil, errors.New("invalid token ID")
	}

	history, err := ph.ledger.GetPaymentRecordsByTokenID(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}

// GetPaymentSummary provides a summary of payments for a specific token ID
func (ph *PaymentHistory) GetPaymentSummary(tokenID string) (float64, error) {
	ph.mutex.Lock()
	defer ph.mutex.Unlock()

	if tokenID == "" {
		return 0, errors.New("invalid token ID")
	}

	history, err := ph.ledger.GetPaymentRecordsByTokenID(tokenID)
	if err != nil {
		return 0, err
	}

	var total float64
	for _, record := range history {
		if record.Status == "completed" {
			total += record.Amount
		}
	}

	return total, nil
}

// GetAllPaymentRecords retrieves all payment records
func (ph *PaymentHistory) GetAllPaymentRecords() ([]PaymentRecord, error) {
	ph.mutex.Lock()
	defer ph.mutex.Unlock()

	history, err := ph.ledger.GetAllPaymentRecords()
	if err != nil {
		return nil, err
	}

	return history, nil
}

// UpdatePaymentStatus updates the status of a payment record
func (ph *PaymentHistory) UpdatePaymentStatus(tokenID string, timestamp time.Time, status string) error {
	ph.mutex.Lock()
	defer ph.mutex.Unlock()

	if tokenID == "" || status == "" {
		return errors.New("invalid payment record details")
	}

	record, err := ph.ledger.GetPaymentRecord(tokenID, timestamp)
	if err != nil {
		return err
	}

	record.Status = status

	if err := ph.ledger.UpdatePaymentRecord(record); err != nil {
		return err
	}

	ph.eventLogger.LogEvent(events.Event{
		Type:      "PaymentStatusUpdated",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "status": status},
	})

	return nil
}
