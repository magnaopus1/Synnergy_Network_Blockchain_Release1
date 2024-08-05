package payments

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/events"
)

// PaymentTracking manages the tracking of rent payments
type PaymentTracking struct {
	ledger       ledger.Ledger
	eventLogger  events.EventLogger
	assetManager assets.AssetManager
	mutex        sync.Mutex
}

// PaymentStatus represents the status of a payment
type PaymentStatus struct {
	TokenID   string
	Amount    float64
	Timestamp time.Time
	Status    string // "completed", "pending", "failed"
}

// NewPaymentTracking creates a new instance of PaymentTracking
func NewPaymentTracking(ledger ledger.Ledger, eventLogger events.EventLogger, assetManager assets.AssetManager) *PaymentTracking {
	return &PaymentTracking{
		ledger:       ledger,
		eventLogger:  eventLogger,
		assetManager: assetManager,
		mutex:        sync.Mutex{},
	}
}

// TrackPayment adds a new payment status to the tracking system
func (pt *PaymentTracking) TrackPayment(tokenID string, amount float64, status string) error {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	if tokenID == "" || amount <= 0 || status == "" {
		return errors.New("invalid payment status details")
	}

	paymentStatus := PaymentStatus{
		TokenID:   tokenID,
		Amount:    amount,
		Timestamp: time.Now(),
		Status:    status,
	}

	if err := pt.ledger.StorePaymentStatus(paymentStatus); err != nil {
		return err
	}

	pt.eventLogger.LogEvent(events.Event{
		Type:      "PaymentStatusTracked",
		Timestamp: paymentStatus.Timestamp,
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": amount, "status": status},
	})

	return nil
}

// GetPaymentStatus retrieves the payment status for a specific token ID
func (pt *PaymentTracking) GetPaymentStatus(tokenID string) ([]PaymentStatus, error) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	if tokenID == "" {
		return nil, errors.New("invalid token ID")
	}

	status, err := pt.ledger.GetPaymentStatusByTokenID(tokenID)
	if err != nil {
		return nil, err
	}

	return status, nil
}

// GetAllPaymentStatuses retrieves all payment statuses
func (pt *PaymentTracking) GetAllPaymentStatuses() ([]PaymentStatus, error) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	statuses, err := pt.ledger.GetAllPaymentStatuses()
	if err != nil {
		return nil, err
	}

	return statuses, nil
}

// UpdatePaymentStatus updates the status of a payment
func (pt *PaymentTracking) UpdatePaymentStatus(tokenID string, timestamp time.Time, status string) error {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	if tokenID == "" || status == "" {
		return errors.New("invalid payment status details")
	}

	paymentStatus, err := pt.ledger.GetPaymentStatus(tokenID, timestamp)
	if err != nil {
		return err
	}

	paymentStatus.Status = status

	if err := pt.ledger.UpdatePaymentStatus(paymentStatus); err != nil {
		return err
	}

	pt.eventLogger.LogEvent(events.Event{
		Type:      "PaymentStatusUpdated",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "status": status},
	})

	return nil
}

// DeletePaymentStatus deletes a payment status from the tracking system
func (pt *PaymentTracking) DeletePaymentStatus(tokenID string, timestamp time.Time) error {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	if tokenID == "" {
		return errors.New("invalid token ID")
	}

	if err := pt.ledger.DeletePaymentStatus(tokenID, timestamp); err != nil {
		return err
	}

	pt.eventLogger.LogEvent(events.Event{
		Type:      "PaymentStatusDeleted",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "timestamp": timestamp},
	})

	return nil
}
