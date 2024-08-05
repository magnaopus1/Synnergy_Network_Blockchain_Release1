package payment_fractals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// PaymentTracking represents the tracking details of a payment.
type PaymentTracking struct {
	TrackingID string    `json:"tracking_id"`
	PaymentID  string    `json:"payment_id"`
	BillID     string    `json:"bill_id"`
	Payer      string    `json:"payer"`
	Amount     float64   `json:"amount"`
	Status     string    `json:"status"` // Initiated, In-Progress, Completed, Failed
	Timestamp  time.Time `json:"timestamp"`
	Metadata   string    `json:"metadata"`
}

// PaymentTrackingDB represents the database for managing payment tracking.
type PaymentTrackingDB struct {
	DB *leveldb.DB
}

// NewPaymentTrackingDB creates a new PaymentTrackingDB instance.
func NewPaymentTrackingDB(dbPath string) (*PaymentTrackingDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentTrackingDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (ptdb *PaymentTrackingDB) CloseDB() error {
	return ptdb.DB.Close()
}

// AddPaymentTracking adds a new payment tracking entry to the database.
func (ptdb *PaymentTrackingDB) AddPaymentTracking(tracking PaymentTracking) error {
	if err := ptdb.ValidatePaymentTracking(tracking); err != nil {
		return err
	}
	data, err := json.Marshal(tracking)
	if err != nil {
		return err
	}
	return ptdb.DB.Put([]byte("payment_tracking_"+tracking.TrackingID), data, nil)
}

// GetPaymentTracking retrieves a payment tracking entry by its tracking ID.
func (ptdb *PaymentTrackingDB) GetPaymentTracking(trackingID string) (*PaymentTracking, error) {
	data, err := ptdb.DB.Get([]byte("payment_tracking_"+trackingID), nil)
	if err != nil {
		return nil, err
	}
	var tracking PaymentTracking
	if err := json.Unmarshal(data, &tracking); err != nil {
		return nil, err
	}
	return &tracking, nil
}

// GetAllPaymentTrackings retrieves all payment tracking entries from the database.
func (ptdb *PaymentTrackingDB) GetAllPaymentTrackings() ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		trackings = append(trackings, tracking)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}

// ValidatePaymentTracking ensures the payment tracking entry is valid before adding it to the database.
func (ptdb *PaymentTrackingDB) ValidatePaymentTracking(tracking PaymentTracking) error {
	if tracking.TrackingID == "" {
		return errors.New("tracking ID must be provided")
	}
	if tracking.PaymentID == "" {
		return errors.New("payment ID must be provided")
	}
	if tracking.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if tracking.Payer == "" {
		return errors.New("payer must be provided")
	}
	if tracking.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if tracking.Status == "" {
		return errors.New("status must be provided")
	}
	return nil
}

// UpdatePaymentTracking updates an existing payment tracking entry in the database.
func (ptdb *PaymentTrackingDB) UpdatePaymentTracking(tracking PaymentTracking) error {
	if _, err := ptdb.GetPaymentTracking(tracking.TrackingID); err != nil {
		return err
	}
	if err := ptdb.ValidatePaymentTracking(tracking); err != nil {
		return err
	}
	tracking.Timestamp = time.Now()
	data, err := json.Marshal(tracking)
	if err != nil {
		return err
	}
	return ptdb.DB.Put([]byte("payment_tracking_"+tracking.TrackingID), data, nil)
}

// DeletePaymentTracking removes a payment tracking entry from the database.
func (ptdb *PaymentTrackingDB) DeletePaymentTracking(trackingID string) error {
	return ptdb.DB.Delete([]byte("payment_tracking_"+trackingID), nil)
}

// SearchPaymentTrackingsByPaymentID retrieves all payment tracking entries for a specific payment ID.
func (ptdb *PaymentTrackingDB) SearchPaymentTrackingsByPaymentID(paymentID string) ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		if tracking.PaymentID == paymentID {
			trackings = append(trackings, tracking)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}

// SearchPaymentTrackingsByBillID retrieves all payment tracking entries for a specific bill ID.
func (ptdb *PaymentTrackingDB) SearchPaymentTrackingsByBillID(billID string) ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		if tracking.BillID == billID {
			trackings = append(trackings, tracking)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}

// SearchPaymentTrackingsByPayer retrieves all payment tracking entries for a specific payer.
func (ptdb *PaymentTrackingDB) SearchPaymentTrackingsByPayer(payer string) ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		if tracking.Payer == payer {
			trackings = append(trackings, tracking)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}

// SearchPaymentTrackingsByStatus retrieves all payment tracking entries by their status.
func (ptdb *PaymentTrackingDB) SearchPaymentTrackingsByStatus(status string) ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		if tracking.Status == status {
			trackings = append(trackings, tracking)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}

// SearchPaymentTrackingsByDateRange retrieves all payment tracking entries within a specific date range.
func (ptdb *PaymentTrackingDB) SearchPaymentTrackingsByDateRange(startDate, endDate time.Time) ([]PaymentTracking, error) {
	var trackings []PaymentTracking
	iter := ptdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var tracking PaymentTracking
		if err := json.Unmarshal(iter.Value(), &tracking); err != nil {
			return nil, err
		}
		if tracking.Timestamp.After(startDate) && tracking.Timestamp.Before(endDate) {
			trackings = append(trackings, tracking)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return trackings, nil
}
