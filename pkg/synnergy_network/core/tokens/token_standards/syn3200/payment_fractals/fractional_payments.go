package payment_fractals

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// FractionalPayment represents a fractional payment for a bill.
type FractionalPayment struct {
	PaymentID     string    `json:"payment_id"`
	BillID        string    `json:"bill_id"`
	Payer         string    `json:"payer"`
	Amount        float64   `json:"amount"`
	PaymentDate   time.Time `json:"payment_date"`
	PaymentStatus string    `json:"payment_status"`
}

// FractionalPaymentDB represents the database for managing fractional payments.
type FractionalPaymentDB struct {
	DB *leveldb.DB
}

// NewFractionalPaymentDB creates a new FractionalPaymentDB instance.
func NewFractionalPaymentDB(dbPath string) (*FractionalPaymentDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &FractionalPaymentDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (fpdb *FractionalPaymentDB) CloseDB() error {
	return fpdb.DB.Close()
}

// AddPayment adds a new fractional payment to the database.
func (fpdb *FractionalPaymentDB) AddPayment(payment FractionalPayment) error {
	if err := fpdb.ValidatePayment(payment); err != nil {
		return err
	}
	data, err := json.Marshal(payment)
	if err != nil {
		return err
	}
	return fpdb.DB.Put([]byte("payment_"+payment.PaymentID), data, nil)
}

// GetPayment retrieves a fractional payment by its payment ID.
func (fpdb *FractionalPaymentDB) GetPayment(paymentID string) (*FractionalPayment, error) {
	data, err := fpdb.DB.Get([]byte("payment_"+paymentID), nil)
	if err != nil {
		return nil, err
	}
	var payment FractionalPayment
	if err := json.Unmarshal(data, &payment); err != nil {
		return nil, err
	}
	return &payment, nil
}

// GetAllPayments retrieves all fractional payments from the database.
func (fpdb *FractionalPaymentDB) GetAllPayments() ([]FractionalPayment, error) {
	var payments []FractionalPayment
	iter := fpdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment FractionalPayment
		if err := json.Unmarshal(iter.Value(), &payment); err != nil {
			return nil, err
		}
		payments = append(payments, payment)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return payments, nil
}

// ValidatePayment ensures the fractional payment is valid before adding it to the database.
func (fpdb *FractionalPaymentDB) ValidatePayment(payment FractionalPayment) error {
	if payment.PaymentID == "" {
		return errors.New("payment ID must be provided")
	}
	if payment.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if payment.Payer == "" {
		return errors.New("payer must be provided")
	}
	if payment.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if payment.PaymentStatus == "" {
		return errors.New("payment status must be provided")
	}
	return nil
}

// UpdatePayment updates an existing fractional payment in the database.
func (fpdb *FractionalPaymentDB) UpdatePayment(payment FractionalPayment) error {
	if _, err := fpdb.GetPayment(payment.PaymentID); err != nil {
		return err
	}
	if err := fpdb.ValidatePayment(payment); err != nil {
		return err
	}
	data, err := json.Marshal(payment)
	if err != nil {
		return err
	}
	return fpdb.DB.Put([]byte("payment_"+payment.PaymentID), data, nil)
}

// DeletePayment removes a fractional payment from the database.
func (fpdb *FractionalPaymentDB) DeletePayment(paymentID string) error {
	return fpdb.DB.Delete([]byte("payment_"+paymentID), nil)
}

// PaymentSchedule represents a payment schedule for fractional payments.
type PaymentSchedule struct {
	ScheduleID   string    `json:"schedule_id"`
	BillID       string    `json:"bill_id"`
	Payer        string    `json:"payer"`
	Amount       float64   `json:"amount"`
	ScheduleDate time.Time `json:"schedule_date"`
}

// PaymentScheduleDB represents the database for managing payment schedules.
type PaymentScheduleDB struct {
	DB *leveldb.DB
}

// NewPaymentScheduleDB creates a new PaymentScheduleDB instance.
func NewPaymentScheduleDB(dbPath string) (*PaymentScheduleDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentScheduleDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (psdb *PaymentScheduleDB) CloseDB() error {
	return psdb.DB.Close()
}

// AddSchedule adds a new payment schedule to the database.
func (psdb *PaymentScheduleDB) AddSchedule(schedule PaymentSchedule) error {
	if err := psdb.ValidateSchedule(schedule); err != nil {
		return err
	}
	data, err := json.Marshal(schedule)
	if err != nil {
		return err
	}
	return psdb.DB.Put([]byte("schedule_"+schedule.ScheduleID), data, nil)
}

// GetSchedule retrieves a payment schedule by its schedule ID.
func (psdb *PaymentScheduleDB) GetSchedule(scheduleID string) (*PaymentSchedule, error) {
	data, err := psdb.DB.Get([]byte("schedule_"+scheduleID), nil)
	if err != nil {
		return nil, err
	}
	var schedule PaymentSchedule
	if err := json.Unmarshal(data, &schedule); err != nil {
		return nil, err
	}
	return &schedule, nil
}

// GetAllSchedules retrieves all payment schedules from the database.
func (psdb *PaymentScheduleDB) GetAllSchedules() ([]PaymentSchedule, error) {
	var schedules []PaymentSchedule
	iter := psdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var schedule PaymentSchedule
		if err := json.Unmarshal(iter.Value(), &schedule); err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return schedules, nil
}

// ValidateSchedule ensures the payment schedule is valid before adding it to the database.
func (psdb *PaymentScheduleDB) ValidateSchedule(schedule PaymentSchedule) error {
	if schedule.ScheduleID == "" {
		return errors.New("schedule ID must be provided")
	}
	if schedule.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if schedule.Payer == "" {
		return errors.New("payer must be provided")
	}
	if schedule.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if schedule.ScheduleDate.IsZero() {
		return errors.New("schedule date must be provided")
	}
	return nil
}

// UpdateSchedule updates an existing payment schedule in the database.
func (psdb *PaymentScheduleDB) UpdateSchedule(schedule PaymentSchedule) error {
	if _, err := psdb.GetSchedule(schedule.ScheduleID); err != nil {
		return err
	}
	if err := psdb.ValidateSchedule(schedule); err != nil {
		return err
	}
	data, err := json.Marshal(schedule)
	if err != nil {
		return err
	}
	return psdb.DB.Put([]byte("schedule_"+schedule.ScheduleID), data, nil)
}

// DeleteSchedule removes a payment schedule from the database.
func (psdb *PaymentScheduleDB) DeleteSchedule(scheduleID string) error {
	return psdb.DB.Delete([]byte("schedule_"+scheduleID), nil)
}

// PaymentTracker tracks the real-time status of payments.
type PaymentTracker struct {
	PaymentID     string    `json:"payment_id"`
	Status        string    `json:"status"`
	LastUpdated   time.Time `json:"last_updated"`
	PaymentAmount float64   `json:"payment_amount"`
}

// PaymentTrackingDB represents the database for tracking payments.
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

// AddTracking adds a new payment tracking entry to the database.
func (ptdb *PaymentTrackingDB) AddTracking(tracking PaymentTracker) error {
	data, err := json.Marshal(tracking)
	if err != nil {
		return err
	}
	return ptdb.DB.Put([]byte("tracking_"+tracking.PaymentID), data, nil)
}

// GetTracking retrieves a payment tracking entry by its payment ID.
func (ptdb *PaymentTrackingDB) GetTracking(paymentID string) (*PaymentTracker, error) {
	data, err := ptdb.DB.Get([]byte("tracking_"+paymentID), nil)
	if err != nil {
		return nil, err
	}
	var tracking PaymentTracker
	if err := json.Unmarshal(data, &tracking); err != nil {
		return nil, err
	}
	return &tracking, nil
}

// UpdateTracking updates an existing payment tracking entry in the database.
func (ptdb *PaymentTrackingDB) UpdateTracking(tracking PaymentTracker) error {
	data, err := json.Marshal(tracking)
	if err != nil {
		return err
	}
	return ptdb.DB.Put([]byte("tracking_"+tracking.PaymentID), data, nil)
}

// DeleteTracking removes a payment tracking entry from the database.
func (ptdb *PaymentTrackingDB) DeleteTracking(paymentID string) error {
	return ptdb.DB.Delete([]byte("tracking_"+paymentID), nil)
}

// ValidateTracking ensures the payment tracking entry is valid before adding it to the database.
func (ptdb *PaymentTrackingDB) ValidateTracking(tracking PaymentTracker) error {
	if tracking.PaymentID == "" {
		return errors.New("payment ID must be provided")
	}
	if tracking.Status == "" {
		return errors.New("status must be provided")
	}
	if tracking.PaymentAmount <= 0 {
		return errors.New("payment amount must be greater than zero")
	}
	return nil
}
