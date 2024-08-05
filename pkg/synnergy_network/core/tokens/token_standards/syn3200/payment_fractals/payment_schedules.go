package payment_fractals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// PaymentSchedule represents the schedule for automated payments of a bill.
type PaymentSchedule struct {
	ScheduleID   string    `json:"schedule_id"`
	BillID       string    `json:"bill_id"`
	Payer        string    `json:"payer"`
	Amount       float64   `json:"amount"`
	Frequency    string    `json:"frequency"` // Daily, Weekly, Monthly
	NextPayment  time.Time `json:"next_payment"`
	Status       string    `json:"status"`    // Active, Paused, Cancelled
	CreatedAt    time.Time `json:"created_at"`
	ModifiedAt   time.Time `json:"modified_at"`
}

// PaymentSchedulesDB represents the database for managing payment schedules.
type PaymentSchedulesDB struct {
	DB *leveldb.DB
}

// NewPaymentSchedulesDB creates a new PaymentSchedulesDB instance.
func NewPaymentSchedulesDB(dbPath string) (*PaymentSchedulesDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentSchedulesDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (psdb *PaymentSchedulesDB) CloseDB() error {
	return psdb.DB.Close()
}

// AddPaymentSchedule adds a new payment schedule to the database.
func (psdb *PaymentSchedulesDB) AddPaymentSchedule(schedule PaymentSchedule) error {
	if err := psdb.ValidatePaymentSchedule(schedule); err != nil {
		return err
	}
	data, err := json.Marshal(schedule)
	if err != nil {
		return err
	}
	return psdb.DB.Put([]byte("payment_schedule_"+schedule.ScheduleID), data, nil)
}

// GetPaymentSchedule retrieves a payment schedule by its ID.
func (psdb *PaymentSchedulesDB) GetPaymentSchedule(scheduleID string) (*PaymentSchedule, error) {
	data, err := psdb.DB.Get([]byte("payment_schedule_"+scheduleID), nil)
	if err != nil {
		return nil, err
	}
	var schedule PaymentSchedule
	if err := json.Unmarshal(data, &schedule); err != nil {
		return nil, err
	}
	return &schedule, nil
}

// GetAllPaymentSchedules retrieves all payment schedules from the database.
func (psdb *PaymentSchedulesDB) GetAllPaymentSchedules() ([]PaymentSchedule, error) {
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

// ValidatePaymentSchedule ensures the payment schedule is valid before adding it to the database.
func (psdb *PaymentSchedulesDB) ValidatePaymentSchedule(schedule PaymentSchedule) error {
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
	if schedule.Frequency == "" {
		return errors.New("frequency must be provided")
	}
	if schedule.Status == "" {
		return errors.New("status must be provided")
	}
	return nil
}

// UpdatePaymentSchedule updates an existing payment schedule in the database.
func (psdb *PaymentSchedulesDB) UpdatePaymentSchedule(schedule PaymentSchedule) error {
	if _, err := psdb.GetPaymentSchedule(schedule.ScheduleID); err != nil {
		return err
	}
	if err := psdb.ValidatePaymentSchedule(schedule); err != nil {
		return err
	}
	schedule.ModifiedAt = time.Now()
	data, err := json.Marshal(schedule)
	if err != nil {
		return err
	}
	return psdb.DB.Put([]byte("payment_schedule_"+schedule.ScheduleID), data, nil)
}

// DeletePaymentSchedule removes a payment schedule from the database.
func (psdb *PaymentSchedulesDB) DeletePaymentSchedule(scheduleID string) error {
	return psdb.DB.Delete([]byte("payment_schedule_"+scheduleID), nil)
}

// SearchPaymentSchedulesByBillID retrieves all payment schedules for a specific bill ID.
func (psdb *PaymentSchedulesDB) SearchPaymentSchedulesByBillID(billID string) ([]PaymentSchedule, error) {
	var schedules []PaymentSchedule
	iter := psdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var schedule PaymentSchedule
		if err := json.Unmarshal(iter.Value(), &schedule); err != nil {
			return nil, err
		}
		if schedule.BillID == billID {
			schedules = append(schedules, schedule)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return schedules, nil
}

// SearchPaymentSchedulesByPayer retrieves all payment schedules for a specific payer.
func (psdb *PaymentSchedulesDB) SearchPaymentSchedulesByPayer(payer string) ([]PaymentSchedule, error) {
	var schedules []PaymentSchedule
	iter := psdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var schedule PaymentSchedule
		if err := json.Unmarshal(iter.Value(), &schedule); err != nil {
			return nil, err
		}
		if schedule.Payer == payer {
			schedules = append(schedules, schedule)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return schedules, nil
}

// SearchPaymentSchedulesByStatus retrieves all payment schedules by their status.
func (psdb *PaymentSchedulesDB) SearchPaymentSchedulesByStatus(status string) ([]PaymentSchedule, error) {
	var schedules []PaymentSchedule
	iter := psdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var schedule PaymentSchedule
		if err := json.Unmarshal(iter.Value(), &schedule); err != nil {
			return nil, err
		}
		if schedule.Status == status {
			schedules = append(schedules, schedule)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return schedules, nil
}

// SearchPaymentSchedulesByDateRange retrieves all payment schedules within a specific date range.
func (psdb *PaymentSchedulesDB) SearchPaymentSchedulesByDateRange(startDate, endDate time.Time) ([]PaymentSchedule, error) {
	var schedules []PaymentSchedule
	iter := psdb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var schedule PaymentSchedule
		if err := json.Unmarshal(iter.Value(), &schedule); err != nil {
			return nil, err
		}
		if schedule.CreatedAt.After(startDate) && schedule.CreatedAt.Before(endDate) {
			schedules = append(schedules, schedule)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return schedules, nil
}

// ExecuteScheduledPayments executes all active scheduled payments due for today.
func (psdb *PaymentSchedulesDB) ExecuteScheduledPayments() error {
	schedules, err := psdb.SearchPaymentSchedulesByStatus("Active")
	if err != nil {
		return err
	}

	for _, schedule := range schedules {
		if schedule.NextPayment.Before(time.Now()) || schedule.NextPayment.Equal(time.Now()) {
			// Logic to process the payment goes here.
			// E.g., interacting with a payment gateway, updating bill status, etc.

			// For demonstration, we assume the payment is successful:
			schedule.NextPayment = calculateNextPaymentDate(schedule.Frequency, schedule.NextPayment)
			schedule.ModifiedAt = time.Now()

			// Update the payment schedule in the database.
			if err := psdb.UpdatePaymentSchedule(schedule); err != nil {
				return err
			}
		}
	}

	return nil
}

// calculateNextPaymentDate calculates the next payment date based on the frequency.
func calculateNextPaymentDate(frequency string, currentPaymentDate time.Time) time.Time {
	switch frequency {
	case "Daily":
		return currentPaymentDate.AddDate(0, 0, 1)
	case "Weekly":
		return currentPaymentDate.AddDate(0, 0, 7)
	case "Monthly":
		return currentPaymentDate.AddDate(0, 1, 0)
	default:
		return currentPaymentDate
	}
}
