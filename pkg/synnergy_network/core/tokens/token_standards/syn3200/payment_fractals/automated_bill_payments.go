package payment_fractals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// AutomatedBillPayment represents an automated payment for a bill.
type AutomatedBillPayment struct {
	PaymentID  string    `json:"payment_id"`
	BillID     string    `json:"bill_id"`
	Payer      string    `json:"payer"`
	Amount     float64   `json:"amount"`
	Schedule   string    `json:"schedule"` // Daily, Weekly, Monthly
	Status     string    `json:"status"`   // Pending, Completed, Cancelled
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

// AutomatedBillPaymentsDB represents the database for managing automated bill payments.
type AutomatedBillPaymentsDB struct {
	DB *leveldb.DB
}

// NewAutomatedBillPaymentsDB creates a new AutomatedBillPaymentsDB instance.
func NewAutomatedBillPaymentsDB(dbPath string) (*AutomatedBillPaymentsDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &AutomatedBillPaymentsDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (abpd *AutomatedBillPaymentsDB) CloseDB() error {
	return abpd.DB.Close()
}

// AddAutomatedBillPayment adds a new automated bill payment to the database.
func (abpd *AutomatedBillPaymentsDB) AddAutomatedBillPayment(payment AutomatedBillPayment) error {
	if err := abpd.ValidateAutomatedBillPayment(payment); err != nil {
		return err
	}
	data, err := json.Marshal(payment)
	if err != nil {
		return err
	}
	return abpd.DB.Put([]byte("automated_bill_payment_"+payment.PaymentID), data, nil)
}

// GetAutomatedBillPayment retrieves an automated bill payment by its payment ID.
func (abpd *AutomatedBillPaymentsDB) GetAutomatedBillPayment(paymentID string) (*AutomatedBillPayment, error) {
	data, err := abpd.DB.Get([]byte("automated_bill_payment_"+paymentID), nil)
	if err != nil {
		return nil, err
	}
	var payment AutomatedBillPayment
	if err := json.Unmarshal(data, &payment); err != nil {
		return nil, err
	}
	return &payment, nil
}

// GetAllAutomatedBillPayments retrieves all automated bill payments from the database.
func (abpd *AutomatedBillPaymentsDB) GetAllAutomatedBillPayments() ([]AutomatedBillPayment, error) {
	var payments []AutomatedBillPayment
	iter := abpd.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment AutomatedBillPayment
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

// ValidateAutomatedBillPayment ensures the automated bill payment is valid before adding it to the database.
func (abpd *AutomatedBillPaymentsDB) ValidateAutomatedBillPayment(payment AutomatedBillPayment) error {
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
	if payment.Schedule == "" {
		return errors.New("schedule must be provided")
	}
	if payment.Status == "" {
		return errors.New("status must be provided")
	}
	return nil
}

// UpdateAutomatedBillPayment updates an existing automated bill payment in the database.
func (abpd *AutomatedBillPaymentsDB) UpdateAutomatedBillPayment(payment AutomatedBillPayment) error {
	if _, err := abpd.GetAutomatedBillPayment(payment.PaymentID); err != nil {
		return err
	}
	if err := abpd.ValidateAutomatedBillPayment(payment); err != nil {
		return err
	}
	payment.ModifiedAt = time.Now()
	data, err := json.Marshal(payment)
	if err != nil {
		return err
	}
	return abpd.DB.Put([]byte("automated_bill_payment_"+payment.PaymentID), data, nil
}

// DeleteAutomatedBillPayment removes an automated bill payment from the database.
func (abpd *AutomatedBillPaymentsDB) DeleteAutomatedBillPayment(paymentID string) error {
	return abpd.DB.Delete([]byte("automated_bill_payment_"+paymentID), nil)
}

// SearchAutomatedBillPaymentsByBillID retrieves all automated bill payments for a specific bill ID.
func (abpd *AutomatedBillPaymentsDB) SearchAutomatedBillPaymentsByBillID(billID string) ([]AutomatedBillPayment, error) {
	var payments []AutomatedBillPayment
	iter := abpd.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment AutomatedBillPayment
		if err := json.Unmarshal(iter.Value(), &payment); err != nil {
			return nil, err
		}
		if payment.BillID == billID {
			payments = append(payments, payment)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return payments, nil
}

// SearchAutomatedBillPaymentsByPayer retrieves all automated bill payments for a specific payer.
func (abpd *AutomatedBillPaymentsDB) SearchAutomatedBillPaymentsByPayer(payer string) ([]AutomatedBillPayment, error) {
	var payments []AutomatedBillPayment
	iter := abpd.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment AutomatedBillPayment
		if err := json.Unmarshal(iter.Value(), &payment); err != nil {
			return nil, err
		}
		if payment.Payer == payer {
			payments = append(payments, payment)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return payments, nil
}

// SearchAutomatedBillPaymentsByStatus retrieves all automated bill payments by their status.
func (abpd *AutomatedBillPaymentsDB) SearchAutomatedBillPaymentsByStatus(status string) ([]AutomatedBillPayment, error) {
	var payments []AutomatedBillPayment
	iter := abpd.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment AutomatedBillPayment
		if err := json.Unmarshal(iter.Value(), &payment); err != nil {
			return nil, err
		}
		if payment.Status == status {
			payments = append(payments, payment)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return payments, nil
}

// SearchAutomatedBillPaymentsByDateRange retrieves all automated bill payments within a specific date range.
func (abpd *AutomatedBillPaymentsDB) SearchAutomatedBillPaymentsByDateRange(startDate, endDate time.Time) ([]AutomatedBillPayment, error) {
	var payments []AutomatedBillPayment
	iter := abpd.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var payment AutomatedBillPayment
		if err := json.Unmarshal(iter.Value(), &payment); err != nil {
			return nil, err
		}
		if payment.CreatedAt.After(startDate) && payment.CreatedAt.Before(endDate) {
			payments = append(payments, payment)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return payments, nil
}

// ExecuteAutomatedPayments executes all pending automated payments.
func (abpd *AutomatedBillPaymentsDB) ExecuteAutomatedPayments() error {
	payments, err := abpd.SearchAutomatedBillPaymentsByStatus("Pending")
	if err != nil {
		return err
	}

	for _, payment := range payments {
		// Logic to process the payment goes here.
		// E.g., interacting with a payment gateway, updating bill status, etc.

		// For demonstration, we assume the payment is successful:
		payment.Status = "Completed"
		payment.ModifiedAt = time.Now()

		// Update the payment status in the database.
		if err := abpd.UpdateAutomatedBillPayment(payment); err != nil {
			return err
		}
	}

	return nil
}
