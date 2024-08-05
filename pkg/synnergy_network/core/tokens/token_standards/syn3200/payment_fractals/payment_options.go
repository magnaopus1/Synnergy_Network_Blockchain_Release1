package payment_fractals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// PaymentOption represents an available payment option for a bill.
type PaymentOption struct {
	OptionID   string    `json:"option_id"`
	BillID     string    `json:"bill_id"`
	Payer      string    `json:"payer"`
	Amount     float64   `json:"amount"`
	DueDate    time.Time `json:"due_date"`
	Status     string    `json:"status"` // Pending, Completed, Cancelled
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

// PaymentOptionsDB represents the database for managing payment options.
type PaymentOptionsDB struct {
	DB *leveldb.DB
}

// NewPaymentOptionsDB creates a new PaymentOptionsDB instance.
func NewPaymentOptionsDB(dbPath string) (*PaymentOptionsDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &PaymentOptionsDB{DB: db}, nil
}

// CloseDB closes the database connection.
func (podb *PaymentOptionsDB) CloseDB() error {
	return podb.DB.Close()
}

// AddPaymentOption adds a new payment option to the database.
func (podb *PaymentOptionsDB) AddPaymentOption(option PaymentOption) error {
	if err := podr.ValidatePaymentOption(option); err != nil {
		return err
	}
	data, err := json.Marshal(option)
	if err != nil {
		return err
	}
	return podb.DB.Put([]byte("payment_option_"+option.OptionID), data, nil)
}

// GetPaymentOption retrieves a payment option by its option ID.
func (podb *PaymentOptionsDB) GetPaymentOption(optionID string) (*PaymentOption, error) {
	data, err := podb.DB.Get([]byte("payment_option_"+optionID), nil)
	if err != nil {
		return nil, err
	}
	var option PaymentOption
	if err := json.Unmarshal(data, &option); err != nil {
		return nil, err
	}
	return &option, nil
}

// GetAllPaymentOptions retrieves all payment options from the database.
func (podb *PaymentOptionsDB) GetAllPaymentOptions() ([]PaymentOption, error) {
	var options []PaymentOption
	iter := podb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var option PaymentOption
		if err := json.Unmarshal(iter.Value(), &option); err != nil {
			return nil, err
		}
		options = append(options, option)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return options, nil
}

// ValidatePaymentOption ensures the payment option is valid before adding it to the database.
func (podb *PaymentOptionsDB) ValidatePaymentOption(option PaymentOption) error {
	if option.OptionID == "" {
		return errors.New("option ID must be provided")
	}
	if option.BillID == "" {
		return errors.New("bill ID must be provided")
	}
	if option.Payer == "" {
		return errors.New("payer must be provided")
	}
	if option.Amount <= 0 {
		return errors.New("amount must be greater than zero")
	}
	if option.DueDate.IsZero() {
		return errors.New("due date must be provided")
	}
	if option.Status == "" {
		return errors.New("status must be provided")
	}
	return nil
}

// UpdatePaymentOption updates an existing payment option in the database.
func (podb *PaymentOptionsDB) UpdatePaymentOption(option PaymentOption) error {
	if _, err := podb.GetPaymentOption(option.OptionID); err != nil {
		return err
	}
	if err := podb.ValidatePaymentOption(option); err != nil {
		return err
	}
	option.ModifiedAt = time.Now()
	data, err := json.Marshal(option)
	if err != nil {
		return err
	}
	return podb.DB.Put([]byte("payment_option_"+option.OptionID), data, nil)
}

// DeletePaymentOption removes a payment option from the database.
func (podb *PaymentOptionsDB) DeletePaymentOption(optionID string) error {
	return podb.DB.Delete([]byte("payment_option_"+optionID), nil)
}

// SearchPaymentOptionsByBillID retrieves all payment options for a specific bill ID.
func (podb *PaymentOptionsDB) SearchPaymentOptionsByBillID(billID string) ([]PaymentOption, error) {
	var options []PaymentOption
	iter := podb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var option PaymentOption
		if err := json.Unmarshal(iter.Value(), &option); err != nil {
			return nil, err
		}
		if option.BillID == billID {
			options = append(options, option)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return options, nil
}

// SearchPaymentOptionsByPayer retrieves all payment options for a specific payer.
func (podb *PaymentOptionsDB) SearchPaymentOptionsByPayer(payer string) ([]PaymentOption, error) {
	var options []PaymentOption
	iter := podb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var option PaymentOption
		if err := json.Unmarshal(iter.Value(), &option); err != nil {
			return nil, err
		}
		if option.Payer == payer {
			options = append(options, option)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return options, nil
}

// SearchPaymentOptionsByStatus retrieves all payment options by their status.
func (podb *PaymentOptionsDB) SearchPaymentOptionsByStatus(status string) ([]PaymentOption, error) {
	var options []PaymentOption
	iter := podb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var option PaymentOption
		if err := json.Unmarshal(iter.Value(), &option); err != nil {
			return nil, err
		}
		if option.Status == status {
			options = append(options, option)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return options, nil
}

// SearchPaymentOptionsByDateRange retrieves all payment options within a specific date range.
func (podb *PaymentOptionsDB) SearchPaymentOptionsByDateRange(startDate, endDate time.Time) ([]PaymentOption, error) {
	var options []PaymentOption
	iter := podb.DB.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		var option PaymentOption
		if err := json.Unmarshal(iter.Value(), &option); err != nil {
			return nil, err
		}
		if option.CreatedAt.After(startDate) && option.CreatedAt.Before(endDate) {
			options = append(options, option)
		}
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return options, nil
}
