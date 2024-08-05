package payments

import (
	"errors"
	"time"

	"github.com/synnergy_network/blockchain/assets"
	"github.com/synnergy_network/blockchain/events"
	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/transactions"
	"golang.org/x/crypto/scrypt"
)

// AutomatedRentPayments handles the automation of rent payments via smart contracts
type AutomatedRentPayments struct {
	Ledger            ledger.Ledger
	AssetManager      assets.AssetManager
	EventLogger       events.EventLogger
	TransactionSystem transactions.TransactionSystem
}

// NewAutomatedRentPayments creates a new instance of AutomatedRentPayments
func NewAutomatedRentPayments(ledger ledger.Ledger, assetManager assets.AssetManager, eventLogger events.EventLogger, transactionSystem transactions.TransactionSystem) *AutomatedRentPayments {
	return &AutomatedRentPayments{
		Ledger:            ledger,
		AssetManager:      assetManager,
		EventLogger:       eventLogger,
		TransactionSystem: transactionSystem,
	}
}

// ProcessMonthlyRent handles the processing of monthly rent payments
func (arp *AutomatedRentPayments) ProcessMonthlyRent(tokenID string) error {
	rentalToken, err := arp.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	if !rentalToken.ActiveStatus {
		return errors.New("rental token is not active")
	}

	payment := PaymentRecord{
		TokenID:   tokenID,
		Amount:    rentalToken.MonthlyRent,
		Timestamp: time.Now(),
		Type:      "Rent Payment",
	}

	if err := arp.TransactionSystem.ProcessPayment(payment); err != nil {
		return err
	}

	if err := arp.Ledger.StorePayment(tokenID, payment); err != nil {
		return err
	}

	arp.EventLogger.LogEvent(events.Event{
		Type:      "RentPaid",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "amount": rentalToken.MonthlyRent},
	})

	return nil
}

// SetupRecurringPayments sets up recurring rent payments for a given rental token
func (arp *AutomatedRentPayments) SetupRecurringPayments(tokenID string, startDate, endDate time.Time) error {
	rentalToken, err := arp.AssetManager.GetRentalToken(tokenID)
	if err != nil {
		return err
	}

	if !rentalToken.ActiveStatus {
		return errors.New("rental token is not active")
	}

	// Create a recurring payment schedule
	recurringPayment := RecurringPayment{
		TokenID:    tokenID,
		StartDate:  startDate,
		EndDate:    endDate,
		Amount:     rentalToken.MonthlyRent,
		LastPaid:   startDate,
		NextDue:    startDate.AddDate(0, 1, 0),
		Active:     true,
		CreateTime: time.Now(),
	}

	// Store the recurring payment schedule in the ledger
	if err := arp.Ledger.StoreRecurringPayment(recurringPayment); err != nil {
		return err
	}

	arp.EventLogger.LogEvent(events.Event{
		Type:      "RecurringPaymentSetup",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"tokenID": tokenID, "startDate": startDate, "endDate": endDate},
	})

	return nil
}

// ProcessRecurringPayments processes all due recurring payments
func (arp *AutomatedRentPayments) ProcessRecurringPayments() error {
	recurringPayments, err := arp.Ledger.GetDueRecurringPayments(time.Now())
	if err != nil {
		return err
	}

	for _, recurringPayment := range recurringPayments {
		if err := arp.ProcessMonthlyRent(recurringPayment.TokenID); err != nil {
			return err
		}

		// Update the recurring payment schedule
		recurringPayment.LastPaid = time.Now()
		recurringPayment.NextDue = recurringPayment.NextDue.AddDate(0, 1, 0)
		if err := arp.Ledger.UpdateRecurringPayment(recurringPayment); err != nil {
			return err
		}
	}

	return nil
}

// PaymentRecord represents a payment transaction
type PaymentRecord struct {
	TokenID   string
	Amount    float64
	Timestamp time.Time
	Type      string
}

// RecurringPayment represents a recurring payment schedule
type RecurringPayment struct {
	TokenID    string
	StartDate  time.Time
	EndDate    time.Time
	Amount     float64
	LastPaid   time.Time
	NextDue    time.Time
	Active     bool
	CreateTime time.Time
}

// encryptPassword encrypts a password using scrypt
func encryptPassword(password, salt []byte) ([]byte, error) {
	const N = 32768
	const r = 8
	const p = 1
	const keyLen = 32

	dk, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}

	return dk, nil
}
