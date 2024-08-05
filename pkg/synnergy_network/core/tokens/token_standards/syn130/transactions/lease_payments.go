package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/contracts"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// LeasePayment represents a lease payment record.
type LeasePayment struct {
	ID             string
	LeaseID        string
	Lessor         string
	Lessee         string
	Amount         float64
	DueDate        time.Time
	PaymentDate    time.Time
	PaymentStatus  string
	TransactionID  string
}

// LeasePaymentManager manages lease payments.
type LeasePaymentManager struct {
	ledger         *ledger.TransactionLedger
	smartContract  *contracts.SmartContract
}

// NewLeasePaymentManager initializes a new LeasePaymentManager.
func NewLeasePaymentManager(ledger *ledger.TransactionLedger, smartContract *contracts.SmartContract) *LeasePaymentManager {
	return &LeasePaymentManager{
		ledger:        ledger,
		smartContract: smartContract,
	}
}

// CreateLeasePayment creates a new lease payment record.
func (lpm *LeasePaymentManager) CreateLeasePayment(leaseID, lessor, lessee string, amount float64, dueDate time.Time) (*LeasePayment, error) {
	if leaseID == "" || lessor == "" || lessee == "" || amount <= 0 || dueDate.IsZero() {
		return nil, errors.New("invalid lease payment details")
	}

	payment := &LeasePayment{
		ID:            utils.GenerateUUID(),
		LeaseID:       leaseID,
		Lessor:        lessor,
		Lessee:        lessee,
		Amount:        amount,
		DueDate:       dueDate,
		PaymentStatus: "Pending",
	}

	// Record the lease payment creation in the transaction ledger
	err := lpm.ledger.RecordTransaction(payment.ID, "LeasePaymentCreation", payment)
	if err != nil {
		return nil, err
	}

	return payment, nil
}

// ProcessLeasePayment processes a lease payment.
func (lpm *LeasePaymentManager) ProcessLeasePayment(paymentID, transactionID string) (*LeasePayment, error) {
	payment, err := lpm.GetLeasePayment(paymentID)
	if err != nil {
		return nil, err
	}

	if payment.PaymentStatus == "Completed" {
		return nil, errors.New("payment already completed")
	}

	payment.PaymentStatus = "Completed"
	payment.PaymentDate = time.Now()
	payment.TransactionID = transactionID

	// Update the payment status in the transaction ledger
	err = lpm.ledger.RecordTransaction(payment.ID, "LeasePaymentProcessing", payment)
	if err != nil {
		return nil, err
	}

	// Execute the smart contract for the lease payment
	err = lpm.smartContract.ExecuteLeasePayment(payment.Lessor, payment.Lessee, payment.Amount)
	if err != nil {
		return nil, err
	}

	return payment, nil
}

// GetLeasePayment retrieves a lease payment record by ID.
func (lpm *LeasePaymentManager) GetLeasePayment(paymentID string) (*LeasePayment, error) {
	var payment LeasePayment
	err := lpm.ledger.GetTransaction(paymentID, &payment)
	if err != nil {
		return nil, err
	}
	return &payment, nil
}

// NotifyLeasePaymentDue sends a notification for upcoming lease payments.
func (lpm *LeasePaymentManager) NotifyLeasePaymentDue(paymentID string) error {
	payment, err := lpm.GetLeasePayment(paymentID)
	if err != nil {
		return err
	}

	if payment.PaymentStatus != "Pending" {
		return errors.New("payment not pending")
	}

	daysUntilDue := time.Until(payment.DueDate).Hours() / 24
	if daysUntilDue <= 3 {
		notification := fmt.Sprintf("Lease payment of %f is due in %d days for lease ID: %s", payment.Amount, int(daysUntilDue), payment.LeaseID)
		err := utils.SendNotification(payment.Lessee, "Lease Payment Due", notification)
		if err != nil {
			return err
		}
	}

	return nil
}

// AutoProcessDuePayments processes due payments automatically.
func (lpm *LeasePaymentManager) AutoProcessDuePayments() error {
	payments, err := lpm.ledger.GetPendingPayments()
	if err != nil {
		return err
	}

	for _, payment := range payments {
		if time.Now().After(payment.DueDate) && payment.PaymentStatus == "Pending" {
			_, err := lpm.ProcessLeasePayment(payment.ID, utils.GenerateUUID())
			if err != nil {
				return err
			}
		}
	}

	return nil
}
