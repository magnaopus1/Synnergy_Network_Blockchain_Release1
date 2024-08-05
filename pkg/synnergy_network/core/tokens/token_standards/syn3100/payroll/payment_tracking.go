package payroll

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// PaymentTracking manages the tracking of payments
type PaymentTracking struct {
	ledger *ledger.TransactionLedger
}

// NewPaymentTracking initializes a new PaymentTracking instance
func NewPaymentTracking(ledger *ledger.TransactionLedger) *PaymentTracking {
	return &PaymentTracking{
		ledger: ledger,
	}
}

// PaymentStatus represents the status of a payment
type PaymentStatus struct {
	ID          string
	TransactionID string
	Status      string    // e.g., "pending", "completed", "failed"
	Details     string    // encrypted details
	Timestamp   time.Time
}

// AddPaymentStatus adds a new payment status
func (pt *PaymentTracking) AddPaymentStatus(transactionID, status, details string) (string, error) {
	encryptedDetails, err := security.EncryptData(details, security.GenerateSalt(), "Scrypt")
	if err != nil {
		return "", err
	}

	paymentStatus := PaymentStatus{
		ID:            generateID(),
		TransactionID: transactionID,
		Status:        status,
		Details:       encryptedDetails,
		Timestamp:     time.Now(),
	}

	return paymentStatus.ID, pt.ledger.AddPaymentStatus(paymentStatus)
}

// UpdatePaymentStatus updates the status of an existing payment
func (pt *PaymentTracking) UpdatePaymentStatus(statusID, transactionID, status, details string) error {
	encryptedDetails, err := security.EncryptData(details, security.GenerateSalt(), "Scrypt")
	if err != nil {
		return err
	}

	paymentStatus := PaymentStatus{
		ID:            statusID,
		TransactionID: transactionID,
		Status:        status,
		Details:       encryptedDetails,
		Timestamp:     time.Now(),
	}

	return pt.ledger.UpdatePaymentStatus(paymentStatus)
}

// GetPaymentStatus retrieves the status of a payment by its ID
func (pt *PaymentTracking) GetPaymentStatus(statusID string) (PaymentStatus, error) {
	return pt.ledger.GetPaymentStatusByID(statusID)
}

// ListPaymentStatuses lists all payment statuses for a specific transaction
func (pt *PaymentTracking) ListPaymentStatuses(transactionID string) ([]PaymentStatus, error) {
	return pt.ledger.GetPaymentStatusesByTransactionID(transactionID)
}

// VerifyPaymentStatus verifies the details of a payment status
func (pt *PaymentTracking) VerifyPaymentStatus(statusID, transactionID, status, details string) (bool, error) {
	paymentStatus, err := pt.GetPaymentStatus(statusID)
	if err != nil {
		return false, err
	}

	decryptedDetails, err := security.DecryptData(paymentStatus.Details, "Scrypt")
	if err != nil {
		return false, err
	}

	return paymentStatus.TransactionID == transactionID && paymentStatus.Status == status && decryptedDetails == details, nil
}

// Generate a unique ID for payment statuses (stub implementation)
func generateID() string {
	return "unique-id-stub"
}
