package payroll

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

type PaymentOptions struct {
	ledger *ledger.TransactionLedger
}

func NewPaymentOptions(ledger *ledger.TransactionLedger) *PaymentOptions {
	return &PaymentOptions{
		ledger: ledger,
	}
}

// PaymentMethod represents a payment method
type PaymentMethod struct {
	ID          string
	EmployeeID  string
	MethodType  string // e.g., "bank_transfer", "crypto"
	Details     string // encrypted details
	CreatedAt   time.Time
	LastUpdated time.Time
}

// AddPaymentMethod adds a new payment method for an employee
func (po *PaymentOptions) AddPaymentMethod(employeeID, methodType, details string) (string, error) {
	encryptedDetails, err := security.EncryptData(details, security.GenerateSalt(), "Scrypt")
	if err != nil {
		return "", err
	}

	paymentMethod := PaymentMethod{
		ID:          generateID(),
		EmployeeID:  employeeID,
		MethodType:  methodType,
		Details:     encryptedDetails,
		CreatedAt:   time.Now(),
		LastUpdated: time.Now(),
	}

	return paymentMethod.ID, po.ledger.AddPaymentMethod(paymentMethod)
}

// UpdatePaymentMethod updates an existing payment method for an employee
func (po *PaymentOptions) UpdatePaymentMethod(methodID, employeeID, methodType, details string) error {
	encryptedDetails, err := security.EncryptData(details, security.GenerateSalt(), "Scrypt")
	if err != nil {
		return err
	}

	paymentMethod := PaymentMethod{
		ID:          methodID,
		EmployeeID:  employeeID,
		MethodType:  methodType,
		Details:     encryptedDetails,
		LastUpdated: time.Now(),
	}

	return po.ledger.UpdatePaymentMethod(paymentMethod)
}

// RemovePaymentMethod removes a payment method by its ID
func (po *PaymentOptions) RemovePaymentMethod(methodID string) error {
	return po.ledger.RemovePaymentMethod(methodID)
}

// ListPaymentMethods lists all payment methods for a specific employee
func (po *PaymentOptions) ListPaymentMethods(employeeID string) ([]PaymentMethod, error) {
	return po.ledger.GetPaymentMethodsByEmployeeID(employeeID)
}

// GetPaymentMethod retrieves a specific payment method by its ID
func (po *PaymentOptions) GetPaymentMethod(methodID string) (PaymentMethod, error) {
	return po.ledger.GetPaymentMethodByID(methodID)
}

// VerifyPaymentMethod verifies the details of a payment method
func (po *PaymentOptions) VerifyPaymentMethod(methodID, employeeID, methodType, details string) (bool, error) {
	method, err := po.GetPaymentMethod(methodID)
	if err != nil {
		return false, err
	}

	decryptedDetails, err := security.DecryptData(method.Details, "Scrypt")
	if err != nil {
		return false, err
	}

	return method.EmployeeID == employeeID && method.MethodType == methodType && decryptedDetails == details, nil
}

// Generate a unique ID for payment methods (stub implementation)
func generateID() string {
	return "unique-id-stub"
}
