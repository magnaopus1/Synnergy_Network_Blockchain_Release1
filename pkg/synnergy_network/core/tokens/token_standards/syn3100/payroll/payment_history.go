package payroll

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

type PaymentHistory struct {
	ledger *ledger.TransactionLedger
}

func NewPaymentHistory(ledger *ledger.TransactionLedger) *PaymentHistory {
	return &PaymentHistory{
		ledger: ledger,
	}
}

// RecordPayment records a new payment in the transaction ledger
func (ph *PaymentHistory) RecordPayment(contractID, payerID, payeeID string, amount float64, paymentDate time.Time) error {
	payment := ledger.Payment{
		ContractID:  contractID,
		PayerID:     payerID,
		PayeeID:     payeeID,
		Amount:      amount,
		PaymentDate: paymentDate,
		Status:      "completed",
	}

	return ph.ledger.AddPayment(payment)
}

// GetPaymentHistory retrieves the payment history for a specific contract ID
func (ph *PaymentHistory) GetPaymentHistory(contractID string) ([]ledger.Payment, error) {
	return ph.ledger.GetPaymentsByContractID(contractID)
}

// VerifyPayment ensures that a payment exists and matches the provided details
func (ph *PaymentHistory) VerifyPayment(contractID, payerID, payeeID string, amount float64, paymentDate time.Time) (bool, error) {
	payments, err := ph.GetPaymentHistory(contractID)
	if err != nil {
		return false, err
	}

	for _, payment := range payments {
		if payment.PayerID == payerID && payment.PayeeID == payeeID && payment.Amount == amount && payment.PaymentDate.Equal(paymentDate) {
			return true, nil
		}
	}

	return false, errors.New("payment not found or details do not match")
}

// ListPaymentsByEmployee retrieves all payments made to a specific employee ID
func (ph *PaymentHistory) ListPaymentsByEmployee(employeeID string) ([]ledger.Payment, error) {
	return ph.ledger.GetPaymentsByPayeeID(employeeID)
}

// EncryptPaymentDetails encrypts the details of a payment for secure storage
func (ph *PaymentHistory) EncryptPaymentDetails(payment ledger.Payment) (string, error) {
	// Serialize payment details
	data := fmt.Sprintf("%s:%s:%s:%f:%s:%s", payment.ContractID, payment.PayerID, payment.PayeeID, payment.Amount, payment.PaymentDate.Format(time.RFC3339), payment.Status)
	
	// Encrypt serialized data using Scrypt
	encryptedData, err := security.EncryptData(data, security.GenerateSalt(), "Scrypt")
	if err != nil {
		return "", err
	}
	
	return encryptedData, nil
}

// DecryptPaymentDetails decrypts the encrypted details of a payment
func (ph *PaymentHistory) DecryptPaymentDetails(encryptedData string) (ledger.Payment, error) {
	// Decrypt data using Scrypt
	decryptedData, err := security.DecryptData(encryptedData, "Scrypt")
	if err != nil {
		return ledger.Payment{}, err
	}
	
	// Deserialize payment details
	var payment ledger.Payment
	_, err = fmt.Sscanf(decryptedData, "%s:%s:%s:%f:%s:%s", &payment.ContractID, &payment.PayerID, &payment.PayeeID, &payment.Amount, &payment.PaymentDate, &payment.Status)
	if err != nil {
		return ledger.Payment{}, err
	}

	return payment, nil
}
