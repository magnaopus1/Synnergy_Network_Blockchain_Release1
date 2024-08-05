package payroll

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/smart_contracts"
)

type AutomatedSalaryPayments struct {
	ledger          *ledger.TransactionLedger
	contractManager *smart_contracts.EmploymentSmartContractManager
	mu              sync.Mutex
}

func NewAutomatedSalaryPayments(ledger *ledger.TransactionLedger, contractManager *smart_contracts.EmploymentSmartContractManager) *AutomatedSalaryPayments {
	return &AutomatedSalaryPayments{
		ledger:          ledger,
		contractManager: contractManager,
	}
}

func (asp *AutomatedSalaryPayments) SchedulePayment(contractID, payerID string, paymentDate time.Time) error {
	asp.mu.Lock()
	defer asp.mu.Unlock()

	contract, err := asp.contractManager.GetEmploymentSmartContract(contractID)
	if err != nil {
		return err
	}

	if contract.Status != "active" {
		return errors.New("contract is not active")
	}

	amount := contract.Salary
	payment := ledger.Payment{
		ContractID:  contractID,
		PayerID:     payerID,
		PayeeID:     contract.EmployeeID,
		Amount:      amount,
		PaymentDate: paymentDate,
		Status:      "scheduled",
	}

	return asp.ledger.AddPayment(payment)
}

func (asp *AutomatedSalaryPayments) ProcessScheduledPayments(currentTime time.Time) error {
	asp.mu.Lock()
	defer asp.mu.Unlock()

	payments, err := asp.ledger.GetScheduledPayments()
	if err != nil {
		return err
	}

	for _, payment := range payments {
		if payment.PaymentDate.Before(currentTime) || payment.PaymentDate.Equal(currentTime) {
			if err := asp.executePayment(payment); err != nil {
				return err
			}
		}
	}

	return nil
}

func (asp *AutomatedSalaryPayments) executePayment(payment ledger.Payment) error {
	contract, err := asp.contractManager.GetEmploymentSmartContract(payment.ContractID)
	if err != nil {
		return err
	}

	if contract.Status != "active" {
		return errors.New("contract is not active")
	}

	if err := security.ValidateFunds(payment.PayerID, payment.Amount); err != nil {
		return err
	}

	transaction := ledger.Transaction{
		ContractID: payment.ContractID,
		FromID:     payment.PayerID,
		ToID:       payment.PayeeID,
		Amount:     payment.Amount,
		Timestamp:  time.Now(),
		Status:     "completed",
	}

	if err := asp.ledger.AddTransaction(transaction); err != nil {
		return err
	}

	payment.Status = "completed"
	return asp.ledger.UpdatePayment(payment)
}

func (asp *AutomatedSalaryPayments) GetPaymentHistory(contractID string) ([]ledger.Payment, error) {
	return asp.ledger.GetPaymentsByContractID(contractID)
}
