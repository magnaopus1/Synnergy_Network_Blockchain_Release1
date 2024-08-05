package payroll

import (
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/smart_contracts"
)

type BonusManagement struct {
	ledger          *ledger.TransactionLedger
	contractManager *smart_contracts.EmploymentSmartContractManager
	mu              sync.Mutex
}

func NewBonusManagement(ledger *ledger.TransactionLedger, contractManager *smart_contracts.EmploymentSmartContractManager) *BonusManagement {
	return &BonusManagement{
		ledger:          ledger,
		contractManager: contractManager,
	}
}

func (bm *BonusManagement) ScheduleBonus(contractID, payerID string, bonusAmount float64, paymentDate time.Time) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	contract, err := bm.contractManager.GetEmploymentSmartContract(contractID)
	if err != nil {
		return err
	}

	if contract.Status != "active" {
		return errors.New("contract is not active")
	}

	bonus := ledger.Payment{
		ContractID:  contractID,
		PayerID:     payerID,
		PayeeID:     contract.EmployeeID,
		Amount:      bonusAmount,
		PaymentDate: paymentDate,
		Status:      "scheduled",
	}

	return bm.ledger.AddPayment(bonus)
}

func (bm *BonusManagement) ProcessScheduledBonuses(currentTime time.Time) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bonuses, err := bm.ledger.GetScheduledPayments()
	if err != nil {
		return err
	}

	for _, bonus := range bonuses {
		if bonus.PaymentDate.Before(currentTime) || bonus.PaymentDate.Equal(currentTime) {
			if err := bm.executeBonus(bonus); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bm *BonusManagement) executeBonus(bonus ledger.Payment) error {
	contract, err := bm.contractManager.GetEmploymentSmartContract(bonus.ContractID)
	if err != nil {
		return err
	}

	if contract.Status != "active" {
		return errors.New("contract is not active")
	}

	if err := security.ValidateFunds(bonus.PayerID, bonus.Amount); err != nil {
		return err
	}

	transaction := ledger.Transaction{
		ContractID: bonus.ContractID,
		FromID:     bonus.PayerID,
		ToID:       bonus.PayeeID,
		Amount:     bonus.Amount,
		Timestamp:  time.Now(),
		Status:     "completed",
	}

	if err := bm.ledger.AddTransaction(transaction); err != nil {
		return err
	}

	bonus.Status = "completed"
	return bm.ledger.UpdatePayment(bonus)
}

func (bm *BonusManagement) GetBonusHistory(contractID string) ([]ledger.Payment, error) {
	return bm.ledger.GetPaymentsByContractID(contractID)
}
