package management

import (
	"fmt"
	"time"

	"github.com/synnergy_network/blockchain/ledger"
	"github.com/synnergy_network/blockchain/payments"
	"github.com/synnergy_network/blockchain/smart_contracts"
)

// SmartContractManager handles the creation, deployment, and management of smart contracts
type SmartContractManager struct {
	Ledger        ledger.Ledger
	PaymentSystem payments.PaymentSystem
}

// NewSmartContractManager constructor
func NewSmartContractManager(ledger ledger.Ledger, paymentSystem payments.PaymentSystem) *SmartContractManager {
	return &SmartContractManager{
		Ledger:        ledger,
		PaymentSystem: paymentSystem,
	}
}

// DeployRentalAgreement deploys a new smart contract for a rental agreement
func (scm *SmartContractManager) DeployRentalAgreement(tokenID, propertyID, tenantID string, rent float64, startDate, endDate time.Time, deposit float64) (string, error) {
	contractID := generateContractID()
	timestamp := time.Now()

	contract := smart_contracts.RentalAgreement{
		ContractID: contractID,
		TokenID:    tokenID,
		PropertyID: propertyID,
		TenantID:   tenantID,
		Rent:       rent,
		StartDate:  startDate,
		EndDate:    endDate,
		Deposit:    deposit,
		Status:     "Active",
		CreatedAt:  timestamp,
		UpdatedAt:  timestamp,
	}

	if err := scm.Ledger.SaveContract(contract); err != nil {
		return "", fmt.Errorf("error saving contract: %v", err)
	}

	return contractID, nil
}

// UpdateRentalAgreement updates an existing rental agreement smart contract
func (scm *SmartContractManager) UpdateRentalAgreement(contractID, propertyID, tenantID string, rent float64, startDate, endDate time.Time, deposit float64) error {
	contract, err := scm.GetRentalAgreement(contractID)
	if err != nil {
		return err
	}

	contract.PropertyID = propertyID
	contract.TenantID = tenantID
	contract.Rent = rent
	contract.StartDate = startDate
	contract.EndDate = endDate
	contract.Deposit = deposit
	contract.UpdatedAt = time.Now()

	if err := scm.Ledger.SaveContract(contract); err != nil {
		return fmt.Errorf("error updating contract: %v", err)
	}

	return nil
}

// GetRentalAgreement retrieves a rental agreement smart contract by its ID
func (scm *SmartContractManager) GetRentalAgreement(contractID string) (smart_contracts.RentalAgreement, error) {
	contract, err := scm.Ledger.GetContract(contractID)
	if err != nil {
		return smart_contracts.RentalAgreement{}, fmt.Errorf("error retrieving contract: %v", err)
	}

	return contract, nil
}

// TerminateRentalAgreement terminates an active rental agreement smart contract
func (scm *SmartContractManager) TerminateRentalAgreement(contractID string) error {
	contract, err := scm.GetRentalAgreement(contractID)
	if err != nil {
		return err
	}

	contract.Status = "Terminated"
	contract.UpdatedAt = time.Now()

	if err := scm.Ledger.SaveContract(contract); err != nil {
		return fmt.Errorf("error terminating contract: %v", err)
	}

	return nil
}

// ProcessAutomatedRentPayment processes automated rent payments based on the rental agreement smart contract
func (scm *SmartContractManager) ProcessAutomatedRentPayment(contractID string) error {
	contract, err := scm.GetRentalAgreement(contractID)
	if err != nil {
		return err
	}

	if contract.Status != "Active" {
		return fmt.Errorf("contract is not active")
	}

	currentDate := time.Now()
	if currentDate.After(contract.StartDate) && currentDate.Before(contract.EndDate) {
		payment := payments.PaymentRecord{
			TokenID:   contract.TokenID,
			Amount:    contract.Rent,
			Timestamp: currentDate,
			Type:      "Rent Payment",
		}

		if err := scm.PaymentSystem.ProcessPayment(payment); err != nil {
			return fmt.Errorf("error processing rent payment: %v", err)
		}

		if err := scm.Ledger.StorePayment(contract.TokenID, payment); err != nil {
			return fmt.Errorf("error storing rent payment: %v", err)
		}
	}

	return nil
}

// EnforceConditionalContractEnforcement enforces conditional terms of a rental agreement smart contract
func (scm *SmartContractManager) EnforceConditionalContractEnforcement(contractID string) error {
	contract, err := scm.GetRentalAgreement(contractID)
	if err != nil {
		return err
	}

	// Example conditional enforcement logic: Check if rent is overdue
	currentDate := time.Now()
	if currentDate.After(contract.StartDate) && currentDate.Before(contract.EndDate) {
		lastPaymentDate := scm.Ledger.GetLastPaymentDate(contract.TokenID)
		if lastPaymentDate.AddDate(0, 0, 30).Before(currentDate) { // Assuming monthly rent
			contract.Status = "Overdue"
			contract.UpdatedAt = currentDate

			if err := scm.Ledger.SaveContract(contract); err != nil {
				return fmt.Errorf("error updating contract status to overdue: %v", err)
			}
		}
	}

	return nil
}

// generateContractID generates a unique ID for a smart contract
func generateContractID() string {
	return fmt.Sprintf("CONTRACT-%d", time.Now().UnixNano())
}
