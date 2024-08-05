package smart_contracts

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/assets"
)

// FairContractAllocation handles the allocation of employment contracts fairly using blockchain technology
type FairContractAllocation struct {
	ledger *ledger.TransactionLedger
	security *security.SecurityManager
}

// NewFairContractAllocation initializes a new FairContractAllocation instance
func NewFairContractAllocation(ledger *ledger.TransactionLedger, security *security.SecurityManager) *FairContractAllocation {
	return &FairContractAllocation{
		ledger: ledger,
		security: security,
	}
}

// AllocateContract allocates an employment contract fairly to an employee
func (fca *FairContractAllocation) AllocateContract(contractID, employeeID, employerID string) error {
	// Check if contract exists
	contract, err := fca.ledger.GetEmploymentContractByID(contractID)
	if err != nil {
		return err
	}

	// Check if the contract is already allocated
	if contract.EmployeeID != "" {
		return errors.New("contract already allocated to another employee")
	}

	// Verify the employee and employer exist
	_, err = fca.ledger.GetEmployeeByID(employeeID)
	if err != nil {
		return err
	}

	_, err = fca.ledger.GetEmployerByID(employerID)
	if err != nil {
		return err
	}

	// Allocate the contract
	contract.EmployeeID = employeeID
	contract.EmployerID = employerID
	contract.StartDate = time.Now()

	// Update the contract in the ledger
	err = fca.ledger.UpdateEmploymentContract(contract)
	if err != nil {
		return err
	}

	// Generate the token for the employee
	tokenID, err := fca.security.GenerateEmploymentToken(contractID, employeeID)
	if err != nil {
		return err
	}

	// Link the contract to the generated token
	link := assets.NewContractLinking(contractID, tokenID)
	err = fca.ledger.AddContractLink(link)
	if err != nil {
		return err
	}

	return nil
}

// ReallocateContract reallocates an employment contract to another employee
func (fca *FairContractAllocation) ReallocateContract(contractID, newEmployeeID string) error {
	// Check if contract exists
	contract, err := fca.ledger.GetEmploymentContractByID(contractID)
	if err != nil {
		return err
	}

	// Verify the new employee exists
	_, err = fca.ledger.GetEmployeeByID(newEmployeeID)
	if err != nil {
		return err
	}

	// Check if the contract can be reallocated
	if contract.EndDate.Before(time.Now()) {
		return errors.New("contract has already ended and cannot be reallocated")
	}

	// Reallocate the contract
	contract.EmployeeID = newEmployeeID

	// Update the contract in the ledger
	err = fca.ledger.UpdateEmploymentContract(contract)
	if err != nil {
		return err
	}

	// Generate the token for the new employee
	tokenID, err := fca.security.GenerateEmploymentToken(contractID, newEmployeeID)
	if err != nil {
		return err
	}

	// Update the contract link to the new token
	link := assets.NewContractLinking(contractID, tokenID)
	err = fca.ledger.UpdateContractLink(link)
	if err != nil {
		return err
	}

	return nil
}

// TerminateContract terminates an employment contract
func (fca *FairContractAllocation) TerminateContract(contractID string) error {
	// Check if contract exists
	contract, err := fca.ledger.GetEmploymentContractByID(contractID)
	if err != nil {
		return err
	}

	// Set the contract end date
	contract.EndDate = time.Now()

	// Update the contract in the ledger
	return fca.ledger.UpdateEmploymentContract(contract)
}

// GetContractDetails retrieves details of an employment contract
func (fca *FairContractAllocation) GetContractDetails(contractID string) (*ledger.EmploymentContract, error) {
	return fca.ledger.GetEmploymentContractByID(contractID)
}

// ListAllocatedContracts lists all allocated contracts for a given employer
func (fca *FairContractAllocation) ListAllocatedContracts(employerID string) ([]ledger.EmploymentContract, error) {
	return fca.ledger.GetContractsByEmployerID(employerID)
}

// ListEmployeeContracts lists all contracts for a given employee
func (fca *FairContractAllocation) ListEmployeeContracts(employeeID string) ([]ledger.EmploymentContract, error) {
	return fca.ledger.GetContractsByEmployeeID(employeeID)
}

// GetContractConditions retrieves the conditions of an employment contract
func (fca *FairContractAllocation) GetContractConditions(contractID string) ([]assets.ContractCondition, error) {
	contract, err := fca.ledger.GetEmploymentContractByID(contractID)
	if err != nil {
		return nil, err
	}
	return contract.Conditions, nil
}
