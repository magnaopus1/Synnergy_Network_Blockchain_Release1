package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// EmploymentContractUI represents the interface for managing employment smart contracts
type EmploymentContractUI struct {
	contractManager *EmploymentSmartContractManager
	userAccess      map[string]string // Maps user IDs to their roles
	mu              sync.RWMutex
}

// NewEmploymentContractUI initializes a new EmploymentContractUI
func NewEmploymentContractUI(contractManager *EmploymentSmartContractManager) *EmploymentContractUI {
	return &EmploymentContractUI{
		contractManager: contractManager,
		userAccess:      make(map[string]string),
	}
}

// AddUser adds a new user with a specific role
func (ui *EmploymentContractUI) AddUser(userID, role string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.userAccess[userID] = role
}

// RemoveUser removes a user
func (ui *EmploymentContractUI) RemoveUser(userID string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	delete(ui.userAccess, userID)
}

// GetRole retrieves the role of a user
func (ui *EmploymentContractUI) GetRole(userID string) (string, error) {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	role, exists := ui.userAccess[userID]
	if !exists {
		return "", errors.New("user not found")
	}
	return role, nil
}

// CreateContract allows a user to create a new employment smart contract
func (ui *EmploymentContractUI) CreateContract(userID, contractID, employeeID, employerID, contractTerms string, startDate, endDate time.Time, salary float64, benefits string) error {
	role, err := ui.GetRole(userID)
	if err != nil {
		return err
	}

	if role != "employer" && role != "admin" {
		return errors.New("insufficient permissions to create a contract")
	}

	return ui.contractManager.AddEmploymentSmartContract(contractID, employeeID, employerID, contractTerms, userID, startDate, endDate, salary, benefits)
}

// UpdateContract allows a user to update an existing employment smart contract
func (ui *EmploymentContractUI) UpdateContract(userID, contractID, contractTerms string, startDate, endDate time.Time, salary float64, benefits string) error {
	role, err := ui.GetRole(userID)
	if err != nil {
		return err
	}

	if role != "employer" && role != "admin" {
		return errors.New("insufficient permissions to update a contract")
	}

	return ui.contractManager.UpdateEmploymentSmartContract(contractID, contractTerms, userID, startDate, endDate, salary, benefits)
}

// DeactivateContract allows a user to deactivate an employment smart contract
func (ui *EmploymentContractUI) DeactivateContract(userID, contractID string) error {
	role, err := ui.GetRole(userID)
	if err != nil {
		return err
	}

	if role != "employer" && role != "admin" {
		return errors.New("insufficient permissions to deactivate a contract")
	}

	return ui.contractManager.DeactivateEmploymentSmartContract(contractID, userID)
}

// ViewContract allows a user to view an employment smart contract
func (ui *EmploymentContractUI) ViewContract(userID, contractID string) (EmploymentSmartContract, error) {
	role, err := ui.GetRole(userID)
	if err != nil {
		return EmploymentSmartContract{}, err
	}

	if role != "employer" && role != "employee" && role != "admin" {
		return EmploymentSmartContract{}, errors.New("insufficient permissions to view a contract")
	}

	return ui.contractManager.GetEmploymentSmartContract(contractID)
}

// ListActiveContracts allows a user to list all active employment smart contracts
func (ui *EmploymentContractUI) ListActiveContracts(userID string) ([]EmploymentSmartContract, error) {
	role, err := ui.GetRole(userID)
	if err != nil {
		return nil, err
	}

	if role != "employer" && role != "admin" {
		return nil, errors.New("insufficient permissions to list active contracts")
	}

	return ui.contractManager.ListActiveEmploymentSmartContracts()
}

// ExportContract allows a user to export an employment smart contract for auditing
func (ui *EmploymentContractUI) ExportContract(userID, contractID string) (string, error) {
	role, err := ui.GetRole(userID)
	if err != nil {
		return "", err
	}

	if role != "admin" {
		return "", errors.New("insufficient permissions to export a contract")
	}

	return ui.contractManager.ExportContractData(contractID)
}

// ImportContract allows a user to import an employment smart contract from JSON data
func (ui *EmploymentContractUI) ImportContract(userID, data string) error {
	role, err := ui.GetRole(userID)
	if err != nil {
		return err
	}

	if role != "admin" {
		return errors.New("insufficient permissions to import a contract")
	}

	return ui.contractManager.ImportContractData(data)
}

// EncryptContract allows a user to encrypt an employment smart contract's data
func (ui *EmploymentContractUI) EncryptContract(userID, data string, key []byte) (string, error) {
	role, err := ui.GetRole(userID)
	if err != nil {
		return "", err
	}

	if role != "admin" {
		return "", errors.New("insufficient permissions to encrypt a contract")
	}

	return EncryptContractData(data, key)
}

// DecryptContract allows a user to decrypt an employment smart contract's data
func (ui *EmploymentContractUI) DecryptContract(userID, encryptedData string, key []byte) (string, error) {
	role, err := ui.GetRole(userID)
	if err != nil {
		return "", err
	}

	if role != "admin" {
		return "", errors.New("insufficient permissions to decrypt a contract")
	}

	return DecryptContractData(encryptedData, key)
}

// Function to convert contract data to JSON
func (ui *EmploymentContractUI) contractToJSON(contract EmploymentSmartContract) (string, error) {
	data, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Function to parse JSON data into contract
func (ui *EmploymentContractUI) jsonToContract(data string) (EmploymentSmartContract, error) {
	var contract EmploymentSmartContract
	err := json.Unmarshal([]byte(data), &contract)
	if err != nil {
		return EmploymentSmartContract{}, err
	}
	return contract, nil
}
