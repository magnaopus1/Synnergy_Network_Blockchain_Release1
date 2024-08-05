package management

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// EmploymentSmartContract represents a smart contract within the employment framework
type EmploymentSmartContract struct {
	ContractID       string    `json:"contract_id"`
	EmployeeID       string    `json:"employee_id"`
	EmployerID       string    `json:"employer_id"`
	ContractTerms    string    `json:"contract_terms"`
	StartDate        time.Time `json:"start_date"`
	EndDate          time.Time `json:"end_date"`
	Salary           float64   `json:"salary"`
	Benefits         string    `json:"benefits"`
	CreatedBy        string    `json:"created_by"`
	CreationDate     time.Time `json:"creation_date"`
	LastUpdatedBy    string    `json:"last_updated_by"`
	LastUpdatedDate  time.Time `json:"last_updated_date"`
	Active           bool      `json:"active"`
}

// EmploymentSmartContractManager manages smart contracts within the employment framework
type EmploymentSmartContractManager struct {
	contracts map[string]EmploymentSmartContract
	mu        sync.RWMutex
}

// NewEmploymentSmartContractManager initializes a new EmploymentSmartContractManager
func NewEmploymentSmartContractManager() *EmploymentSmartContractManager {
	return &EmploymentSmartContractManager{
		contracts: make(map[string]EmploymentSmartContract),
	}
}

// AddEmploymentSmartContract adds a new employment smart contract
func (scm *EmploymentSmartContractManager) AddEmploymentSmartContract(contractID, employeeID, employerID, contractTerms, createdBy string, startDate, endDate time.Time, salary float64, benefits string) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	if _, exists := scm.contracts[contractID]; exists {
		return errors.New("contract already exists")
	}

	now := time.Now()
	contract := EmploymentSmartContract{
		ContractID:       contractID,
		EmployeeID:       employeeID,
		EmployerID:       employerID,
		ContractTerms:    contractTerms,
		StartDate:        startDate,
		EndDate:          endDate,
		Salary:           salary,
		Benefits:         benefits,
		CreatedBy:        createdBy,
		CreationDate:     now,
		LastUpdatedBy:    createdBy,
		LastUpdatedDate:  now,
		Active:           true,
	}

	scm.contracts[contractID] = contract
	return nil
}

// UpdateEmploymentSmartContract updates an existing employment smart contract
func (scm *EmploymentSmartContractManager) UpdateEmploymentSmartContract(contractID, contractTerms, updatedBy string, startDate, endDate time.Time, salary float64, benefits string) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.ContractTerms = contractTerms
	contract.StartDate = startDate
	contract.EndDate = endDate
	contract.Salary = salary
	contract.Benefits = benefits
	contract.LastUpdatedBy = updatedBy
	contract.LastUpdatedDate = time.Now()

	scm.contracts[contractID] = contract
	return nil
}

// DeactivateEmploymentSmartContract deactivates an existing employment smart contract
func (scm *EmploymentSmartContractManager) DeactivateEmploymentSmartContract(contractID, updatedBy string) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.Active = false
	contract.LastUpdatedBy = updatedBy
	contract.LastUpdatedDate = time.Now()

	scm.contracts[contractID] = contract
	return nil
}

// GetEmploymentSmartContract retrieves an employment smart contract by ID
func (scm *EmploymentSmartContractManager) GetEmploymentSmartContract(contractID string) (EmploymentSmartContract, error) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return EmploymentSmartContract{}, errors.New("contract not found")
	}

	return contract, nil
}

// ListActiveEmploymentSmartContracts lists all active employment smart contracts
func (scm *EmploymentSmartContractManager) ListActiveEmploymentSmartContracts() ([]EmploymentSmartContract, error) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	var activeContracts []EmploymentSmartContract
	for _, contract := range scm.contracts {
		if contract.Active {
			activeContracts = append(activeContracts, contract)
		}
	}

	return activeContracts, nil
}

// ExportContractData exports contract data as JSON for auditing
func (scm *EmploymentSmartContractManager) ExportContractData(contractID string) (string, error) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return "", errors.New("contract not found")
	}

	data, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ImportContractData imports contract data from JSON
func (scm *EmploymentSmartContractManager) ImportContractData(data string) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	var contract EmploymentSmartContract
	err := json.Unmarshal([]byte(data), &contract)
	if err != nil {
		return err
	}

	scm.contracts[contract.ContractID] = contract
	return nil
}

// EncryptContractData encrypts contract data for secure storage
func EncryptContractData(data string, key []byte) (string, error) {
	encryptedData, err := security.Encrypt(data, key)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptContractData decrypts contract data for retrieval
func DecryptContractData(encryptedData string, key []byte) (string, error) {
	decryptedData, err := security.Decrypt(encryptedData, key)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}
