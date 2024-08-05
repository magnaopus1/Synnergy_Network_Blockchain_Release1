// Package management provides functionality for managing smart contracts within the SYN4900 Token Standard.
package management

import (
	"errors"
	"time"
	"sync"
)

// SmartContract represents a smart contract deployed on the blockchain.
type SmartContract struct {
	ContractID    string
	Name          string
	Description   string
	Owner         string
	Code          string
	DeploymentDate time.Time
	Status        string
	LastUpdated   time.Time
	ReviewNotes   string
}

// SmartContractManager manages the lifecycle of smart contracts, including deployment, updating, and auditing.
type SmartContractManager struct {
	contracts map[string]SmartContract
	mutex     sync.Mutex
}

// NewSmartContractManager initializes and returns a new SmartContractManager.
func NewSmartContractManager() *SmartContractManager {
	return &SmartContractManager{
		contracts: make(map[string]SmartContract),
	}
}

// DeployContract deploys a new smart contract to the blockchain.
func (scm *SmartContractManager) DeployContract(name, description, owner, code string) (SmartContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Validate inputs
	if name == "" || owner == "" || code == "" {
		return SmartContract{}, errors.New("invalid contract details")
	}

	// Generate a unique contract ID
	contractID := generateContractID(name, owner, time.Now())

	// Create the new smart contract
	contract := SmartContract{
		ContractID:    contractID,
		Name:          name,
		Description:   description,
		Owner:         owner,
		Code:          code,
		DeploymentDate: time.Now(),
		Status:        "Deployed",
		LastUpdated:   time.Now(),
	}

	// Store the contract
	scm.contracts[contractID] = contract

	return contract, nil
}

// UpdateContract updates the details of an existing smart contract.
func (scm *SmartContractManager) UpdateContract(contractID, name, description, code, status, reviewNotes string) (SmartContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	// Retrieve the existing contract
	contract, exists := scm.contracts[contractID]
	if !exists {
		return SmartContract{}, errors.New("contract not found")
	}

	// Update contract details
	if name != "" {
		contract.Name = name
	}
	if description != "" {
		contract.Description = description
	}
	if code != "" {
		contract.Code = code
	}
	if status != "" {
		contract.Status = status
	}
	if reviewNotes != "" {
		contract.ReviewNotes = reviewNotes
	}
	contract.LastUpdated = time.Now()

	// Save the updated contract
	scm.contracts[contractID] = contract

	return contract, nil
}

// GetContract retrieves a smart contract by its ID.
func (scm *SmartContractManager) GetContract(contractID string) (SmartContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return SmartContract{}, errors.New("contract not found")
	}

	return contract, nil
}

// ListContracts returns all smart contracts managed by the system.
func (scm *SmartContractManager) ListContracts() []SmartContract {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contracts := make([]SmartContract, 0)
	for _, contract := range scm.contracts {
		contracts = append(contracts, contract)
	}

	return contracts
}

// generateContractID generates a unique ID for a smart contract based on its name, owner, and deployment date.
func generateContractID(name, owner string, deployedAt time.Time) string {
	return name + "-" + owner + "-" + deployedAt.Format("20060102150405")
}
