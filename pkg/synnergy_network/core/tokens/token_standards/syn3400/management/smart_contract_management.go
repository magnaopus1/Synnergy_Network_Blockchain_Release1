package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ForexSmartContract represents a smart contract for managing Forex trading
type ForexSmartContract struct {
	ContractID       string    `json:"contract_id"`
	Owner            string    `json:"owner"`
	Code             string    `json:"code"`
	DeploymentDate   time.Time `json:"deployment_date"`
	LastUpdatedDate  time.Time `json:"last_updated_date"`
	ActivationStatus bool      `json:"activation_status"`
}

// ForexSmartContractManager manages smart contracts for SYN3400 tokens
type ForexSmartContractManager struct {
	contracts map[string]ForexSmartContract
	mutex     sync.Mutex
}

// NewForexSmartContractManager initializes the ForexSmartContractManager structure
func NewForexSmartContractManager() *ForexSmartContractManager {
	return &ForexSmartContractManager{
		contracts: make(map[string]ForexSmartContract),
	}
}

// AddContract adds a new smart contract to the manager
func (fscm *ForexSmartContractManager) AddContract(contract ForexSmartContract) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	if _, exists := fscm.contracts[contract.ContractID]; exists {
		return errors.New("contract already exists")
	}

	contract.DeploymentDate = time.Now()
	contract.LastUpdatedDate = time.Now()
	fscm.contracts[contract.ContractID] = contract

	// Log the contract addition
	fscm.logContractEvent(contract, "CONTRACT_ADDED")

	return nil
}

// UpdateContract updates an existing smart contract in the manager
func (fscm *ForexSmartContractManager) UpdateContract(contract ForexSmartContract) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	if _, exists := fscm.contracts[contract.ContractID]; !exists {
		return errors.New("contract not found")
	}

	contract.LastUpdatedDate = time.Now()
	fscm.contracts[contract.ContractID] = contract

	// Log the contract update
	fscm.logContractEvent(contract, "CONTRACT_UPDATED")

	return nil
}

// GetContract retrieves a smart contract from the manager
func (fscm *ForexSmartContractManager) GetContract(contractID string) (ForexSmartContract, error) {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.contracts[contractID]
	if !exists {
		return ForexSmartContract{}, errors.New("contract not found")
	}

	return contract, nil
}

// ActivateContract activates a smart contract
func (fscm *ForexSmartContractManager) ActivateContract(contractID string) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	if contract.ActivationStatus {
		return errors.New("contract already activated")
	}

	contract.ActivationStatus = true
	contract.LastUpdatedDate = time.Now()
	fscm.contracts[contractID] = contract

	// Log the contract activation
	fscm.logContractEvent(contract, "CONTRACT_ACTIVATED")

	return nil
}

// DeactivateContract deactivates a smart contract
func (fscm *ForexSmartContractManager) DeactivateContract(contractID string) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	if !contract.ActivationStatus {
		return errors.New("contract already deactivated")
	}

	contract.ActivationStatus = false
	contract.LastUpdatedDate = time.Now()
	fscm.contracts[contractID] = contract

	// Log the contract deactivation
	fscm.logContractEvent(contract, "CONTRACT_DEACTIVATED")

	return nil
}

// logContractEvent logs events related to smart contracts
func (fscm *ForexSmartContractManager) logContractEvent(contract ForexSmartContract, eventType string) {
	event := map[string]interface{}{
		"event_type":      eventType,
		"contract_id":     contract.ContractID,
		"owner":           contract.Owner,
		"timestamp":       time.Now().UTC(),
		"activation_status": contract.ActivationStatus,
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}

// ListContracts lists all smart contracts managed
func (fscm *ForexSmartContractManager) ListContracts() []ForexSmartContract {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contracts := make([]ForexSmartContract, 0, len(fscm.contracts))
	for _, contract := range fscm.contracts {
		contracts = append(contracts, contract)
	}
	return contracts
}
