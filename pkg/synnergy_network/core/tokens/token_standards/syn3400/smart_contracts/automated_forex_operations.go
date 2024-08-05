package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ForexSmartContract represents a smart contract for automated Forex operations
type ForexSmartContract struct {
	ContractID       string    `json:"contract_id"`
	Owner            string    `json:"owner"`
	Code             string    `json:"code"`
	DeploymentDate   time.Time `json:"deployment_date"`
	LastUpdatedDate  time.Time `json:"last_updated_date"`
	ActivationStatus bool      `json:"activation_status"`
}

// ForexSmartContractManager manages Forex smart contracts
type ForexSmartContractManager struct {
	Contracts map[string]ForexSmartContract
	mutex     sync.Mutex
}

// NewForexSmartContractManager initializes the ForexSmartContractManager
func NewForexSmartContractManager() *ForexSmartContractManager {
	return &ForexSmartContractManager{
		Contracts: make(map[string]ForexSmartContract),
	}
}

// AddContract adds a new Forex smart contract
func (fscm *ForexSmartContractManager) AddContract(contract ForexSmartContract) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	if _, exists := fscm.Contracts[contract.ContractID]; exists {
		return errors.New("contract already exists")
	}

	fscm.Contracts[contract.ContractID] = contract
	fscm.logContractEvent(contract, "CONTRACT_ADDED")

	return nil
}

// UpdateContract updates an existing Forex smart contract
func (fscm *ForexSmartContractManager) UpdateContract(contract ForexSmartContract) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	if _, exists := fscm.Contracts[contract.ContractID]; !exists {
		return errors.New("contract not found")
	}

	fscm.Contracts[contract.ContractID] = contract
	fscm.logContractEvent(contract, "CONTRACT_UPDATED")

	return nil
}

// ActivateContract activates a Forex smart contract
func (fscm *ForexSmartContractManager) ActivateContract(contractID string) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.ActivationStatus = true
	contract.LastUpdatedDate = time.Now()
	fscm.Contracts[contractID] = contract
	fscm.logContractEvent(contract, "CONTRACT_ACTIVATED")

	return nil
}

// DeactivateContract deactivates a Forex smart contract
func (fscm *ForexSmartContractManager) DeactivateContract(contractID string) error {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.ActivationStatus = false
	contract.LastUpdatedDate = time.Now()
	fscm.Contracts[contractID] = contract
	fscm.logContractEvent(contract, "CONTRACT_DEACTIVATED")

	return nil
}

// GetContract retrieves a Forex smart contract by ID
func (fscm *ForexSmartContractManager) GetContract(contractID string) (ForexSmartContract, error) {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.Contracts[contractID]
	if !exists {
		return ForexSmartContract{}, errors.New("contract not found")
	}

	return contract, nil
}

// ListContracts lists all Forex smart contracts
func (fscm *ForexSmartContractManager) ListContracts() []ForexSmartContract {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contracts := make([]ForexSmartContract, 0, len(fscm.Contracts))
	for _, contract := range fscm.Contracts {
		contracts = append(contracts, contract)
	}
	return contracts
}

// ExecuteContract executes the logic defined in the smart contract code
func (fscm *ForexSmartContractManager) ExecuteContract(contractID string) (string, error) {
	fscm.mutex.Lock()
	defer fscm.mutex.Unlock()

	contract, exists := fscm.Contracts[contractID]
	if !exists {
		return "", errors.New("contract not found")
	}

	if !contract.ActivationStatus {
		return "", errors.New("contract is not activated")
	}

	// Example logic execution (this should be extended with real business logic)
	result := fmt.Sprintf("Executing contract %s owned by %s with code: %s", contract.ContractID, contract.Owner, contract.Code)
	fscm.logContractEvent(contract, "CONTRACT_EXECUTED")

	return result, nil
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
