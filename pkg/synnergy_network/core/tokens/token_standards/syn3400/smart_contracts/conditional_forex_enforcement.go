package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ConditionalForexEnforcement represents a conditional enforcement mechanism for Forex operations
type ConditionalForexEnforcement struct {
	ContractID       string        `json:"contract_id"`
	Owner            string        `json:"owner"`
	Conditions       []Condition   `json:"conditions"`
	DeploymentDate   time.Time     `json:"deployment_date"`
	LastUpdatedDate  time.Time     `json:"last_updated_date"`
	ActivationStatus bool          `json:"activation_status"`
	mutex            sync.Mutex
}

// Condition represents a single condition in the enforcement mechanism
type Condition struct {
	ConditionID string    `json:"condition_id"`
	Type        string    `json:"type"`        // Type of condition, e.g., "RateThreshold"
	Params      string    `json:"params"`      // JSON-encoded parameters
	CreatedAt   time.Time `json:"created_at"`
}

// ConditionalForexEnforcementManager manages conditional Forex enforcements
type ConditionalForexEnforcementManager struct {
	Contracts map[string]*ConditionalForexEnforcement
	mutex     sync.Mutex
}

// NewConditionalForexEnforcementManager initializes the ConditionalForexEnforcementManager
func NewConditionalForexEnforcementManager() *ConditionalForexEnforcementManager {
	return &ConditionalForexEnforcementManager{
		Contracts: make(map[string]*ConditionalForexEnforcement),
	}
}

// AddContract adds a new conditional Forex enforcement contract
func (cfem *ConditionalForexEnforcementManager) AddContract(contract *ConditionalForexEnforcement) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	if _, exists := cfem.Contracts[contract.ContractID]; exists {
		return errors.New("contract already exists")
	}

	cfem.Contracts[contract.ContractID] = contract
	cfem.logContractEvent(contract, "CONTRACT_ADDED")

	return nil
}

// UpdateContract updates an existing conditional Forex enforcement contract
func (cfem *ConditionalForexEnforcementManager) UpdateContract(contract *ConditionalForexEnforcement) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	if _, exists := cfem.Contracts[contract.ContractID]; !exists {
		return errors.New("contract not found")
	}

	cfem.Contracts[contract.ContractID] = contract
	cfem.logContractEvent(contract, "CONTRACT_UPDATED")

	return nil
}

// ActivateContract activates a conditional Forex enforcement contract
func (cfem *ConditionalForexEnforcementManager) ActivateContract(contractID string) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.ActivationStatus = true
	contract.LastUpdatedDate = time.Now()
	cfem.Contracts[contractID] = contract
	cfem.logContractEvent(contract, "CONTRACT_ACTIVATED")

	return nil
}

// DeactivateContract deactivates a conditional Forex enforcement contract
func (cfem *ConditionalForexEnforcementManager) DeactivateContract(contractID string) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	contract.ActivationStatus = false
	contract.LastUpdatedDate = time.Now()
	cfem.Contracts[contractID] = contract
	cfem.logContractEvent(contract, "CONTRACT_DEACTIVATED")

	return nil
}

// GetContract retrieves a conditional Forex enforcement contract by ID
func (cfem *ConditionalForexEnforcementManager) GetContract(contractID string) (*ConditionalForexEnforcement, error) {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return nil, errors.New("contract not found")
	}

	return contract, nil
}

// ListContracts lists all conditional Forex enforcement contracts
func (cfem *ConditionalForexEnforcementManager) ListContracts() []*ConditionalForexEnforcement {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contracts := make([]*ConditionalForexEnforcement, 0, len(cfem.Contracts))
	for _, contract := range cfem.Contracts {
		contracts = append(contracts, contract)
	}
	return contracts
}

// AddCondition adds a condition to a contract
func (cfem *ConditionalForexEnforcementManager) AddCondition(contractID string, condition Condition) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	condition.ConditionID = generateUniqueID()
	condition.CreatedAt = time.Now()
	contract.Conditions = append(contract.Conditions, condition)
	contract.LastUpdatedDate = time.Now()
	cfem.Contracts[contractID] = contract
	cfem.logContractEvent(contract, "CONDITION_ADDED")

	return nil
}

// RemoveCondition removes a condition from a contract
func (cfem *ConditionalForexEnforcementManager) RemoveCondition(contractID, conditionID string) error {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return errors.New("contract not found")
	}

	for i, cond := range contract.Conditions {
		if cond.ConditionID == conditionID {
			contract.Conditions = append(contract.Conditions[:i], contract.Conditions[i+1:]...)
			contract.LastUpdatedDate = time.Now()
			cfem.Contracts[contractID] = contract
			cfem.logContractEvent(contract, "CONDITION_REMOVED")
			return nil
		}
	}

	return errors.New("condition not found")
}

// EvaluateContract evaluates all conditions of a contract
func (cfem *ConditionalForexEnforcementManager) EvaluateContract(contractID string) (bool, error) {
	cfem.mutex.Lock()
	defer cfem.mutex.Unlock()

	contract, exists := cfem.Contracts[contractID]
	if !exists {
		return false, errors.New("contract not found")
	}

	if !contract.ActivationStatus {
		return false, errors.New("contract is not activated")
	}

	allConditionsMet := true
	for _, condition := range contract.Conditions {
		conditionMet, err := evaluateCondition(condition)
		if err != nil {
			return false, err
		}
		if !conditionMet {
			allConditionsMet = false
		}
	}

	cfem.logContractEvent(contract, "CONTRACT_EVALUATED")

	return allConditionsMet, nil
}

// evaluateCondition evaluates a single condition (dummy implementation)
func evaluateCondition(condition Condition) (bool, error) {
	// Dummy implementation, should be extended with real business logic
	switch condition.Type {
	case "RateThreshold":
		// Example condition evaluation logic
		var params map[string]interface{}
		if err := json.Unmarshal([]byte(condition.Params), &params); err != nil {
			return false, err
		}
		if currentRate, ok := params["current_rate"].(float64); ok {
			if threshold, ok := params["threshold"].(float64); ok {
				return currentRate >= threshold, nil
			}
		}
	}
	return false, nil
}

// logContractEvent logs events related to conditional Forex contracts
func (cfem *ConditionalForexEnforcementManager) logContractEvent(contract *ConditionalForexEnforcement, eventType string) {
	event := map[string]interface{}{
		"event_type":        eventType,
		"contract_id":       contract.ContractID,
		"owner":             contract.Owner,
		"timestamp":         time.Now().UTC(),
		"activation_status": contract.ActivationStatus,
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}

// generateUniqueID generates a unique identifier (dummy implementation)
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
