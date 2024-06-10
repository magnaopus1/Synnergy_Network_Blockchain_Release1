package contracts

import (
	"sync"
	"errors"
	"math/rand"
	"time"
)

// Contract defines the structure for managing resource allocation contracts.
type Contract struct {
	ID          string
	NodeID      string
	ResourceType string
	Quantity    int
	Priority    int
	Status      string
	CreatedAt   time.Time
}

// ContractManager manages the lifecycle of contracts and their execution.
type ContractManager struct {
	mutex     sync.Mutex
	contracts map[string]*Contract
}

// NewContractManager creates a new instance of ContractManager.
func NewContractManager() *ContractManager {
	return &ContractManager{
		contracts: make(map[string]*Contract),
	}
}

// CreateContract creates and stores a new resource allocation contract.
func (cm *ContractManager) CreateContract(nodeID, resourceType string, quantity, priority int) (*Contract, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	contractID := generateContractID()
	newContract := &Contract{
		ID:          contractID,
		NodeID:      nodeID,
		ResourceType: resourceType,
		Quantity:    quantity,
		Priority:    priority,
		Status:      "Active",
		CreatedAt:   time.Now(),
	}

	cm.contracts[contractID] = newContract
	return newContract, nil
}

// GetContract retrieves a contract by its ID.
func (cm *ContractManager) GetContract(id string) (*Contract, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	contract, exists := cm.contracts[id]
	if !exists {
		return nil, errors.New("contract not found")
	}
	return contract, nil
}

// UpdateContract updates specific fields of an existing contract.
func (cm *ContractManager) UpdateContract(id string, updates map[string]interface{}) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	contract, exists := cm.contracts[id]
	if !exists {
		return errors.New("contract not found")
	}

	if quantity, ok := updates["quantity"].(int); ok {
		contract.Quantity = quantity
	}
	if priority, ok := updates["priority"].(int); ok {
		contract.Priority = priority
	}
	if status, ok := updates["status"].(string); ok {
		contract.Status = status
	}

	return nil
}

// ListContracts returns a list of all contracts.
func (cm *ContractManager) ListContracts() []*Contract {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	list := make([]*Contract, 0, len(cm.contracts))
	for _, contract := range cm.contracts {
		list = append(list, contract)
	}
	return list
}

// DeleteContract removes a contract from the manager.
func (cm *ContractManager) DeleteContract(id string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	_, exists := cm.contracts[id]
	if !exists {
		return errors.New("contract not found")
	}

	delete(cm.contracts, id)
	return nil
}

// generateContractID generates a unique identifier for a new contract.
func generateContractID() string {
	rand.Seed(time.Now().UnixNano())
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 10)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

