// Package smart_contracts provides functionality for managing smart contracts
// related to agricultural tokens in the SYN4900 Token Standard.
package smart_contracts

import (
	"errors"
	"fmt"
	"time"
	"sync"

	"github.com/synnergy_network/ledger"
	"github.com/synnergy_network/transactions"
)

// SupplyChainContract represents a smart contract for managing supply chain operations.
type SupplyChainContract struct {
	ContractID      string
	TokenID         string
	Conditions      []Condition
	Status          string
	CreationDate    time.Time
	CompletionDate  time.Time
	TransactionLogs []transactions.TransactionRecord
	mutex           sync.Mutex
}

// Condition represents a condition that must be met for a supply chain operation.
type Condition struct {
	Description string
	Met         bool
}

// SupplyChainManager defines the methods for managing supply chain operations using smart contracts.
type SupplyChainManager struct {
	contracts map[string]SupplyChainContract
	mutex     sync.Mutex
}

// NewSupplyChainManager initializes and returns a new SupplyChainManager.
func NewSupplyChainManager() *SupplyChainManager {
	return &SupplyChainManager{
		contracts: make(map[string]SupplyChainContract),
	}
}

// CreateContract allows the creation of a new supply chain contract.
func (scm *SupplyChainManager) CreateContract(tokenID string, conditions []Condition) (SupplyChainContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	if tokenID == "" || len(conditions) == 0 {
		return SupplyChainContract{}, errors.New("invalid contract details")
	}

	contractID := generateContractID(tokenID, time.Now())
	contract := SupplyChainContract{
		ContractID:      contractID,
		TokenID:         tokenID,
		Conditions:      conditions,
		Status:          "Pending",
		CreationDate:    time.Now(),
		TransactionLogs: []transactions.TransactionRecord{},
	}

	scm.contracts[contractID] = contract
	return contract, nil
}

// UpdateCondition allows updating a specific condition of a supply chain contract.
func (scm *SupplyChainManager) UpdateCondition(contractID string, conditionIndex int, met bool) (SupplyChainContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return SupplyChainContract{}, errors.New("contract not found")
	}

	if conditionIndex < 0 || conditionIndex >= len(contract.Conditions) {
		return SupplyChainContract{}, errors.New("invalid condition index")
	}

	contract.Conditions[conditionIndex].Met = met
	scm.contracts[contractID] = contract

	return contract, nil
}

// CompleteContract completes a supply chain contract if all conditions are met.
func (scm *SupplyChainManager) CompleteContract(contractID string) (SupplyChainContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return SupplyChainContract{}, errors.New("contract not found")
	}

	for _, condition := range contract.Conditions {
		if !condition.Met {
			return SupplyChainContract{}, errors.New("not all conditions are met")
		}
	}

	contract.Status = "Completed"
	contract.CompletionDate = time.Now()
	scm.contracts[contractID] = contract

	return contract, nil
}

// LogTransaction logs a transaction associated with a supply chain contract.
func (scm *SupplyChainManager) LogTransaction(contractID, transactionID, description string, quantity float64, from, to string) (SupplyChainContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return SupplyChainContract{}, errors.New("contract not found")
	}

	transactionRecord := transactions.TransactionRecord{
		TransactionID: transactionID,
		Timestamp:     time.Now(),
		From:          from,
		To:            to,
		Quantity:      quantity,
		Description:   description,
	}

	contract.TransactionLogs = append(contract.TransactionLogs, transactionRecord)
	scm.contracts[contractID] = contract

	return contract, nil
}

// GetContract retrieves the details of a specific supply chain contract by its ID.
func (scm *SupplyChainManager) GetContract(contractID string) (SupplyChainContract, error) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contract, exists := scm.contracts[contractID]
	if !exists {
		return SupplyChainContract{}, errors.New("contract not found")
	}

	return contract, nil
}

// ListContracts returns all supply chain contracts managed by the system.
func (scm *SupplyChainManager) ListContracts() []SupplyChainContract {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()

	contracts := make([]SupplyChainContract, 0)
	for _, contract := range scm.contracts {
		contracts = append(contracts, contract)
	}

	return contracts
}

// generateContractID generates a unique ID for a supply chain contract.
func generateContractID(tokenID string, createdAt time.Time) string {
	return fmt.Sprintf("SC-%s-%d", tokenID, createdAt.Unix())
}
