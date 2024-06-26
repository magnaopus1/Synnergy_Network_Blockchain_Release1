package contracts

import (
	"errors"
	"sync"
)

// Validator is responsible for validating resource allocations against defined rules.
type Validator struct {
	ruleManager *RuleManager
	mutex       sync.Mutex
}

// NewValidator creates a new Validator instance with a given rule manager.
func NewValidator(ruleManager *RuleManager) *Validator {
	return &Validator{
		ruleManager: ruleManager,
	}
}

// ValidateResourceAllocation checks if a given resource allocation request is valid per the current rules.
func (v *Validator) ValidateResourceAllocation(resourceType string, quantity int) (bool, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	rules := v.ruleManager.ListRules()

	// Check rules relevant to the specific resource type
	for _, rule := range rules {
		if rule.ResourceType != resourceType {
			continue
		}

		if quantity < rule.MinValue || quantity > rule.MaxValue {
			return false, errors.New("resource allocation quantity is outside the allowed range")
		}
	}

	return true, nil
}

// ValidateTransaction validates if a transaction follows the priority rules and does not exceed resource limits.
func (v *Validator) ValidateTransaction(transactionID, resourceType string, quantity int) (bool, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Retrieve the specific rule for this resource type
	rule, err := v.ruleManager.GetRule(resourceType)
	if err != nil {
		return false, err
	}

	// Check if the transaction meets the priority requirements
	if quantity > rule.MaxValue || quantity < rule.MinValue {
		return false, errors.New("transaction does not meet priority or resource constraints")
	}

	return true, nil
}

// AuditCompliance checks the overall compliance of all transactions within a given period or batch.
func (v *Validator) AuditCompliance(transactions []Transaction) ([]bool, error) {
	results := make([]bool, len(transactions))
	for i, transaction := range transactions {
		valid, err := v.ValidateTransaction(transaction.ID, transaction.ResourceType, transaction.Quantity)
		if err != nil {
			return nil, err
		}
		results[i] = valid
	}
	return results, nil
}

// Transaction represents a transaction within the blockchain, particularly regarding resource allocation.
type Transaction struct {
	ID           string
	ResourceType string
	Quantity     int
}

