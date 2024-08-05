// Package management provides functionality for managing agricultural policies in the SYN4900 Token Standard.
package management

import (
	"errors"
	"sync"
	"time"
)

// Policy represents an agricultural policy within the SYN4900 system.
type Policy struct {
	PolicyID      string
	Name          string
	Description   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	IsActive      bool
	Regulations   []string
}

// PolicyManager handles the creation, modification, enforcement, and tracking of policies.
type PolicyManager struct {
	policies map[string]Policy
	mutex    sync.Mutex
}

// NewPolicyManager initializes and returns a new PolicyManager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]Policy),
	}
}

// CreatePolicy adds a new policy to the system.
func (pm *PolicyManager) CreatePolicy(name, description string, regulations []string) (Policy, error) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Validate inputs
	if name == "" || description == "" || len(regulations) == 0 {
		return Policy{}, errors.New("invalid policy details")
	}

	// Generate a unique policy ID
	policyID := generatePolicyID(name, time.Now())

	// Create the new policy
	policy := Policy{
		PolicyID:    policyID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
		Regulations: regulations,
	}

	// Store the policy
	pm.policies[policyID] = policy

	return policy, nil
}

// UpdatePolicy updates the details of an existing policy.
func (pm *PolicyManager) UpdatePolicy(policyID, name, description string, regulations []string) (Policy, error) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Retrieve the existing policy
	policy, exists := pm.policies[policyID]
	if !exists {
		return Policy{}, errors.New("policy not found")
	}

	// Update policy details
	if name != "" {
		policy.Name = name
	}
	if description != "" {
		policy.Description = description
	}
	if len(regulations) > 0 {
		policy.Regulations = regulations
	}
	policy.UpdatedAt = time.Now()

	// Save the updated policy
	pm.policies[policyID] = policy

	return policy, nil
}

// GetPolicy retrieves a policy by its ID.
func (pm *PolicyManager) GetPolicy(policyID string) (Policy, error) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policy, exists := pm.policies[policyID]
	if !exists {
		return Policy{}, errors.New("policy not found")
	}

	return policy, nil
}

// ListPolicies returns all active policies.
func (pm *PolicyManager) ListPolicies() []Policy {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policies := make([]Policy, 0)
	for _, policy := range pm.policies {
		if policy.IsActive {
			policies = append(policies, policy)
		}
	}

	return policies
}

// DeactivatePolicy deactivates a policy, preventing it from being applied to new transactions.
func (pm *PolicyManager) DeactivatePolicy(policyID string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	policy, exists := pm.policies[policyID]
	if !exists {
		return errors.New("policy not found")
	}

	// Deactivate the policy
	policy.IsActive = false
	policy.UpdatedAt = time.Now()
	pm.policies[policyID] = policy

	return nil
}

// generatePolicyID generates a unique ID for a policy based on its name and creation time.
func generatePolicyID(name string, createdAt time.Time) string {
	return name + "-" + createdAt.Format("20060102150405")
}
