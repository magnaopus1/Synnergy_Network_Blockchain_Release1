// gambling_policy_management.go

package management

import (
	"errors"
	"time"
)

// Policy represents a gambling policy within the system
type Policy struct {
	ID             string            // Unique identifier for the policy
	Name           string            // Name of the policy
	Description    string            // Detailed description of the policy
	EffectiveDate  time.Time         // The date from which the policy is effective
	ExpiryDate     time.Time         // The date when the policy expires
	Conditions     map[string]string // Conditions that must be met under the policy
	Active         bool              // Indicates if the policy is currently active
	CreatedBy      string            // Entity that created the policy
	LastModifiedBy string            // Entity that last modified the policy
	LastModified   time.Time         // The last modification date
}

// PolicyManager handles the creation, updating, and enforcement of gambling policies
type PolicyManager struct {
	policies map[string]Policy // Map of policy ID to Policy objects
}

// NewPolicyManager initializes a new PolicyManager
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]Policy),
	}
}

// AddPolicy adds a new policy to the system
func (pm *PolicyManager) AddPolicy(policy Policy) error {
	if _, exists := pm.policies[policy.ID]; exists {
		return errors.New("policy with this ID already exists")
	}
	if policy.EffectiveDate.After(policy.ExpiryDate) {
		return errors.New("effective date must be before expiry date")
	}

	policy.Active = true
	policy.LastModified = time.Now()
	pm.policies[policy.ID] = policy
	return nil
}

// UpdatePolicy updates an existing policy
func (pm *PolicyManager) UpdatePolicy(policyID string, updated Policy) error {
	if policy, exists := pm.policies[policyID]; exists {
		updated.CreatedBy = policy.CreatedBy
		updated.LastModifiedBy = policy.LastModifiedBy
		updated.LastModified = time.Now()
		pm.policies[policyID] = updated
		return nil
	}
	return errors.New("policy not found")
}

// DeactivatePolicy deactivates a policy
func (pm *PolicyManager) DeactivatePolicy(policyID string) error {
	if policy, exists := pm.policies[policyID]; exists {
		policy.Active = false
		pm.policies[policyID] = policy
		return nil
	}
	return errors.New("policy not found")
}

// GetActivePolicies returns a list of all active policies
func (pm *PolicyManager) GetActivePolicies() []Policy {
	activePolicies := []Policy{}
	for _, policy := range pm.policies {
		if policy.Active && policy.EffectiveDate.Before(time.Now()) && policy.ExpiryDate.After(time.Now()) {
			activePolicies = append(activePolicies, policy)
		}
	}
	return activePolicies
}

// GetPolicy retrieves a policy by its ID
func (pm *PolicyManager) GetPolicy(policyID string) (Policy, error) {
	if policy, exists := pm.policies[policyID]; exists {
		return policy, nil
	}
	return Policy{}, errors.New("policy not found")
}

// CheckPolicyCompliance checks if an action complies with active policies
func (pm *PolicyManager) CheckPolicyCompliance(action string, details map[string]interface{}) (bool, error) {
	for _, policy := range pm.GetActivePolicies() {
		// Here we should implement specific logic to check conditions
		// For simplicity, assuming a condition is met if action matches policy name
		if policy.Name == action {
			return true, nil
		}
	}
	return false, errors.New("no policy found for this action")
}

// RemovePolicy removes a policy by its ID
func (pm *PolicyManager) RemovePolicy(policyID string) error {
	if _, exists := pm.policies[policyID]; exists {
		delete(pm.policies, policyID)
		return nil
	}
	return errors.New("policy not found")
}
