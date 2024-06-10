package governance_framework

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/pkg/errors"
)

// Policy defines the structure for governance policies.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Creator     string    `json:"creator"`
	CreatedAt   time.Time `json:"created_at"`
	Active      bool      `json:"active"`
	Rules       []string  `json:"rules"` // List of rules in the policy
}

// PolicyManager handles the creation, modification, and enforcement of policies.
type PolicyManager struct {
	Policies map[string]*Policy
}

// NewPolicyManager initializes a new policy manager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		Policies: make(map[string]*Policy),
	}
}

// CreatePolicy creates a new policy with given details.
func (pm *PolicyManager) CreatePolicy(id, name, description, creator string, rules []string) error {
	if _, exists := pm.Policies[id]; exists {
		return errors.New("policy already exists with the given ID")
	}
	pm.Policies[id] = &Policy{
		ID:          id,
		Name:        name,
		Description: description,
		Creator:     creator,
		CreatedAt:   time.Now(),
		Active:      true,
		Rules:       rules,
	}
	log.Printf("Policy created: %s", name)
	return nil
}

// UpdatePolicy modifies an existing policy identified by ID.
func (pm *PolicyManager) UpdatePolicy(id string, newRules []string) error {
	policy, exists := pm.Policies[id]
	if !exists {
		return errors.New("policy not found")
	}
	policy.Rules = newRules
	log.Printf("Policy updated: %s", policy.Name)
	return nil
}

// DeactivatePolicy sets a policy's active status to false.
func (pm *PolicyManager) DeactivatePolicy(id string) error {
	policy, exists := pm.Policies[id]
	if !exists {
		return errors.New("policy not found")
	}
	policy.Active = false
	log.Printf("Policy deactivated: %s", policy.Name)
	return nil
}

// SerializePolicy serializes a policy to JSON.
func (pm *PolicyManager) SerializePolicy(id string) ([]byte, error) {
	policy, exists := pm.Policies[id]
	if !exists {
		return nil, errors.New("policy not found")
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize policy")
	}
	return data, nil
}

// DeserializePolicy deserializes JSON into a Policy object.
func DeserializePolicy(data []byte) (*Policy, error) {
	var policy Policy
	err := json.Unmarshal(data, &policy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialize policy")
	}
	return &policy, nil
}

// LogPolicyDetails logs the details of a policy for auditing.
func LogPolicyDetails(policy *Policy) {
	log.Printf("Policy Details: ID=%s, Name=%s, Active=%t, Rules=%v", policy.ID, policy.Name, policy.Active, policy.Rules)
}
