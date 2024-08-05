package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3100/security"
)

// EmploymentPolicy represents a policy within the employment framework
type EmploymentPolicy struct {
	PolicyID        string    `json:"policy_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	EffectiveDate   time.Time `json:"effective_date"`
	ExpirationDate  time.Time `json:"expiration_date"`
	CreatedBy       string    `json:"created_by"`
	CreationDate    time.Time `json:"creation_date"`
	LastUpdatedBy   string    `json:"last_updated_by"`
	LastUpdatedDate time.Time `json:"last_updated_date"`
}

// EmploymentPolicyManager manages employment policies
type EmploymentPolicyManager struct {
	policies map[string]EmploymentPolicy
	mu       sync.RWMutex
}

// NewEmploymentPolicyManager initializes a new EmploymentPolicyManager
func NewEmploymentPolicyManager() *EmploymentPolicyManager {
	return &EmploymentPolicyManager{
		policies: make(map[string]EmploymentPolicy),
	}
}

// AddPolicy adds a new employment policy
func (epm *EmploymentPolicyManager) AddPolicy(policyID, title, description, createdBy string, effectiveDate, expirationDate time.Time) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	if _, exists := epm.policies[policyID]; exists {
		return errors.New("policy already exists")
	}

	now := time.Now()
	policy := EmploymentPolicy{
		PolicyID:        policyID,
		Title:           title,
		Description:     description,
		EffectiveDate:   effectiveDate,
		ExpirationDate:  expirationDate,
		CreatedBy:       createdBy,
		CreationDate:    now,
		LastUpdatedBy:   createdBy,
		LastUpdatedDate: now,
	}

	epm.policies[policyID] = policy
	return nil
}

// UpdatePolicy updates an existing employment policy
func (epm *EmploymentPolicyManager) UpdatePolicy(policyID, title, description, updatedBy string, effectiveDate, expirationDate time.Time) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	policy, exists := epm.policies[policyID]
	if !exists {
		return errors.New("policy not found")
	}

	policy.Title = title
	policy.Description = description
	policy.EffectiveDate = effectiveDate
	policy.ExpirationDate = expirationDate
	policy.LastUpdatedBy = updatedBy
	policy.LastUpdatedDate = time.Now()

	epm.policies[policyID] = policy
	return nil
}

// DeletePolicy deletes an existing employment policy
func (epm *EmploymentPolicyManager) DeletePolicy(policyID string) error {
	epm.mu.Lock()
	defer epm.mu.Unlock()

	if _, exists := epm.policies[policyID]; !exists {
		return errors.New("policy not found")
	}

	delete(epm.policies, policyID)
	return nil
}

// GetPolicy retrieves an employment policy by its ID
func (epm *EmploymentPolicyManager) GetPolicy(policyID string) (EmploymentPolicy, error) {
	epm.mu.RLock()
	defer epm.mu.RUnlock()

	policy, exists := epm.policies[policyID]
	if !exists {
		return EmploymentPolicy{}, errors.New("policy not found")
	}

	return policy, nil
}

// GetAllPolicies retrieves all employment policies
func (epm *EmploymentPolicyManager) GetAllPolicies() ([]EmploymentPolicy, error) {
	epm.mu.RLock()
	defer epm.mu.RUnlock()

	policies := make([]EmploymentPolicy, 0, len(epm.policies))
	for _, policy := range epm.policies {
		policies = append(policies, policy)
	}

	return policies, nil
}

// EncryptPolicyData encrypts the policy data for secure storage
func (epm *EmploymentPolicyManager) EncryptPolicyData(policyID, password string) (string, error) {
	epm.mu.RLock()
	defer epm.mu.RUnlock()

	policy, exists := epm.policies[policyID]
	if !exists {
		return "", errors.New("policy not found")
	}

	dataBytes, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}

	encryptedData, err := security.EncryptData(dataBytes, password)
	if err != nil {
		return "", err
	}

	return encryptedData, nil
}

// DecryptPolicyData decrypts the policy data
func (epm *EmploymentPolicyManager) DecryptPolicyData(encryptedData, password string) (EmploymentPolicy, error) {
	decryptedData, err := security.DecryptData(encryptedData, password)
	if err != nil {
		return EmploymentPolicy{}, err
	}

	var policy EmploymentPolicy
	err = json.Unmarshal([]byte(decryptedData), &policy)
	if err != nil {
		return EmploymentPolicy{}, err
	}

	return policy, nil
}
