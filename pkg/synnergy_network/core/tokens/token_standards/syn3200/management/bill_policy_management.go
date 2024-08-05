// Package management provides functionalities for managing bill policies for SYN3200 tokens.
package management

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// BillPolicy represents a policy for managing bills.
type BillPolicy struct {
	PolicyID        string    `json:"policy_id"`
	PolicyName      string    `json:"policy_name"`
	CreationDate    time.Time `json:"creation_date"`
	TermsAndConditions string `json:"terms_and_conditions"`
	Active          bool      `json:"active"`
}

// BillPolicyManager manages bill policies.
type BillPolicyManager struct {
	DB *leveldb.DB
}

// NewBillPolicyManager creates a new instance of BillPolicyManager.
func NewBillPolicyManager(dbPath string) (*BillPolicyManager, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &BillPolicyManager{DB: db}, nil
}

// CloseDB closes the database connection.
func (bpm *BillPolicyManager) CloseDB() error {
	return bpm.DB.Close()
}

// AddBillPolicy adds a new bill policy to the manager.
func (bpm *BillPolicyManager) AddBillPolicy(policy BillPolicy) error {
	if err := bpm.ValidateBillPolicy(policy); err != nil {
		return err
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return bpm.DB.Put([]byte("policy_"+policy.PolicyID), data, nil)
}

// GetBillPolicy retrieves a bill policy by its policy ID.
func (bpm *BillPolicyManager) GetBillPolicy(policyID string) (*BillPolicy, error) {
	data, err := bpm.DB.Get([]byte("policy_"+policyID), nil)
	if err != nil {
		return nil, err
	}
	var policy BillPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// GetAllBillPolicies retrieves all bill policies from the manager.
func (bpm *BillPolicyManager) GetAllBillPolicies() ([]BillPolicy, error) {
	var policies []BillPolicy
	iter := bpm.DB.NewIterator(util.BytesPrefix([]byte("policy_")), nil)
	defer iter.Release()
	for iter.Next() {
		var policy BillPolicy
		if err := json.Unmarshal(iter.Value(), &policy); err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	if iter.Error() != nil {
		return nil, iter.Error()
	}
	return policies, nil
}

// ValidateBillPolicy ensures the bill policy is valid before adding it to the manager.
func (bpm *BillPolicyManager) ValidateBillPolicy(policy BillPolicy) error {
	if policy.PolicyID == "" {
		return errors.New("policy ID must be provided")
	}
	if policy.PolicyName == "" {
		return errors.New("policy name must be provided")
	}
	if policy.CreationDate.IsZero() {
		return errors.New("creation date must be provided")
	}
	if policy.TermsAndConditions == "" {
		return errors.New("terms and conditions must be provided")
	}
	// Add more validation rules as necessary
	return nil
}

// UpdateBillPolicy updates an existing bill policy in the manager.
func (bpm *BillPolicyManager) UpdateBillPolicy(policy BillPolicy) error {
	if _, err := bpm.GetBillPolicy(policy.PolicyID); err != nil {
		return err
	}
	if err := bpm.ValidateBillPolicy(policy); err != nil {
		return err
	}
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	return bpm.DB.Put([]byte("policy_"+policy.PolicyID), data, nil)
}

// DeactivateBillPolicy deactivates an existing bill policy.
func (bpm *BillPolicyManager) DeactivateBillPolicy(policyID string) error {
	policy, err := bpm.GetBillPolicy(policyID)
	if err != nil {
		return err
	}
	policy.Active = false
	return bpm.UpdateBillPolicy(*policy)
}

// DeleteBillPolicy removes a bill policy from the manager.
func (bpm *BillPolicyManager) DeleteBillPolicy(policyID string) error {
	return bpm.DB.Delete([]byte("policy_"+policyID), nil)
}

// GetActiveBillPolicies retrieves all active bill policies.
func (bpm *BillPolicyManager) GetActiveBillPolicies() ([]BillPolicy, error) {
	var activePolicies []BillPolicy
	policies, err := bpm.GetAllBillPolicies()
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if policy.Active {
			activePolicies = append(activePolicies, policy)
		}
	}
	return activePolicies, nil
}

// GetInactiveBillPolicies retrieves all inactive bill policies.
func (bpm *BillPolicyManager) GetInactiveBillPolicies() ([]BillPolicy, error) {
	var inactivePolicies []BillPolicy
	policies, err := bpm.GetAllBillPolicies()
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		if !policy.Active {
			inactivePolicies = append(inactivePolicies, policy)
		}
	}
	return inactivePolicies, nil
}
