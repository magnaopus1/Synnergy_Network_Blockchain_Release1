package utils

import (
	"errors"
	"sync"
	"time"
)

// ValidatorStatus represents the status of a validator
type ValidatorStatus int

const (
	Active ValidatorStatus = iota
	Inactive
)

// Validator represents a network validator
type Validator struct {
	ID             string
	Stake          int64
	LastActiveTime time.Time
	Status         ValidatorStatus
}

// ValidatorSet represents a set of validators
type ValidatorSet struct {
	mu         sync.Mutex
	validators map[string]*Validator
}

// NewValidatorSet creates a new ValidatorSet
func NewValidatorSet() *ValidatorSet {
	return &ValidatorSet{
		validators: make(map[string]*Validator),
	}
}

// AddValidator adds a new validator to the set
func (vs *ValidatorSet) AddValidator(id string, stake int64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.validators[id] = &Validator{
		ID:             id,
		Stake:          stake,
		LastActiveTime: time.Now(),
		Status:         Active,
	}
}

// RemoveValidator removes a validator from the set
func (vs *ValidatorSet) RemoveValidator(id string) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if _, exists := vs.validators[id]; !exists {
		return errors.New("validator not found")
	}
	delete(vs.validators, id)
	return nil
}

// UpdateValidatorStake updates the stake of a validator
func (vs *ValidatorSet) UpdateValidatorStake(id string, newStake int64) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		validator.Stake = newStake
		return nil
	}
	return errors.New("validator not found")
}

// SetValidatorStatus sets the status of a validator
func (vs *ValidatorSet) SetValidatorStatus(id string, status ValidatorStatus) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		validator.Status = status
		return nil
	}
	return errors.New("validator not found")
}

// GetActiveValidators returns a list of active validators
func (vs *ValidatorSet) GetActiveValidators() []*Validator {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	activeValidators := []*Validator{}
	for _, validator := range vs.validators {
		if validator.Status == Active {
			activeValidators = append(activeValidators, validator)
		}
	}
	return activeValidators
}

// GetValidatorStake returns the stake of a specific validator
func (vs *ValidatorSet) GetValidatorStake(id string) (int64, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		return validator.Stake, nil
	}
	return 0, errors.New("validator not found")
}

// GetValidatorStatus returns the status of a specific validator
func (vs *ValidatorSet) GetValidatorStatus(id string) (ValidatorStatus, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		return validator.Status, nil
	}
	return Inactive, errors.New("validator not found")
}

// Helper functions for various calculations

// CalculateStakeWeight calculates the stake weight based on the validator's stake
func CalculateStakeWeight(validatorStake, totalStake int64) float64 {
	if totalStake == 0 {
		return 0
	}
	return float64(validatorStake) / float64(totalStake)
}

// UpdateValidatorActivity updates the last active time of a validator
func (vs *ValidatorSet) UpdateValidatorActivity(id string) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		validator.LastActiveTime = time.Now()
		return nil
	}
	return errors.New("validator not found")
}

// CheckValidatorActivity checks if a validator is still active
func (vs *ValidatorSet) CheckValidatorActivity(id string, timeout time.Duration) (bool, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	if validator, exists := vs.validators[id]; exists {
		if time.Since(validator.LastActiveTime) > timeout {
			validator.Status = Inactive
			return false, nil
		}
		return true, nil
	}
	return false, errors.New("validator not found")
}

// GetTotalStake calculates the total stake of all validators
func (vs *ValidatorSet) GetTotalStake() int64 {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	var totalStake int64
	for _, validator := range vs.validators {
		totalStake += validator.Stake
	}
	return totalStake
}
