package consensus

import (
	"errors"
	"math/big"
	"sync"
	"time"
)

// Validator encapsulates the stake and penalty details for a single validator.
type Validator struct {
	ID              string
	StakeAmount     *big.Int
	StakeStartTime  time.Time
	IsActive        bool
	TotalPenalties  *big.Int
	LockUpPeriod    time.Duration
}

// SlashingRule defines the criteria and consequences of a slashing condition.
type SlashingRule struct {
	Condition func(*Validator) bool
	Penalty   *big.Int
}

// StakingAndSlashing manages all staking and slashing operations.
type StakingAndSlashing struct {
	validators map[string]*Validator
	rules      []SlashingRule
	lock       sync.RWMutex
}

// NewStakingAndSlashing initializes the StakingAndSlashing system with default settings.
func NewStakingAndSlashing() *StakingAndSlashing {
	return &StakingAndSlashing{
		validators: make(map[string]*Validator),
		rules:      initializeSlashingRules(),
	}
}

// initializeSlashingRules defines default slashing conditions.
func initializeSlashingRules() []SlashingRule {
	return []SlashingRule{
		{
			Condition: func(v *Validator) bool {
				return time.Since(v.StakeStartTime) < v.LockUpPeriod && !v.IsActive
			},
			Penalty: big.NewInt(100), // example penalty for early unstaking or inactivity
		},
		// Additional slashing conditions can be implemented here.
	}
}

// Stake registers or increases a stake for a validator.
func (s *StakingAndSlashing) Stake(validatorID string, amount *big.Int, lockUpPeriod time.Duration) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if amount.Sign() <= 0 {
		return errors.New("stake amount must be positive")
	}

	validator, exists := s.validators[validatorID]
	if !exists {
		validator = &Validator{
			ID:             validatorID,
			StakeAmount:    big.NewInt(0),
			StakeStartTime: time.Now(),
			IsActive:       true,
			TotalPenalties: big.NewInt(0),
			LockUpPeriod:   lockUpPeriod,
		}
		s.validators[validatorID] = validator
	}

	validator.StakeAmount.Add(validator.StakeAmount, amount)
	return nil
}

// Slash evaluates all validators against the defined slashing conditions.
func (s *StakingAndSlashing) Slash() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, validator := range s.validators {
		for _, rule := range s.rules {
			if rule.Condition(validator) {
				validator.StakeAmount.Sub(validator.StakeAmount, rule.Penalty)
				validator.TotalPenalties.Add(validator.TotalPenalties, rule.Penalty)
			}
		}
	}
}

// Unstake handles the removal of stake considering the lock-up period.
func (s *StakingAndSlashing) Unstake(validatorID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	validator, exists := s.validators[validatorID]
	if !exists {
		return errors.New("validator not found")
	}

	if time.Since(validator.StakeStartTime) < validator.LockUpPeriod {
		return errors.New("cannot unstake during lock-up period")
	}

	delete(s.validators, validatorID)
	return nil
}

// GetValidator returns the detailed information of a validator.
func (s *StakingAndSlashing) GetValidator(validatorID string) (*Validator, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	validator, exists := s.validators[validatorID]
	if !exists {
		return nil, errors.New("validator not found")
	}
	return validator, nil
}
