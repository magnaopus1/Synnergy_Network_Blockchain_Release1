package utils

import (
	"errors"
	"math"
	"time"
)

// Validator represents the structure of a network validator
type Validator struct {
	ID                 string
	Stake              int
	PerformanceScore   float64
	ContributionScore  float64
	LastActivity       time.Time
	IsActive           bool
	ReputationScore    float64
}

// NewValidator initializes a new Validator instance
func NewValidator(id string, stake int, performanceScore, contributionScore, reputationScore float64) *Validator {
	return &Validator{
		ID:                id,
		Stake:             stake,
		PerformanceScore:  performanceScore,
		ContributionScore: contributionScore,
		LastActivity:      time.Now(),
		IsActive:          true,
		ReputationScore:   reputationScore,
	}
}

// UpdateActivity updates the last activity time of the validator
func (v *Validator) UpdateActivity() {
	v.LastActivity = time.Now()
}

// CalculateIncentive calculates the incentive for a validator based on performance and contribution
func (v *Validator) CalculateIncentive(baseReward, maxPerformanceScore, maxContributionScore float64) float64 {
	performanceIncentive := baseReward * (1 + (v.PerformanceScore / maxPerformanceScore))
	contributionIncentive := baseReward * (1 + (v.ContributionScore / maxContributionScore))
	return (performanceIncentive + contributionIncentive) / 2
}

// AdjustReputationScore adjusts the reputation score of the validator
func (v *Validator) AdjustReputationScore(change float64) {
	v.ReputationScore += change
	if v.ReputationScore < 0 {
		v.ReputationScore = 0
	}
}

// Deactivate deactivates a validator due to inactivity or penalties
func (v *Validator) Deactivate() {
	v.IsActive = false
}

// Reactivate reactivates a validator
func (v *Validator) Reactivate() {
	v.IsActive = true
	v.UpdateActivity()
}

// ValidatorPool represents a pool of validators
type ValidatorPool struct {
	Validators map[string]*Validator
}

// NewValidatorPool initializes a new ValidatorPool instance
func NewValidatorPool() *ValidatorPool {
	return &ValidatorPool{
		Validators: make(map[string]*Validator),
	}
}

// AddValidator adds a validator to the pool
func (vp *ValidatorPool) AddValidator(validator *Validator) {
	vp.Validators[validator.ID] = validator
}

// RemoveValidator removes a validator from the pool
func (vp *ValidatorPool) RemoveValidator(id string) {
	delete(vp.Validators, id)
}

// GetValidator retrieves a validator from the pool by ID
func (vp *ValidatorPool) GetValidator(id string) (*Validator, error) {
	validator, exists := vp.Validators[id]
	if !exists {
		return nil, errors.New("validator not found")
	}
	return validator, nil
}

// CalculateTotalStake calculates the total stake of all active validators in the pool
func (vp *ValidatorPool) CalculateTotalStake() int {
	totalStake := 0
	for _, validator := range vp.Validators {
		if validator.IsActive {
			totalStake += validator.Stake
		}
	}
	return totalStake
}

// CalculateValidatorAllocation calculates the allocation for a validator based on their stake
func (vp *ValidatorPool) CalculateValidatorAllocation(id string, totalResources int) (float64, error) {
	validator, err := vp.GetValidator(id)
	if err != nil {
		return 0, err
	}

	totalStake := vp.CalculateTotalStake()
	if totalStake == 0 {
		return 0, errors.New("total stake is zero")
	}

	return float64(validator.Stake) * float64(totalResources) / float64(totalStake), nil
}

// CalculateAverageReputation calculates the average reputation score of active validators
func (vp *ValidatorPool) CalculateAverageReputation() float64 {
	totalReputation := 0.0
	activeValidators := 0
	for _, validator := range vp.Validators {
		if validator.IsActive {
			totalReputation += validator.ReputationScore
			activeValidators++
		}
	}
	if activeValidators == 0 {
		return 0
	}
	return totalReputation / float64(activeValidators)
}

// PenalizeValidator penalizes a validator by reducing their reputation score
func (vp *ValidatorPool) PenalizeValidator(id string, penalty float64) error {
	validator, err := vp.GetValidator(id)
	if err != nil {
		return err
	}
	validator.AdjustReputationScore(-penalty)
	if validator.ReputationScore == 0 {
		validator.Deactivate()
	}
	return nil
}

// RewardValidator rewards a validator by increasing their reputation score
func (vp *ValidatorPool) RewardValidator(id string, reward float64) error {
	validator, err := vp.GetValidator(id)
	if err != nil {
		return err
	}
	validator.AdjustReputationScore(reward)
	return nil
}

// ValidateConsensus validates if the consensus is achieved based on active validators' stake and reputation
func (vp *ValidatorPool) ValidateConsensus(requiredStake int, requiredReputation float64) bool {
	totalStake := 0
	for _, validator := range vp.Validators {
		if validator.IsActive && validator.ReputationScore >= requiredReputation {
			totalStake += validator.Stake
		}
	}
	return totalStake >= requiredStake
}

// Encryption and Decryption Utility
type EncryptDecryptUtility struct{}

// EncryptData encrypts the given data using Argon2 and AES
func (edu *EncryptDecryptUtility) EncryptData(data, key string) (string, error) {
	// Implement encryption logic here using Argon2 and AES
	return "", nil
}

// DecryptData decrypts the given data using Argon2 and AES
func (edu *EncryptDecryptUtility) DecryptData(data, key string) (string, error) {
	// Implement decryption logic here using Argon2 and AES
	return "", nil
}
