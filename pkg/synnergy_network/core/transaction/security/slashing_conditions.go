package security

import (
	"errors"
	"sync"
	"time"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
)

// SlashingConditions manages the enforcement of conditions under which validators are penalized.
type SlashingConditions struct {
	sync.Mutex
	Blockchain *blockchain.Blockchain
	// SlashThresholds defines the conditions and corresponding penalties.
	SlashThresholds map[string]struct {
		Percentage float64
		Duration   time.Duration
	}
}

// NewSlashingConditions creates a new SlashingConditions with predefined thresholds.
func NewSlashingConditions(blockchain *blockchain.Blockchain) *SlashingConditions {
	return &SlashingConditions{
		Blockchain: blockchain,
		SlashThresholds: map[string]struct {
			Percentage float64
			Duration   time.Duration
		}{
			"doubleSigning": {Percentage: 0.05, Duration: 48 * time.Hour},
			"downtime":      {Percentage: 0.01, Duration: 24 * time.Hour},
		},
	}
}

// ValidateValidatorActivity checks for any activity that might trigger slashing conditions.
func (sc *SlashingConditions) ValidateValidatorActivity(validatorID string) error {
	sc.Lock()
	defer sc.Unlock()

	validator, exists := sc.Blockchain.GetValidator(validatorID)
	if !exists {
		return errors.New("validator not found")
	}

	// Check for double signing within the last 48 hours
	doubleSigningIncidents := sc.Blockchain.GetDoubleSigningIncidents(validatorID, sc.SlashThresholds["doubleSigning"].Duration)
	if len(doubleSigningIncidents) > 0 {
		return sc.applyPenalty(validatorID, sc.SlashThresholds["doubleSigning"].Percentage)
	}

	// Check for unacceptable downtime
	downtimeIncidents := sc.Blockchain.GetDowntimeIncidents(validatorID, sc.SlashThresholds["downtime"].Duration)
	if len(downtimeIncidents) > 0 {
		return sc.applyPenalty(validatorID, sc.SlashThresholds["downtime"].Percentage)
	}

	return nil
}

// applyPenalty applies the slashing condition to the validator's stake.
func (sc *SlashingConditions) applyPenalty(validatorID string, penaltyPercentage float64) error {
	validator, exists := sc.Blockchain.GetValidator(validatorID)
	if !exists {
		return errors.New("validator not found for penalty")
	}

	penaltyAmount := uint64(float64(validator.Stake) * penaltyPercentage)
	validator.Stake -= penaltyAmount
	sc.Blockchain.UpdateValidator(validator)
	return nil
}

// UpdateThreshold updates the penalty conditions for a specific violation type.
func (sc *SlashingConditions) UpdateThreshold(violationType string, percentage float64, duration time.Duration) {
	sc.Lock()
	defer sc.Unlock()
	if threshold, ok := sc.SlashThresholds[violationType]; ok {
		threshold.Percentage = percentage
		threshold.Duration = duration
		sc.SlashThresholds[violationType] = threshold
	}
}
