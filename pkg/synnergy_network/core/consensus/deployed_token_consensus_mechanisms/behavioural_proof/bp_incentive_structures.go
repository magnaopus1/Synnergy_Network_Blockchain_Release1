package behavioural_proof

import (
	"sync"
	"errors"
)

// IncentiveManager manages the incentive structures for validators based on their performance.
type IncentiveManager struct {
	mutex       sync.RWMutex
	baseReward  float64
	penaltyRate map[string]float64
}

// NewIncentiveManager creates a new incentive manager with specified base reward.
func NewIncentiveManager(baseReward float64) *IncentiveManager {
	return &IncentiveManager{
		baseReward:  baseReward,
		penaltyRate: make(map[string]float64),
	}
}

// CalculateReward computes the reward for a validator based on their reputation score and maximum score.
func (im *IncentiveManager) CalculateReward(reputation, maxReputation float64) float64 {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	if maxReputation == 0 {
		return 0 // Prevent division by zero
	}

	rewardMultiplier := 1 + (reputation / maxReputation)
	return im.baseReward * rewardMultiplier
}

// SetPenaltyRate sets the penalty rate for specific types of violations.
func (im *IncentiveManager) SetPenaltyRate(violationType string, rate float64) error {
	if rate < 0 {
		return errors.New("penalty rate must be non-negative")
	}

	im.mutex.Lock()
	defer im.mutex.Unlock()

	im.penaltyRate[violationType] = rate
	return nil
}

// CalculatePenalty computes the penalty for a given violation based on its type and severity.
func (im *IncentiveManager) CalculatePenalty(violationType string, severity float64) (float64, error) {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	rate, exists := im.penaltyRate[violationType]
	if !exists {
		return 0, errors.New("violation type not recognized")
	}

	return rate * severity, nil
}

// ListPenalties lists all the current penalty rates for violations.
func (im *IncentiveManager) ListPenalties() map[string]float64 {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	// Create a copy of the map to prevent modification
	copiedMap := make(map[string]float64)
	for key, value := range im.penaltyRate {
		copiedMap[key] = value
	}
	return copiedMap
}

