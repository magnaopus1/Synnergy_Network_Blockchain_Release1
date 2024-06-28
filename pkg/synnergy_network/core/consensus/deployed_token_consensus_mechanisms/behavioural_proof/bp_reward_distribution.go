package behavioural_proof

import (
	"math"
	"sync"
)

// RewardDistributionManager handles the distribution of rewards among validators based on their reputation.
type RewardDistributionManager struct {
	mutex sync.RWMutex
	// Maps validator ID to its reputation score
	reputationScores map[string]float64
	// Total reward pool available for distribution
	totalRewardPool float64
}

// NewRewardDistributionManager creates a new instance of RewardDistributionManager
func NewRewardDistributionManager(initialRewardPool float64) *RewardDistributionManager {
	return &RewardDistributionManager{
		reputationScores: make(map[string]float64),
		totalRewardPool:  initialRewardPool,
	}
}

// SetReputationScore sets or updates the reputation score for a given validator.
func (rdm *RewardDistributionManager) SetReputationScore(validatorID string, score float64) {
	rdm.mutex.Lock()
	defer rdm.mutex.Unlock()
	rdm.reputationScores[validatorID] = score
}

// UpdateRewardPool updates the total reward pool available for distribution.
func (rdm *RewardDistributionManager) UpdateRewardPool(amount float64) {
	rdm.mutex.Lock()
	defer rdm.mutex.Unlock()
	rdm.totalRewardPool += amount
}

// CalculateRewards computes and returns the reward distribution among validators based on their reputation scores.
func (rdm *RewardDistributionManager) CalculateRewards() map[string]float64 {
	rdm.mutex.RLock()
	defer rdm.mutex.RUnlock()

	totalReputation := 0.0
	for _, score := range rdm.reputationScores {
		totalReputation += score
	}

	rewards := make(map[string]float64)
	for id, score := range rdm.reputationScores {
		if totalReputation == 0 {
			rewards[id] = 0
		} else {
			rewards[id] = (score / totalReputation) * rdm.totalRewardPool
		}
	}

	return rewards
}

// DistributeRewards executes the reward distribution to validators and resets the reward pool.
func (rdm *RewardDistributionManager) DistributeRewards() {
	rewards := rdm.CalculateRewards()
	for id, reward := range rewards {
		rdm.payValidator(id, reward)
	}
	// Reset reward pool after distribution
	rdm.totalRewardPool = 0
}

// payValidator simulates the payment process to a validator.
func (rdm *RewardDistributionManager) payValidator(validatorID string, amount float64) {
	// Simulate payment transaction to validator
	// This function would interact with the network's financial subsystem
	fmt.Printf("Paid %f to validator %s\n", amount, validatorID)
}

// GetTotalRewardPool returns the current total reward pool.
func (rdm *RewardDistributionManager) GetTotalRewardPool() float64 {
	rdm.mutex.RLock()
	defer rdm.mutex.RUnlock()
	return rdm.totalRewardPool
}
