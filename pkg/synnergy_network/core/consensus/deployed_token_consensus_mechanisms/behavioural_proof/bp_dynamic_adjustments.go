package behavioural_proof

import (
	"sync"
	"time"
)

// DynamicAdjustmentManager manages the dynamic adjustment of reputations and other parameters in real-time.
type DynamicAdjustmentManager struct {
	mutex               sync.Mutex
	reputationScores    map[string]float64
	averageUptime       float64
	expectedUptime      float64
	weightingFactors    WeightingFactors
	lastAdjustmentTime  time.Time
	adjustmentFrequency time.Duration
}

// WeightingFactors defines the weight of each metric contributing to the reputation score.
type WeightingFactors struct {
	UptimeWeight    float64
	AccuracyWeight  float64
	ContributionWeight float64
}

// NewDynamicAdjustmentManager creates a new instance of DynamicAdjustmentManager.
func NewDynamicAdjustmentManager() *DynamicAdjustmentManager {
	return &DynamicAdjustmentManager{
		reputationScores:   make(map[string]float64),
		weightingFactors:   WeightingFactors{UptimeWeight: 0.4, AccuracyWeight: 0.4, ContributionWeight: 0.2},
		adjustmentFrequency: time.Hour * 24, // Adjust daily
		lastAdjustmentTime:  time.Now(),
	}
}

// UpdateReputationScore updates the reputation score for a validator based on uptime, accuracy, and community contributions.
func (dam *DynamicAdjustmentManager) UpdateReputationScore(validatorID string, uptimeScore, accuracyScore, contributionScore float64) {
	dam.mutex.Lock()
	defer dam.mutex.Unlock()

	// Calculate new reputation score using weighted factors
	newScore := dam.weightingFactors.UptimeWeight*uptimeScore +
		dam.weightingFactors.AccuracyWeight*accuracyScore +
		dam.weightingFactors.ContributionWeight*contributionScore

	dam.reputationScores[validatorID] = newScore
}

// PeriodicAdjustment checks if it's time to adjust the weighting factors based on overall network performance.
func (dam *DynamicAdjustmentManager) PeriodicAdjustment() {
	if time.Since(dam.lastAdjustmentTime) >= dam.adjustmentFrequency {
		dam.adjustWeightingFactors()
		dam.lastAdjustmentTime = time.Now()
	}
}

// adjustWeightingFactors dynamically adjusts the weighting factors based on recent network data.
func (dam *DynamicAdjustmentManager) adjustWeightingFactors() {
	dam.mutex.Lock()
	defer dam.mutex.Unlock()

	// Example logic to adjust weighting factors based on hypothetical network conditions
	if dam.averageUptime < dam.expectedUptime {
		dam.weightingFactors.UptimeWeight *= 1.1 // Increase importance of uptime
	} else {
		dam.weightingFactors.UptimeWeight *= 0.9 // Decrease importance of uptime
	}

	// Log changes for transparency and auditing
	logAdjustmentChanges(dam.weightingFactors)
}

// logAdjustmentChanges logs any changes to the weighting factors for audit purposes.
func logAdjustmentChanges(wf WeightingFactors) {
	// Implementation of logging changes to an audit log or similar
}

// GetReputationScore retrieves the reputation score for a specific validator.
func (dam *DynamicAdjustmentManager) GetReputationScore(validatorID string) float64 {
	dam.mutex.Lock()
	defer dam.mutex.Unlock()

	return dam.reputationScores[validatorID]
}
