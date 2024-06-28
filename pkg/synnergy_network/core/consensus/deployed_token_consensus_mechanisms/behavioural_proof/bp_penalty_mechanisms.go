package behavioural_proof

import (
	"fmt"
	"sync"
)

// PenaltyManager manages the application of penalties to validators based on their actions.
type PenaltyManager struct {
	mutex sync.RWMutex
	// Maps validator ID to their reputation and penalty records
	validatorPenalties map[string]*PenaltyRecord
}

// PenaltyRecord stores details of penalties for a validator.
type PenaltyRecord struct {
	UptimeScore      float64
	TransactionScore float64
	CommunityScore   float64
}

// NewPenaltyManager creates a new instance of PenaltyManager.
func NewPenaltyManager() *PenaltyManager {
	return &PenaltyManager{
		validatorPenalties: make(map[string]*PenaltyRecord),
	}
}

// RecordPenalty applies penalties to a validator based on different criteria.
func (pm *PenaltyManager) RecordPenalty(validatorID string, downtime, transactionErrors, communityImpact int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	penalty, exists := pm.validatorPenalties[validatorID]
	if !exists {
		penalty = &PenaltyRecord{}
		pm.validatorPenalties[validatorID] = penalty
	}

	// Calculate penalties
	downtimePenalty := calculateDowntimePenalty(downtime)
	transactionPenalty := calculateTransactionPenalty(transactionErrors)
	communityPenalty := calculateCommunityPenalty(communityImpact)

	// Apply penalties
	penalty.UptimeScore -= downtimePenalty
	penalty.TransactionScore -= transactionPenalty
	penalty.CommunityScore -= communityPenalty

	fmt.Printf("Penalties recorded for validator %s: Downtime: %.2f, Transaction Errors: %.2f, Community Impact: %.2f\n",
		validatorID, downtimePenalty, transactionPenalty, communityPenalty)
}

// calculateDowntimePenalty calculates the penalty for downtime based on its duration.
func calculateDowntimePenalty(downtime int) float64 {
	const penaltyFactor = 0.5 // Example penalty factor
	return float64(downtime) * penaltyFactor
}

// calculateTransactionPenalty calculates the penalty for transaction errors.
func calculateTransactionPenalty(errors int) float64 {
	const penaltyFactor = 0.3 // Example penalty factor
	return float64(errors) * penaltyFactor
}

// calculateCommunityPenalty calculates the penalty for negative community impacts.
func calculateCommunityPenalty(impact int) float64 {
	const penaltyFactor = 0.7 // Example penalty factor
	return float64(impact) * penaltyFactor
}

// GetPenaltyRecord retrieves the penalty record for a given validator.
func (pm *PenaltyManager) GetPenaltyRecord(validatorID string) *PenaltyRecord {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.validatorPenalties[validatorID]
}
