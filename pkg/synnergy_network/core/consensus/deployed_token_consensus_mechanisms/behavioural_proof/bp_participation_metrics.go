package behavioural_proof

import (
	"time"
	"sync"
)

// ParticipationMetricsManager manages and tracks validators' participation metrics.
type ParticipationMetricsManager struct {
	mutex sync.RWMutex
	// Maps validator ID to their participation records
	participationRecords map[string]*ParticipationRecord
}

// ParticipationRecord stores details of participation metrics for a validator.
type ParticipationRecord struct {
	LastOnlineTime     time.Time
	TransactionsValid  int
	TransactionsTotal  int
	CommunityScore     int
}

// NewParticipationMetricsManager creates a new instance of ParticipationMetricsManager.
func NewParticipationMetricsManager() *ParticipationMetricsManager {
	return &ParticipationMetricsManager{
		participationRecords: make(map[string]*ParticipationRecord),
	}
}

// UpdateUptime updates the last online time for a validator.
func (pm *ParticipationMetricsManager) UpdateUptime(validatorID string, lastOnline time.Time) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	record, exists := pm.participationRecords[validatorID]
	if !exists {
		record = &ParticipationRecord{}
		pm.participationRecords[validatorID] = record
	}
	record.LastOnlineTime = lastOnline
}

// UpdateTransactions updates the transaction metrics for a validator.
func (pm *ParticipationMetricsManager) UpdateTransactions(validatorID string, valid, total int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	record, exists := pm.participationRecords[validatorID]
	if !exists {
		record = &ParticipationRecord{}
		pm.participationRecords[validatorID] = record
	}
	record.TransactionsValid += valid
	record.TransactionsTotal += total
}

// UpdateCommunityScore updates the community score for a validator.
func (pm *ParticipationMetricsManager) UpdateCommunityScore(validatorID string, score int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	record, exists := pm.participationRecords[validatorID]
	if !exists {
		record = &ParticipationRecord{}
		pm.participationRecords[validatorID] = record
	}
	record.CommunityScore += score
}

// CalculateReputationScore calculates the reputation score for a validator.
func (pm *ParticipationMetricsManager) CalculateReputationScore(validatorID string) float64 {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	record, exists := pm.participationRecords[validatorID]
	if !exists {
		return 0
	}

	uptimeScore := calculateUptimeScore(record.LastOnlineTime)
	transactionAccuracy := calculateTransactionAccuracy(record.TransactionsValid, record.TransactionsTotal)
	communityScore := float64(record.CommunityScore)

	// Weighting factors (example values)
	alpha, beta, gamma := 0.35, 0.40, 0.25
	reputationScore := alpha*uptimeScore + beta*transactionAccuracy + gamma*communityScore
	return reputationScore
}

// calculateUptimeScore calculates the uptime score based on the last online timestamp.
func calculateUptimeScore(lastOnline time.Time) float64 {
	if time.Since(lastOnline) < 24*time.Hour {
		return 100.0 // Maximum score
	}
	return 0.0 // No score if offline for more than 24 hours
}

// calculateTransactionAccuracy calculates the accuracy of transactions processed.
func calculateTransactionAccuracy(valid, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(valid) / float64(total)) * 100.0
}

