package dynamic_consensus_algorithms

import (
	"log"
	"math"
	"sync"
	"time"

	"github.com/synnergy_network/core/consensus/metrics"
	"github.com/synnergy_network/core/consensus/security"
	"github.com/synnergy_network/core/consensus/utils"
)

// DynamicRewardsAndFees represents the structure for dynamic rewards and fee distribution
type DynamicRewardsAndFees struct {
	mu                 sync.Mutex
	baseReward         float64
	maxPerformance     float64
	feeDistribution    []ValidatorFeeShare
	rewardHistory      []RewardRecord
	feeDistributionLog []FeeDistributionRecord
}

// ValidatorPerformance represents the performance metrics of a validator
type ValidatorPerformance struct {
	ValidatorID   string
	PerformanceScore float64
}

// ValidatorFeeShare represents the fee share for a validator
type ValidatorFeeShare struct {
	ValidatorID string
	FeeShare    float64
}

// RewardRecord represents a record of reward distribution
type RewardRecord struct {
	Timestamp    time.Time
	ValidatorID  string
	RewardAmount float64
}

// FeeDistributionRecord represents a record of fee distribution
type FeeDistributionRecord struct {
	Timestamp      time.Time
	ValidatorID    string
	FeeShareAmount float64
}

// InitializeRewardsAndFees initializes the rewards and fee distribution structure
func (drf *DynamicRewardsAndFees) InitializeRewardsAndFees(baseReward float64, maxPerformance float64) {
	drf.mu.Lock()
	defer drf.mu.Unlock()

	drf.baseReward = baseReward
	drf.maxPerformance = maxPerformance
	drf.rewardHistory = []RewardRecord{}
	drf.feeDistributionLog = []FeeDistributionRecord{}
}

// CalculateDynamicRewards calculates and distributes dynamic rewards based on validator performance
func (drf *DynamicRewardsAndFees) CalculateDynamicRewards(validatorPerformances []ValidatorPerformance) {
	drf.mu.Lock()
	defer drf.mu.Unlock()

	for _, vp := range validatorPerformances {
		rewardAmount := drf.baseReward * (1 + vp.PerformanceScore/drf.maxPerformance)
		rewardRecord := RewardRecord{
			Timestamp:    time.Now(),
			ValidatorID:  vp.ValidatorID,
			RewardAmount: rewardAmount,
		}
		drf.rewardHistory = append(drf.rewardHistory, rewardRecord)
		log.Printf("Distributed reward: %+v", rewardRecord)
	}
}

// DistributeTransactionFees distributes transaction fees among validators based on their performance contribution
func (drf *DynamicRewardsAndFees) DistributeTransactionFees(totalFees float64, validatorPerformances []ValidatorPerformance) {
	drf.mu.Lock()
	defer drf.mu.Unlock()

	totalPerformance := float64(0)
	for _, vp := range validatorPerformances {
		totalPerformance += vp.PerformanceScore
	}

	for _, vp := range validatorPerformances {
		feeShare := totalFees * (vp.PerformanceScore / totalPerformance)
		feeRecord := FeeDistributionRecord{
			Timestamp:      time.Now(),
			ValidatorID:    vp.ValidatorID,
			FeeShareAmount: feeShare,
		}
		drf.feeDistributionLog = append(drf.feeDistributionLog, feeRecord)
		log.Printf("Distributed fee share: %+v", feeRecord)
	}
}

// GetRewardHistory returns the history of reward distributions
func (drf *DynamicRewardsAndFees) GetRewardHistory() []RewardRecord {
	drf.mu.Lock()
	defer drf.mu.Unlock()

	return drf.rewardHistory
}

// GetFeeDistributionLog returns the log of fee distributions
func (drf *DynamicRewardsAndFees) GetFeeDistributionLog() []FeeDistributionRecord {
	drf.mu.Lock()
	defer drf.mu.Unlock()

	return drf.feeDistributionLog
}

// Example usage
func main() {
	rewardsAndFees := DynamicRewardsAndFees{}
	rewardsAndFees.InitializeRewardsAndFees(10.0, 100.0)

	validatorPerformances := []ValidatorPerformance{
		{ValidatorID: "validator_1", PerformanceScore: 80},
		{ValidatorID: "validator_2", PerformanceScore: 60},
		{ValidatorID: "validator_3", PerformanceScore: 90},
	}

	rewardsAndFees.CalculateDynamicRewards(validatorPerformances)
	rewardsAndFees.DistributeTransactionFees(100.0, validatorPerformances)
}
