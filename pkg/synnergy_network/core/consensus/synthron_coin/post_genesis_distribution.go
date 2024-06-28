package synthron_coin

import (
	"time"
)

// RewardDistribution handles the distribution of mining and staking rewards
type RewardDistribution struct {
	Validators map[string]float64 // Validator ID and their rewards
	Stakers    map[string]float64 // Staker ID and their rewards
}

// StakingPool represents the staking mechanism details
type StakingPool struct {
	TotalStaked    float64
	StakeRewards   map[string]float64 // Staker ID and rewards
	StakeTimestamp map[string]time.Time // Track when stakes were made
}

// InitializeRewardDistribution sets up the reward distribution system
func InitializeRewardDistribution() *RewardDistribution {
	return &RewardDistribution{
		Validators: make(map[string]float64),
		Stakers:    make(map[string]float64),
	}
}

// DistributeRewards handles the distribution of rewards to validators and stakers
func (rd *RewardDistribution) DistributeRewards(blockHeight int, transactionFees, blockReward float64) {
	// Simplified distribution logic
	for id := range rd.Validators {
		rd.Validators[id] += blockReward * 0.5 / float64(len(rd.Validators)) // 50% to validators
	}
	for id := range rd.Stakers {
		rd.Stakers[id] += transactionFees * 0.5 / float64(len(rd.Stakers)) // 50% to stakers from fees
	}
}

// InitializeStakingPool initializes the staking pool for network participants
func InitializeStakingPool() *StakingPool {
	return &StakingPool{
		TotalStaked:  0,
		StakeRewards: make(map[string]float64),
		StakeTimestamp: make(map[string]time.Time),
	}
}

// AddStake adds a stake to the staking pool
func (sp *StakingPool) AddStake(stakerID string, amount float64) {
	sp.TotalStaked += amount
	sp.StakeRewards[stakerID] = 0 // Initialize rewards for this staker
	sp.StakeTimestamp[stakerID] = time.Now()
}

// CalculateStakingRewards periodically updates rewards for all stakers based on staked amount and time
func (sp *StakingPool) CalculateStakingRewards(currentTime time.Time) {
	for id, stakeTime := range sp.StakeTimestamp {
		// Simplified: Reward based on how long the coins have been staked
		duration := currentTime.Sub(stakeTime).Hours()
		sp.StakeRewards[id] += 0.0001 * duration // 0.01% interest per hour staked
	}
}

