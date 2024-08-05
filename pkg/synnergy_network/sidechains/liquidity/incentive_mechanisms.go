package liquidity

import (
	"errors"
	"sync"
	"time"
)

// IncentiveMechanism represents the incentive mechanism for the liquidity sidechain
type IncentiveMechanism struct {
	mu                  sync.RWMutex
	rewardsPool         float64
	userRewards         map[string]float64
	stakingRates        map[string]float64
	transactionRewards  map[string]float64
	rewardDistribution  time.Duration
	lastDistribution    time.Time
}

// NewIncentiveMechanism creates a new IncentiveMechanism instance
func NewIncentiveMechanism(initialPool float64, rewardDistribution time.Duration) *IncentiveMechanism {
	return &IncentiveMechanism{
		rewardsPool:         initialPool,
		userRewards:         make(map[string]float64),
		stakingRates:        make(map[string]float64),
		transactionRewards:  make(map[string]float64),
		rewardDistribution:  rewardDistribution,
		lastDistribution:    time.Now(),
	}
}

// AddStakingRate adds or updates a staking rate for a user
func (im *IncentiveMechanism) AddStakingRate(userID string, rate float64) error {
	if rate <= 0 {
		return errors.New("staking rate must be positive")
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	im.stakingRates[userID] = rate
	return nil
}

// RemoveStakingRate removes a staking rate for a user
func (im *IncentiveMechanism) RemoveStakingRate(userID string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, exists := im.stakingRates[userID]; !exists {
		return errors.New("staking rate not found for user")
	}

	delete(im.stakingRates, userID)
	return nil
}

// AddTransactionReward adds or updates a transaction reward for a user
func (im *IncentiveMechanism) AddTransactionReward(userID string, reward float64) error {
	if reward <= 0 {
		return errors.New("transaction reward must be positive")
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	im.transactionRewards[userID] = reward
	return nil
}

// RemoveTransactionReward removes a transaction reward for a user
func (im *IncentiveMechanism) RemoveTransactionReward(userID string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, exists := im.transactionRewards[userID]; !exists {
		return errors.New("transaction reward not found for user")
	}

	delete(im.transactionRewards, userID)
	return nil
}

// DistributeRewards distributes rewards to users based on their staking rates and transaction rewards
func (im *IncentiveMechanism) DistributeRewards() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if time.Now().Sub(im.lastDistribution) < im.rewardDistribution {
		return errors.New("reward distribution interval has not elapsed")
	}

	totalStakingRates := 0.0
	for _, rate := range im.stakingRates {
		totalStakingRates += rate
	}

	if totalStakingRates == 0 {
		return errors.New("no staking rates found")
	}

	for userID, rate := range im.stakingRates {
		stakingReward := (rate / totalStakingRates) * im.rewardsPool
		transactionReward, exists := im.transactionRewards[userID]
		if !exists {
			transactionReward = 0
		}

		im.userRewards[userID] += stakingReward + transactionReward
	}

	im.lastDistribution = time.Now()
	return nil
}

// GetUserReward gets the total reward for a user
func (im *IncentiveMechanism) GetUserReward(userID string) (float64, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()

	reward, exists := im.userRewards[userID]
	if !exists {
		return 0, errors.New("user reward not found")
	}

	return reward, nil
}

// ListUserRewards lists all user rewards
func (im *IncentiveMechanism) ListUserRewards() map[string]float64 {
	im.mu.RLock()
	defer im.mu.RUnlock()

	rewards := make(map[string]float64)
	for userID, reward := range im.userRewards {
		rewards[userID] = reward
	}

	return rewards
}

// AddRewardsToPool adds rewards to the rewards pool
func (im *IncentiveMechanism) AddRewardsToPool(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	im.rewardsPool += amount
	return nil
}

// WithdrawUserReward withdraws the reward for a user
func (im *IncentiveMechanism) WithdrawUserReward(userID string, amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	reward, exists := im.userRewards[userID]
	if !exists {
		return errors.New("user reward not found")
	}

	if reward < amount {
		return errors.New("insufficient reward balance")
	}

	im.userRewards[userID] -= amount
	im.rewardsPool -= amount
	return nil
}
