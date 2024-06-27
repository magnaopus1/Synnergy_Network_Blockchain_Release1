package token_rewards

import (
	"errors"
	"sync"
)

// Constants for reward calculations
const (
	BaseStakingReward     = 50.0
	BaseDevelopmentReward = 100.0
	BaseGovernanceReward  = 25.0
)

// RewardType defines different types of rewards
type RewardType int

const (
	Staking RewardType = iota
	Development
	Governance
)

// User represents a participant in the network
type User struct {
	ID                string
	Stake             float64
	ContributionScore float64
}

// TokenRewardSystem represents the token reward distribution system
type TokenRewardSystem struct {
	mu          sync.Mutex
	Users       map[string]*User
	TotalTokens float64
}

// NewTokenRewardSystem creates a new TokenRewardSystem instance
func NewTokenRewardSystem(totalTokens float64) *TokenRewardSystem {
	return &TokenRewardSystem{
		Users:       make(map[string]*User),
		TotalTokens: totalTokens,
	}
}

// AddUser adds a new user to the reward system
func (trs *TokenRewardSystem) AddUser(id string, stake, contributionScore float64) {
	trs.mu.Lock()
	defer trs.mu.Unlock()
	trs.Users[id] = &User{
		ID:                id,
		Stake:             stake,
		ContributionScore: contributionScore,
	}
}

// CalculateStakingReward calculates the staking reward for a user
func (trs *TokenRewardSystem) CalculateStakingReward(user *User) float64 {
	return BaseStakingReward * (user.Stake / trs.TotalStake())
}

// CalculateDevelopmentReward calculates the development reward for a user
func (trs *TokenRewardSystem) CalculateDevelopmentReward(user *User) float64 {
	return BaseDevelopmentReward * (user.ContributionScore / trs.MaxContributionScore())
}

// CalculateGovernanceReward calculates the governance reward for a user
func (trs *TokenRewardSystem) CalculateGovernanceReward(user *User) float64 {
	return BaseGovernanceReward * (user.ContributionScore / trs.MaxContributionScore())
}

// DistributeRewards distributes rewards to all users based on their contributions
func (trs *TokenRewardSystem) DistributeRewards(rewardType RewardType) (map[string]float64, error) {
	trs.mu.Lock()
	defer trs.mu.Unlock()
	rewards := make(map[string]float64)
	for id, user := range trs.Users {
		switch rewardType {
		case Staking:
			rewards[id] = trs.CalculateStakingReward(user)
		case Development:
			rewards[id] = trs.CalculateDevelopmentReward(user)
		case Governance:
			rewards[id] = trs.CalculateGovernanceReward(user)
		default:
			return nil, errors.New("invalid reward type")
		}
	}
	return rewards, nil
}

// TotalStake calculates the total stake of all users
func (trs *TokenRewardSystem) TotalStake() float64 {
	totalStake := 0.0
	for _, user := range trs.Users {
		totalStake += user.Stake
	}
	return totalStake
}

// MaxContributionScore calculates the maximum contribution score among all users
func (trs *TokenRewardSystem) MaxContributionScore() float64 {
	maxScore := 0.0
	for _, user := range trs.Users {
		if user.ContributionScore > maxScore {
			maxScore = user.ContributionScore
		}
	}
	return maxScore
}

// AdjustContributionScore adjusts the contribution score of a user
func (trs *TokenRewardSystem) AdjustContributionScore(userID string, adjustment float64) error {
	trs.mu.Lock()
	defer trs.mu.Unlock()
	user, exists := trs.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	user.ContributionScore += adjustment
	if user.ContributionScore < 0 {
		user.ContributionScore = 0
	}
	return nil
}

// GetUserContributionScore gets the contribution score of a user
func (trs *TokenRewardSystem) GetUserContributionScore(userID string) (float64, error) {
	trs.mu.Lock()
	defer trs.mu.Unlock()
	user, exists := trs.Users[userID]
	if !exists {
		return 0, errors.New("user not found")
	}
	return user.ContributionScore, nil
}

// ListUsers returns a list of all users in the reward system
func (trs *TokenRewardSystem) ListUsers() []*User {
	trs.mu.Lock()
	defer trs.mu.Unlock()
	users := []*User{}
	for _, user := range trs.Users {
		users = append(users, user)
	}
	return users
}

// VerifyTotalTokens verifies if the total distributed tokens match the system's total tokens
func (trs *TokenRewardSystem) VerifyTotalTokens(distributedRewards map[string]float64) bool {
	totalDistributed := 0.0
	for _, reward := range distributedRewards {
		totalDistributed += reward
	}
	return totalDistributed <= trs.TotalTokens
}

// TransferTokens transfers tokens from the system to the users based on their rewards
func (trs *TokenRewardSystem) TransferTokens(distributedRewards map[string]float64) error {
	if !trs.VerifyTotalTokens(distributedRewards) {
		return errors.New("distributed rewards exceed total tokens")
	}
	for id, reward := range distributedRewards {
		trs.Users[id].Stake += reward
	}
	trs.TotalTokens -= trs.sumRewards(distributedRewards)
	return nil
}

// sumRewards calculates the sum of all distributed rewards
func (trs *TokenRewardSystem) sumRewards(rewards map[string]float64) float64 {
	total := 0.0
	for _, reward := range rewards {
		total += reward
	}
	return total
}
