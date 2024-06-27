package incentive_strategies

import (
	"errors"
	"sync"
)

// Constants for incentive calculations
const (
	BaseBehavioralReward = 20.0
	BaseDynamicReward    = 30.0
)

// IncentiveType defines different types of incentives
type IncentiveType int

const (
	Behavioral IncentiveType = iota
	Dynamic
)

// NetworkPerformance holds network performance metrics
type NetworkPerformance struct {
	Score  float64
	MaxScore float64
}

// User represents a participant in the network
type User struct {
	ID                string
	ContributionScore float64
	Stake             float64
}

// IncentiveSystem represents the incentive distribution system
type IncentiveSystem struct {
	mu                 sync.Mutex
	Users              map[string]*User
	TotalContribution  float64
	NetworkPerformance NetworkPerformance
}

// NewIncentiveSystem creates a new IncentiveSystem instance
func NewIncentiveSystem(maxNetworkScore float64) *IncentiveSystem {
	return &IncentiveSystem{
		Users: make(map[string]*User),
		NetworkPerformance: NetworkPerformance{
			Score: 0,
			MaxScore: maxNetworkScore,
		},
	}
}

// AddUser adds a new user to the incentive system
func (is *IncentiveSystem) AddUser(id string, contributionScore, stake float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Users[id] = &User{
		ID:                id,
		ContributionScore: contributionScore,
		Stake:             stake,
	}
	is.TotalContribution += contributionScore
}

// CalculateBehavioralIncentive calculates the behavioral incentive for a user
func (is *IncentiveSystem) CalculateBehavioralIncentive(user *User) float64 {
	return BaseBehavioralReward * (1 + (user.ContributionScore / is.MaxContributionScore()))
}

// CalculateDynamicIncentive calculates the dynamic incentive for a user based on network performance
func (is *IncentiveSystem) CalculateDynamicIncentive(user *User) float64 {
	return BaseDynamicReward * (1 + (is.NetworkPerformance.Score / is.NetworkPerformance.MaxScore))
}

// DistributeIncentives distributes incentives to all users based on their contributions and network performance
func (is *IncentiveSystem) DistributeIncentives(incentiveType IncentiveType) (map[string]float64, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	incentives := make(map[string]float64)
	for id, user := range is.Users {
		switch incentiveType {
		case Behavioral:
			incentives[id] = is.CalculateBehavioralIncentive(user)
		case Dynamic:
			incentives[id] = is.CalculateDynamicIncentive(user)
		default:
			return nil, errors.New("invalid incentive type")
		}
	}
	return incentives, nil
}

// MaxContributionScore calculates the maximum contribution score among all users
func (is *IncentiveSystem) MaxContributionScore() float64 {
	maxScore := 0.0
	for _, user := range is.Users {
		if user.ContributionScore > maxScore {
			maxScore = user.ContributionScore
		}
	}
	return maxScore
}

// AdjustContributionScore adjusts the contribution score of a user
func (is *IncentiveSystem) AdjustContributionScore(userID string, adjustment float64) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	user.ContributionScore += adjustment
	if user.ContributionScore < 0 {
		user.ContributionScore = 0
	}
	is.TotalContribution += adjustment
	return nil
}

// GetUserContributionScore gets the contribution score of a user
func (is *IncentiveSystem) GetUserContributionScore(userID string) (float64, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return 0, errors.New("user not found")
	}
	return user.ContributionScore, nil
}

// ListUsers returns a list of all users in the incentive system
func (is *IncentiveSystem) ListUsers() []*User {
	is.mu.Lock()
	defer is.mu.Unlock()
	users := []*User{}
	for _, user := range is.Users {
		users = append(users, user)
	}
	return users
}

// UpdateNetworkPerformance updates the network performance metrics
func (is *IncentiveSystem) UpdateNetworkPerformance(score float64) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	if score < 0 || score > is.NetworkPerformance.MaxScore {
		return errors.New("invalid network performance score")
	}
	is.NetworkPerformance.Score = score
	return nil
}
