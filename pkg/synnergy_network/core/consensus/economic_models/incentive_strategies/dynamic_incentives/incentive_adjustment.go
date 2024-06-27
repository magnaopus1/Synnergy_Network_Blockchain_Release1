package dynamic_incentives

import (
	"errors"
	"sync"
)

// Constants for dynamic incentives adjustment
const (
	BaseReward     = 10.0
	MaxPerformance = 100.0
)

// User represents a participant in the network
type User struct {
	ID               string
	Stake            float64
	PerformanceScore float64
}

// NetworkMetrics represents the overall performance metrics of the network
type NetworkMetrics struct {
	PerformanceScore      float64
	TotalTransactionVolume float64
}

// IncentiveSystem represents the incentive calculation system
type IncentiveSystem struct {
	mu              sync.Mutex
	Users           map[string]*User
	NetworkMetrics  NetworkMetrics
	TotalStake      float64
}

// NewIncentiveSystem creates a new IncentiveSystem instance
func NewIncentiveSystem() *IncentiveSystem {
	return &IncentiveSystem{
		Users: make(map[string]*User),
	}
}

// AddUser adds a new user to the incentive system
func (is *IncentiveSystem) AddUser(id string, stake, performanceScore float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Users[id] = &User{
		ID:               id,
		Stake:            stake,
		PerformanceScore: performanceScore,
	}
	is.TotalStake += stake
}

// CalculateDynamicIncentive calculates the dynamic incentive for a user
func (is *IncentiveSystem) CalculateDynamicIncentive(user *User) float64 {
	return BaseReward * (1 + user.PerformanceScore/MaxPerformance)
}

// CalculateIncentives calculates the incentives for all users
func (is *IncentiveSystem) CalculateIncentives() map[string]float64 {
	is.mu.Lock()
	defer is.mu.Unlock()
	incentives := make(map[string]float64)
	for id, user := range is.Users {
		incentives[id] = is.CalculateDynamicIncentive(user)
	}
	return incentives
}

// AdjustPerformanceScore adjusts the performance score of a user
func (is *IncentiveSystem) AdjustPerformanceScore(userID string, adjustment float64) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return errors.New("user not found")
	}
	user.PerformanceScore += adjustment
	if user.PerformanceScore > MaxPerformance {
		user.PerformanceScore = MaxPerformance
	} else if user.PerformanceScore < 0 {
		user.PerformanceScore = 0
	}
	return nil
}

// UpdateNetworkMetrics updates the network performance metrics
func (is *IncentiveSystem) UpdateNetworkMetrics(performanceScore, totalTransactionVolume float64) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.NetworkMetrics.PerformanceScore = performanceScore
	is.NetworkMetrics.TotalTransactionVolume = totalTransactionVolume
}

// GetUserPerformanceScore gets the performance score of a user
func (is *IncentiveSystem) GetUserPerformanceScore(userID string) (float64, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return 0, errors.New("user not found")
	}
	return user.PerformanceScore, nil
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

// StakeBasedAllocation calculates stake-based resource allocation for a user
func (is *IncentiveSystem) StakeBasedAllocation(userID string) (float64, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	user, exists := is.Users[userID]
	if !exists {
		return 0, errors.New("user not found")
	}
	if is.TotalStake == 0 {
		return 0, errors.New("total stake is zero")
	}
	return (user.Stake / is.TotalStake), nil
}

// TransactionImportance calculates transaction importance
func (is *IncentiveSystem) TransactionImportance(value, priority, size float64) float64 {
	return (value + priority) / size
}

// FeeRedistribution calculates the redistributed fee for validators
func (is *IncentiveSystem) FeeRedistribution(collectedFees float64, numValidators int) float64 {
	if numValidators == 0 {
		return 0
	}
	return collectedFees / float64(numValidators)
}

// ZeroFeeEligibility checks if a transaction is eligible for zero fee
func (is *IncentiveSystem) ZeroFeeEligibility(transactionType string, value float64) bool {
	switch transactionType {
	case "sustainability":
		return true
	case "microtransaction":
		if value < 1.0 {
			return true
		}
	}
	return false
}

// CalculateVariableFee calculates the variable fee based on transaction volume
func (is *IncentiveSystem) CalculateVariableFee(baseFee, transactionVolume, maxVolume float64) float64 {
	return baseFee * (1 + (transactionVolume / maxVolume))
}
