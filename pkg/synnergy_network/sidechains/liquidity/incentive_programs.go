package liquidity

import (
	"errors"
	"sync"
	"time"
)

// IncentiveProgram represents an incentive program in the liquidity sidechain
type IncentiveProgram struct {
	mu                   sync.RWMutex
	name                 string
	description          string
	startTime            time.Time
	endTime              time.Time
	totalRewards         float64
	userParticipations   map[string]float64
	userRewards          map[string]float64
	rewardDistribution   time.Duration
	lastDistribution     time.Time
	eligibilityCriteria  func(userID string) bool
	participationCap     float64
}

// NewIncentiveProgram creates a new IncentiveProgram instance
func NewIncentiveProgram(name, description string, startTime, endTime time.Time, totalRewards float64, rewardDistribution time.Duration, eligibilityCriteria func(userID string) bool, participationCap float64) *IncentiveProgram {
	return &IncentiveProgram{
		name:                 name,
		description:          description,
		startTime:            startTime,
		endTime:              endTime,
		totalRewards:         totalRewards,
		userParticipations:   make(map[string]float64),
		userRewards:          make(map[string]float64),
		rewardDistribution:   rewardDistribution,
		lastDistribution:     time.Now(),
		eligibilityCriteria:  eligibilityCriteria,
		participationCap:     participationCap,
	}
}

// Participate allows a user to participate in the incentive program
func (ip *IncentiveProgram) Participate(userID string, amount float64) error {
	if time.Now().Before(ip.startTime) || time.Now().After(ip.endTime) {
		return errors.New("incentive program not active")
	}

	if !ip.eligibilityCriteria(userID) {
		return errors.New("user not eligible for participation")
	}

	if amount <= 0 {
		return errors.New("participation amount must be positive")
	}

	ip.mu.Lock()
	defer ip.mu.Unlock()

	totalParticipation := ip.userParticipations[userID] + amount
	if totalParticipation > ip.participationCap {
		return errors.New("participation cap exceeded")
	}

	ip.userParticipations[userID] = totalParticipation
	return nil
}

// DistributeRewards distributes rewards to participants based on their participations
func (ip *IncentiveProgram) DistributeRewards() error {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	if time.Now().Sub(ip.lastDistribution) < ip.rewardDistribution {
		return errors.New("reward distribution interval has not elapsed")
	}

	totalParticipations := 0.0
	for _, participation := range ip.userParticipations {
		totalParticipations += participation
	}

	if totalParticipations == 0 {
		return errors.New("no participations found")
	}

	for userID, participation := range ip.userParticipations {
		reward := (participation / totalParticipations) * ip.totalRewards
		ip.userRewards[userID] += reward
	}

	ip.lastDistribution = time.Now()
	return nil
}

// GetUserReward gets the total reward for a user
func (ip *IncentiveProgram) GetUserReward(userID string) (float64, error) {
	ip.mu.RLock()
	defer ip.mu.RUnlock()

	reward, exists := ip.userRewards[userID]
	if !exists {
		return 0, errors.New("user reward not found")
	}

	return reward, nil
}

// ListUserRewards lists all user rewards
func (ip *IncentiveProgram) ListUserRewards() map[string]float64 {
	ip.mu.RLock()
	defer ip.mu.RUnlock()

	rewards := make(map[string]float64)
	for userID, reward := range ip.userRewards {
		rewards[userID] = reward
	}

	return rewards
}

// WithdrawUserReward withdraws the reward for a user
func (ip *IncentiveProgram) WithdrawUserReward(userID string, amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}

	ip.mu.Lock()
	defer ip.mu.Unlock()

	reward, exists := ip.userRewards[userID]
	if !exists {
		return errors.New("user reward not found")
	}

	if reward < amount {
		return errors.New("insufficient reward balance")
	}

	ip.userRewards[userID] -= amount
	ip.totalRewards -= amount
	return nil
}

// AddRewardsToProgram adds rewards to the total rewards pool of the program
func (ip *IncentiveProgram) AddRewardsToProgram(amount float64) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}

	ip.mu.Lock()
	defer ip.mu.Unlock()

	ip.totalRewards += amount
	return nil
}

// ExtendProgram extends the duration of the incentive program
func (ip *IncentiveProgram) ExtendProgram(newEndTime time.Time) error {
	if newEndTime.Before(ip.endTime) {
		return errors.New("new end time must be after the current end time")
	}

	ip.mu.Lock()
	defer ip.mu.Unlock()

	ip.endTime = newEndTime
	return nil
}
