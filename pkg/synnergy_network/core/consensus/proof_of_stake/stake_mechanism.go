package consensus

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"crypto/rand"
)

// StakeStore manages all staking operations and stores the stake details for each validator.
type StakeStore struct {
	stakes    map[string]*StakeDetail
	lock      sync.RWMutex
	minStake  *big.Int
	alpha     float64
}

// StakeDetail represents the details of a stake including the amount, start time, and lock-up duration.
type StakeDetail struct {
	Amount       *big.Int
	StartTime    time.Time
	LockUpPeriod time.Duration
}

// NewStakeStore creates a new instance of StakeStore with initialized values.
func NewStakeStore(minStake *big.Int, alpha float64) *StakeStore {
	return &StakeStore{
		stakes:   make(map[string]*StakeDetail),
		minStake: minStake,
		alpha:    alpha,
	}
}

// AddStake initializes a new stake or updates an existing stake for a validator.
func (s *StakeStore) AddStake(validatorID string, amount *big.Int) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if amount.Cmp(s.minStake) < 0 {
		return errors.New("stake amount is less than the minimum required")
	}

	if stake, exists := s.stakes[validatorID]; exists {
		stake.Amount.Add(stake.Amount, amount)
	} else {
		s.stakes[validatorID] = &StakeDetail{
			Amount:       amount,
			StartTime:    time.Now(),
			LockUpPeriod: calculateLockUpPeriod(amount, s.alpha),
		}
	}
	return nil
}

// calculateLockUpPeriod determines the lock-up period based on the staked amount using a dynamic formula.
func calculateLockUpPeriod(stakeAmount *big.Int, alpha float64) time.Duration {
	// The base duration could be dynamically adjusted based on the stake amount and alpha value
	baseDuration := time.Duration(90+int(alpha*30)) * 24 * time.Hour // Base lock-up period adjustment
	return baseDuration
}

// RemoveStake handles the unstaking process, ensuring that lock-up periods are respected.
func (s *StakeStore) RemoveStake(validatorID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	stake, exists := s.stakes[validatorID]
	if !exists {
		return errors.New("no stake found for validator")
	}

	if time.Since(stake.StartTime) < stake.LockUpPeriod {
		return errors.New("stake is still in the lock-up period")
	}

	delete(s.stakes, validatorID)
	return nil
}

// GetStakeDetails returns the stake details for a specific validator.
func (s *StakeStore) GetStakeDetails(validatorID string) (*StakeDetail, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	stake, exists := s.stakes[validatorID]
	if !exists {
		return nil, errors.New("no stake found for validator")
	}

	return stake, nil
}

// AdjustAlpha dynamically adjusts the alpha value based on market conditions and security needs.
func (s *StakeStore) AdjustAlpha(newAlpha float64) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.alpha = newAlpha
}

// SecureRandomStake selects a random stake detail securely for audit purposes or examples.
func (s *StakeStore) SecureRandomStake() (*StakeDetail, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keys := make([]string, 0, len(s.stakes))
	for k := range s.stakes {
		keys = append(keys, k)
	}

	if len(keys) == 0 {
		return nil, errors.New("no stakes available")
	}

	// Secure random selection
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(keys))))
	if err != nil {
		return nil, err
	}

	stake := s.stakes[keys[int(index.Int64())]]
	return stake, nil
}
