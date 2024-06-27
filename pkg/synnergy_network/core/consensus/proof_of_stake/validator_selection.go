package consensus

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/synthon/crypto/vrf"
)

// Validator represents a staker in the network with their stake details.
type Validator struct {
	ID        string
	Stake     *big.Int
	StartTime time.Time
	Duration  time.Duration // Duration they have been staking, to consider for weighted selection
}

// ValidatorPool holds the list of validators and performs operations related to validator selection.
type ValidatorPool struct {
	Validators map[string]*Validator
	VrfKey     []byte
}

// NewValidatorPool initializes the validator pool with a secure VRF key.
func NewValidatorPool() *ValidatorPool {
	vrfKey, err := rand.Prime(rand.Reader, 256) // Generate a secure VRF key
	if err != nil {
		panic("failed to generate a secure VRF key") // Handle error appropriately in production
	}
	return &ValidatorPool{
		Validators: make(map[string]*Validator),
		VrfKey:     vrfKey.Bytes(),
	}
}

// AddValidator adds or updates a validator in the pool.
func (vp *ValidatorPool) AddValidator(id string, stakeAmount *big.Int, duration time.Duration) {
	validator, exists := vp.Validators[id]
	if !exists {
		validator = &Validator{
			ID:        id,
			Stake:     big.NewInt(0),
			StartTime: time.Now(),
			Duration:  0,
		}
		vp.Validators[id] = validator
	}
	validator.Stake.Add(validator.Stake, stakeAmount)
	validator.Duration += duration
}

// SelectValidators selects a subset of validators for block creation using VRF for randomness.
func (vp *ValidatorPool) SelectValidators(seed []byte) ([]*Validator, error) {
	validatorList := make([]*Validator, 0, len(vp.Validators))
	for _, v := range vp.Validators {
		validatorList = append(validatorList, v)
	}

	proof, value, err := vrf.Prove(vp.VrfKey, seed)
	if err != nil {
		return nil, err
	}

	randomness := new(big.Int).SetBytes(value)
	sort.Slice(validatorList, func(i, j int) bool {
		return weightedSelection(validatorList[i], validatorList[j], randomness)
	})

	selectedValidators := selectTopValidatorsByStakeAndDuration(validatorList, 10) // Example: Select top 10%
	return selectedValidators, nil
}

// weightedSelection defines the criteria to sort validators based on stake, duration, and randomness.
func weightedSelection(a, b *Validator, randomness *big.Int) bool {
	// Enhance the selection logic to consider stake size, staking duration, and randomness
	stakeWeightA := new(big.Int).Mul(a.Stake, big.NewInt(int64(a.Duration.Hours())))
	stakeWeightB := new(big.Int).Mul(b.Stake, big.NewInt(int64(b.Duration.Hours())))
	return stakeWeightA.Cmp(stakeWeightB) > 0
}

// selectTopValidatorsByStakeAndDuration selects the top percentage of validators based on weighted stake.
func selectTopValidatorsByStakeAndDuration(validators []*Validator, percent int) []*Validator {
	numValidators := len(validators) * percent / 100
	if numValidators == 0 {
		numValidators = 1 // Ensure at least one validator is selected
	}
	return validators[:numValidators]
}

