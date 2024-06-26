package security

import (
	"errors"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
)

// MinimumStakeValidator manages the staking requirements for validators.
type MinimumStakeValidator struct {
	sync.Mutex
	Blockchain *blockchain.Blockchain
	MinStake   uint64 // Minimum amount of tokens required to become a validator.
}

// NewMinimumStakeValidator creates a new MinimumStakeValidator.
func NewMinimumStakeValidator(blockchain *blockchain.Blockchain, minStake uint64) *MinimumStakeValidator {
	return &MinimumStakeValidator{
		Blockchain: blockchain,
		MinStake:   minStake,
	}
}

// ValidateStake checks if the specified validator meets the minimum staking requirement.
func (msv *MinimumStakeValidator) ValidateStake(validatorID string) (bool, error) {
	msv.Lock()
	defer msv.Unlock()

	validator, exists := msv.Blockchain.GetValidator(validator.td)
	if !exists {
		return false, errors.New("validator not found")
	}

	if validator.Stake < msv.MinStake {
		return false, errors.New("validator does not meet minimum stake requirement")
	}

	return true, nil
}

// EnforceMinimumStake applies the minimum stake validation rule to all current validators.
func (msv *MinimumStakeValidator) EnforceMinimumStake() error {
	validators := msv.Blockchain.GetAllValidators()
	for id, _ := range validators {
		valid, err := msv.ValidateStake(id)
		if err != nil {
			return err
		}
		if !valid {
			return errors.New("one or more validators do not meet the minimum stake requirement")
		}
	}
	return nil
}

// UpdateStake allows updating the minimum stake requirement.
func (msv *MinimumStakeValidator) UpdateStake(newStake uint64) {
	msv.Lock()
	defer msv.Unlock()
	msv.MinStake = newStake
}

