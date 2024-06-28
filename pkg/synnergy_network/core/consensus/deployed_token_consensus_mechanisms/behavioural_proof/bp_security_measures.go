package behavioural_proof

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"synnergy_network/pkg/utils"
)

// Validator represents a network node that participates in blockchain consensus.
type Validator struct {
	ID        string
	Reputation float64
	Uptime    float64
	Accuracy  float64
}

// ValidatorSecurityManager handles the security aspects of validators in the Behavioral Proof consensus mechanism.
type ValidatorSecurityManager struct {
	validators map[string]*Validator
	mutex      sync.RWMutex
}

// NewValidatorSecurityManager initializes a new instance of ValidatorSecurityManager.
func NewValidatorSecurityManager() *ValidatorSecurityManager {
	return &ValidatorSecurityManager{
		validators: make(map[string]*Validator),
	}
}

// RegisterValidator adds a new validator to the network with initial security parameters.
func (vsm *ValidatorSecurityManager) RegisterValidator(validatorID string, reputation, uptime, accuracy float64) error {
	vsm.mutex.Lock()
	defer vsm.mutex.Unlock()

	if _, exists := vsm.validators[validatorID]; exists {
		return errors.New("validator already registered")
	}

	vsm.validators[validatorID] = &Validator{
		ID:        validatorID,
		Reputation: reputation,
		Uptime:    uptime,
		Accuracy:  accuracy,
	}
	return nil
}

// CalculateReputationScore updates and calculates the reputation score for a validator based on their performance metrics.
func (vsm *ValidatorSecurityManager) CalculateReputationScore(validatorID string) (float64, error) {
	vsm.mutex.Lock()
	defer vsm.mutex.Unlock()

	validator, exists := vsm.validators[validatorID]
	if !exists {
		return 0, errors.New("validator not found")
	}

	uptimeScore := validator.Uptime * utils.UptimeWeight
	accuracyScore := validator.Accuracy * utils.AccuracyWeight
	reputationScore := uptimeScore + accuracyScore

	// Update the reputation score in the validator's profile
	validator.Reputation = reputationScore
	return reputationScore, nil
}

// EvaluateValidatorIntegrity checks the integrity of the validator's actions within the network.
func (vsm *ValidatorSecurityManager) EvaluateValidatorIntegrity(validatorID string, transactionHash []byte) (bool, error) {
	vsm.mutex.RLock()
	defer vsm.mutex.RUnlock()

	validator, exists := vsm.validators[validatorID]
	if !exists {
		return false, errors.New("validator not found")
	}

	// Simulate a check on the hash of the last transaction processed by the validator
	expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(validator.ID+time.Now().String())))
	actualHash := fmt.Sprintf("%x", transactionHash)

	return expectedHash == actualHash, nil
}

// ApplyPenalty reduces the validator's reputation based on the severity of the security breach.
func (vsm *ValidatorSecurityManager) ApplyPenalty(validatorID string, penalty float64) error {
	vsm.mutex.Lock()
	defer vsm.mutex.Unlock()

	validator, exists := vsm.validators[validatorID]
	if !exists {
		return errors.New("validator not found")
	}

	newReputation := validator.Reputation - penalty
	if newReputation < 0 {
		newReputation = 0
	}
	validator.Reputation = newReputation
	return nil
}
