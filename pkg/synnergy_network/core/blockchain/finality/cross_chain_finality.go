package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/consensus"
	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/types"
	"github.com/synnergy_network/utils"
)

// CrossChainFinalityManager handles the finality of transactions across multiple blockchain networks
type CrossChainFinalityManager struct {
	mutex           sync.RWMutex
	chainValidators map[string]map[string]string // ChainID -> ValidatorID -> PublicKey
	checkpoints     map[string]map[string]Checkpoint // ChainID -> BlockHash -> Checkpoint
	consensusEngine *consensus.Engine
}

// NewCrossChainFinalityManager creates a new CrossChainFinalityManager
func NewCrossChainFinalityManager(consensusEngine *consensus.Engine) *CrossChainFinalityManager {
	return &CrossChainFinalityManager{
		chainValidators: make(map[string]map[string]string),
		checkpoints:     make(map[string]map[string]Checkpoint),
		consensusEngine: consensusEngine,
	}
}

// RegisterValidator registers a validator for a specific chain
func (ccfm *CrossChainFinalityManager) RegisterValidator(chainID, validatorID, publicKey string) {
	ccfm.mutex.Lock()
	defer ccfm.mutex.Unlock()

	if _, exists := ccfm.chainValidators[chainID]; !exists {
		ccfm.chainValidators[chainID] = make(map[string]string)
	}
	ccfm.chainValidators[chainID][validatorID] = publicKey
}

// CreateCheckpoint creates a checkpoint for a given block hash on a specific chain
func (ccfm *CrossChainFinalityManager) CreateCheckpoint(chainID, blockHash, validatorID string) (Checkpoint, error) {
	ccfm.mutex.Lock()
	defer ccfm.mutex.Unlock()

	validators, exists := ccfm.chainValidators[chainID]
	if !exists {
		return Checkpoint{}, errors.New("chain not registered")
	}

	publicKey, validatorExists := validators[validatorID]
	if !validatorExists {
		return Checkpoint{}, errors.New("validator not registered")
	}

	timestamp := time.Now()
	data := chainID + blockHash + timestamp.String() + validatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := crypto.SignData(publicKey, hash[:])
	if err != nil {
		return Checkpoint{}, err
	}

	checkpoint := Checkpoint{
		BlockHash:   blockHash,
		Timestamp:   timestamp,
		ValidatorID: validatorID,
		Signature:   hex.EncodeToString(signature),
	}

	if _, exists := ccfm.checkpoints[chainID]; !exists {
		ccfm.checkpoints[chainID] = make(map[string]Checkpoint)
	}
	ccfm.checkpoints[chainID][blockHash] = checkpoint
	return checkpoint, nil
}

// ValidateCheckpoint validates a checkpoint for a specific chain
func (ccfm *CrossChainFinalityManager) ValidateCheckpoint(chainID string, checkpoint Checkpoint) (bool, error) {
	ccfm.mutex.RLock()
	defer ccfm.mutex.RUnlock()

	validators, exists := ccfm.chainValidators[chainID]
	if !exists {
		return false, errors.New("chain not registered")
	}

	publicKey, validatorExists := validators[checkpoint.ValidatorID]
	if !validatorExists {
		return false, errors.New("validator not registered")
	}

	data := chainID + checkpoint.BlockHash + checkpoint.Timestamp.String() + checkpoint.ValidatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := hex.DecodeString(checkpoint.Signature)
	if err != nil {
		return false, err
	}

	return crypto.VerifySignature(publicKey, hash[:], signature)
}

// IsCheckpointFinalized checks if a checkpoint is finalized based on consensus across multiple chains
func (ccfm *CrossChainFinalityManager) IsCheckpointFinalized(chainID, blockHash string) (bool, error) {
	ccfm.mutex.RLock()
	defer ccfm.mutex.RUnlock()

	checkpoint, exists := ccfm.checkpoints[chainID][blockHash]
	if !exists {
		return false, errors.New("checkpoint not found")
	}

	validators := ccfm.consensusEngine.GetValidators(chainID)
	requiredVotes := len(validators)/2 + 1

	votes := 0
	for _, validator := range validators {
		if ccfm.consensusEngine.HasValidatorVoted(chainID, blockHash, validator) {
			votes++
		}
	}

	return votes >= requiredVotes, nil
}

// PeriodicallyCreateCheckpoints creates checkpoints at regular intervals for all chains
func (ccfm *CrossChainFinalityManager) PeriodicallyCreateCheckpoints() {
	ticker := time.NewTicker(time.Duration(60) * time.Second) // Example interval, can be adjusted
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for chainID := range ccfm.chainValidators {
				latestBlockHash := ccfm.consensusEngine.GetLatestBlockHash(chainID)
				validatorID := ccfm.consensusEngine.GetCurrentValidator(chainID)
				_, err := ccfm.CreateCheckpoint(chainID, latestBlockHash, validatorID)
				if err != nil {
					fmt.Printf("Failed to create checkpoint for chain %s: %v\n", chainID, err)
				} else {
					fmt.Printf("Checkpoint created for chain %s, block hash: %s by validator: %s\n", chainID, latestBlockHash, validatorID)
				}
			}
		}
	}
}

// RetrieveCheckpoint retrieves a checkpoint by block hash for a specific chain
func (ccfm *CrossChainFinalityManager) RetrieveCheckpoint(chainID, blockHash string) (Checkpoint, error) {
	ccfm.mutex.RLock()
	defer ccfm.mutex.RUnlock()

	checkpoint, exists := ccfm.checkpoints[chainID][blockHash]
	if !exists {
		return Checkpoint{}, errors.New("checkpoint not found")
	}

	return checkpoint, nil
}

// ValidateAllCheckpoints validates all existing checkpoints across all chains
func (ccfm *CrossChainFinalityManager) ValidateAllCheckpoints() {
	ccfm.mutex.RLock()
	defer ccfm.mutex.RUnlock()

	for chainID, chainCheckpoints := range ccfm.checkpoints {
		for blockHash, checkpoint := range chainCheckpoints {
			valid, err := ccfm.ValidateCheckpoint(chainID, checkpoint)
			if err != nil {
				fmt.Printf("Failed to validate checkpoint for chain %s, block hash: %s, error: %v\n", chainID, blockHash, err)
			} else if !valid {
				fmt.Printf("Invalid checkpoint detected for chain %s, block hash: %s\n", chainID, blockHash)
			} else {
				fmt.Printf("Checkpoint for chain %s, block hash: %s is valid\n", chainID, blockHash)
			}
		}
	}
}

// MonitorCrossChainFinality continuously monitors and reports the finality status across chains
func (ccfm *CrossChainFinalityManager) MonitorCrossChainFinality() {
	for {
		time.Sleep(10 * time.Second) // Adjust monitoring interval as needed
		for chainID, chainCheckpoints := range ccfm.checkpoints {
			for blockHash := range chainCheckpoints {
				finalized, err := ccfm.IsCheckpointFinalized(chainID, blockHash)
				if err != nil {
					fmt.Printf("Error checking finality for chain %s, block hash: %s, error: %v\n", chainID, blockHash, err)
					continue
				}
				if finalized {
					fmt.Printf("Checkpoint for chain %s, block hash: %s is finalized\n", chainID, blockHash)
				} else {
					fmt.Printf("Checkpoint for chain %s, block hash: %s is not yet finalized\n", chainID, blockHash)
				}
			}
		}
	}
}
