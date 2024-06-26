package finality

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network/consensus"
	"github.com/synnergy_network/crypto"
	"github.com/synnergy_network/types"
	"github.com/synnergy_network/utils"
)

// FinalityManager manages finality within the Synnergy Network.
type FinalityManager struct {
	mutex           sync.RWMutex
	finalizedBlocks map[string]FinalizedBlock
	validators      map[string]Validator
	consensusEngine *consensus.Engine
}

// NewFinalityManager creates a new FinalityManager.
func NewFinalityManager(consensusEngine *consensus.Engine) *FinalityManager {
	return &FinalityManager{
		finalizedBlocks: make(map[string]FinalizedBlock),
		validators:      make(map[string]Validator),
		consensusEngine: consensusEngine,
	}
}

// RegisterValidator registers a new validator for the network.
func (fm *FinalityManager) RegisterValidator(validator Validator) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	fm.validators[validator.ID] = validator
}

// CreateFinalizedBlock marks a block as finalized.
func (fm *FinalityManager) CreateFinalizedBlock(blockHash, validatorID string) (FinalizedBlock, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	validator, exists := fm.validators[validatorID]
	if !exists {
		return FinalizedBlock{}, errors.New("validator not registered")
	}

	timestamp := time.Now()
	data := blockHash + timestamp.String() + validatorID
	hash := crypto.HashData([]byte(data))
	signature, err := crypto.SignData(validator.PrivateKey, hash)
	if err != nil {
		return FinalizedBlock{}, err
	}

	finalizedBlock := FinalizedBlock{
		BlockHash:   blockHash,
		Timestamp:   timestamp,
		ValidatorID: validatorID,
		Signature:   signature,
	}
	fm.finalizedBlocks[blockHash] = finalizedBlock
	return finalizedBlock, nil
}

// IsBlockFinalized checks if a block is finalized.
func (fm *FinalityManager) IsBlockFinalized(blockHash string) (bool, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	_, exists := fm.finalizedBlocks[blockHash]
	return exists, nil
}

// ValidateFinalizedBlock validates a given finalized block.
func (fm *FinalityManager) ValidateFinalizedBlock(finalizedBlock FinalizedBlock) (bool, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	validator, exists := fm.validators[finalizedBlock.ValidatorID]
	if !exists {
		return false, errors.New("validator not registered")
	}

	data := finalizedBlock.BlockHash + finalizedBlock.Timestamp.String() + finalizedBlock.ValidatorID
	hash := crypto.HashData([]byte(data))

	return crypto.VerifySignature(validator.PublicKey, hash, finalizedBlock.Signature)
}

// PeriodicallyCreateFinalizedBlocks creates finalized blocks at regular intervals.
func (fm *FinalityManager) PeriodicallyCreateFinalizedBlocks() {
	ticker := time.NewTicker(time.Duration(60) * time.Second) // Example interval, can be adjusted
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			latestBlockHash := fm.consensusEngine.GetLatestBlockHash()
			validatorID := fm.consensusEngine.GetCurrentValidator()
			_, err := fm.CreateFinalizedBlock(latestBlockHash, validatorID)
			if err != nil {
				fmt.Printf("Failed to create finalized block: %v\n", err)
			} else {
				fmt.Printf("Finalized block created for block hash: %s by validator: %s\n", latestBlockHash, validatorID)
			}
		}
	}
}

// MonitorFinalizedBlocks continuously monitors and reports the finalization status.
func (fm *FinalityManager) MonitorFinalizedBlocks() {
	for {
		time.Sleep(10 * time.Second) // Adjust monitoring interval as needed
		for blockHash := range fm.finalizedBlocks {
			finalized, err := fm.IsBlockFinalized(blockHash)
			if err != nil {
				fmt.Printf("Error checking finality for block hash: %s, error: %v\n", blockHash, err)
				continue
			}
			if finalized {
				fmt.Printf("Block hash: %s is finalized\n", blockHash)
			} else {
				fmt.Printf("Block hash: %s is not yet finalized\n", blockHash)
			}
		}
	}
}

// GetFinalizedBlockMetrics provides real-time finalized block metrics.
func (fm *FinalityManager) GetFinalizedBlockMetrics() map[string]interface{} {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	metrics := make(map[string]interface{})
	finalizedCount := len(fm.finalizedBlocks)

	metrics["finalized_blocks"] = finalizedCount
	metrics["validators"] = len(fm.validators)
	metrics["last_finalized_time"] = time.Now() // Example placeholder

	return metrics
}

// FinalizedBlock represents a finalized block in the blockchain.
type FinalizedBlock struct {
	BlockHash   string    `json:"block_hash"`
	Timestamp   time.Time `json:"timestamp"`
	ValidatorID string    `json:"validator_id"`
	Signature   string    `json:"signature"`
}

// Validator represents a validator in the network.
type Validator struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}
