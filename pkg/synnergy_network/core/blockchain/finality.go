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



// NewCheckpointManager creates a new CheckpointManager
func NewCheckpointManager(consensusEngine *consensus.Engine, checkpointPeriod int) *CheckpointManager {
    return &CheckpointManager{
        checkpoints:      make(map[string]Checkpoint),
        validators:       make(map[string]string),
        consensusEngine:  consensusEngine,
        checkpointPeriod: checkpointPeriod,
    }
}

// RegisterValidator registers a validator with the checkpoint manager
func (cm *CheckpointManager) RegisterValidator(validatorID, publicKey string) {
    cm.mutex.Lock()
    defer cm.mutex.Unlock()
    cm.validators[validatorID] = publicKey
}

// CreateCheckpoint creates a new checkpoint for a given block hash
func (cm *CheckpointManager) CreateCheckpoint(blockHash string, validatorID string) (Checkpoint, error) {
    cm.mutex.Lock()
    defer cm.mutex.Unlock()

    if _, exists := cm.validators[validatorID]; !exists {
        return Checkpoint{}, errors.New("validator not registered")
    }

    timestamp := time.Now()
    data := blockHash + timestamp.String() + validatorID
    hash := sha256.Sum256([]byte(data))
    signature, err := crypto.SignData(cm.validators[validatorID], hash[:])
    if err != nil {
        return Checkpoint{}, err
    }

    checkpoint := Checkpoint{
        BlockHash:   blockHash,
        Timestamp:   timestamp,
        ValidatorID: validatorID,
        Signature:   hex.EncodeToString(signature),
    }

    cm.checkpoints[blockHash] = checkpoint
    return checkpoint, nil
}

// ValidateCheckpoint validates a checkpoint
func (cm *CheckpointManager) ValidateCheckpoint(checkpoint Checkpoint) (bool, error) {
    cm.mutex.RLock()
    defer cm.mutex.RUnlock()

    publicKey, exists := cm.validators[checkpoint.ValidatorID]
    if !exists {
        return false, errors.New("validator not registered")
    }

    data := checkpoint.BlockHash + checkpoint.Timestamp.String() + checkpoint.ValidatorID
    hash := sha256.Sum256([]byte(data))
    signature, err := hex.DecodeString(checkpoint.Signature)
    if err != nil {
        return false, err
    }

    return crypto.VerifySignature(publicKey, hash[:], signature)
}

// IsCheckpointFinalized checks if a checkpoint is finalized based on consensus
func (cm *CheckpointManager) IsCheckpointFinalized(blockHash string) (bool, error) {
    cm.mutex.RLock()
    defer cm.mutex.RUnlock()

    checkpoint, exists := cm.checkpoints[blockHash]
    if !exists {
        return false, errors.New("checkpoint not found")
    }

    validators := cm.consensusEngine.GetValidators()
    requiredVotes := len(validators)/2 + 1

    votes := 0
    for _, validator := range validators {
        if cm.consensusEngine.HasValidatorVoted(blockHash, validator) {
            votes++
        }
    }

    return votes >= requiredVotes, nil
}

// PeriodicallyCreateCheckpoints creates checkpoints at regular intervals
func (cm *CheckpointManager) PeriodicallyCreateCheckpoints() {
    ticker := time.NewTicker(time.Duration(cm.checkpointPeriod) * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            latestBlockHash := cm.consensusEngine.GetLatestBlockHash()
            validatorID := cm.consensusEngine.GetCurrentValidator()
            _, err := cm.CreateCheckpoint(latestBlockHash, validatorID)
            if err != nil {
                fmt.Printf("Failed to create checkpoint: %v\n", err)
            } else {
                fmt.Printf("Checkpoint created for block hash: %s by validator: %s\n", latestBlockHash, validatorID)
            }
        }
    }
}

// RetrieveCheckpoint retrieves a checkpoint by block hash
func (cm *CheckpointManager) RetrieveCheckpoint(blockHash string) (Checkpoint, error) {
    cm.mutex.RLock()
    defer cm.mutex.RUnlock()

    checkpoint, exists := cm.checkpoints[blockHash]
    if !exists {
        return Checkpoint{}, errors.New("checkpoint not found")
    }

    return checkpoint, nil
}

// ValidateAllCheckpoints validates all existing checkpoints
func (cm *CheckpointManager) ValidateAllCheckpoints() {
    cm.mutex.RLock()
    defer cm.mutex.RUnlock()

    for blockHash, checkpoint := range cm.checkpoints {
        valid, err := cm.ValidateCheckpoint(checkpoint)
        if err != nil {
            fmt.Printf("Failed to validate checkpoint for block hash: %s, error: %v\n", blockHash, err)
        } else if !valid {
            fmt.Printf("Invalid checkpoint detected for block hash: %s\n", blockHash)
        } else {
            fmt.Printf("Checkpoint for block hash: %s is valid\n", blockHash)
        }
    }
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

// NewFinalityManager creates a new FinalityManager.
func NewFinalityManager(consensusEngine *consensus.Engine) *FinalityManager {
	return &FinalityManager{
		checkpoints:     make(map[string]Checkpoint),
		finalizedBlocks: make(map[string]FinalizedBlock),
		validators:      make(map[string]string),
		consensusEngine: consensusEngine,
	}
}

// RegisterValidator registers a new validator for the network.
func (fm *FinalityManager) RegisterValidator(validatorID, publicKey string) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	fm.validators[validatorID] = publicKey
}

// CreateCheckpoint creates a checkpoint for a given block hash.
func (fm *FinalityManager) CreateCheckpoint(blockHash, validatorID string) (Checkpoint, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	publicKey, exists := fm.validators[validatorID]
	if !exists {
		return Checkpoint{}, errors.New("validator not registered")
	}

	timestamp := time.Now()
	data := blockHash + timestamp.String() + validatorID
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
	fm.checkpoints[blockHash] = checkpoint
	return checkpoint, nil
}

// ValidateCheckpoint validates a given checkpoint.
func (fm *FinalityManager) ValidateCheckpoint(checkpoint Checkpoint) (bool, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	publicKey, exists := fm.validators[checkpoint.ValidatorID]
	if !exists {
		return false, errors.New("validator not registered")
	}

	data := checkpoint.BlockHash + checkpoint.Timestamp.String() + checkpoint.ValidatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := hex.DecodeString(checkpoint.Signature)
	if err != nil {
		return false, err
	}

	return crypto.VerifySignature(publicKey, hash[:], signature)
}

// CreateFinalizedBlock marks a block as finalized.
func (fm *FinalityManager) CreateFinalizedBlock(blockHash, validatorID string) (FinalizedBlock, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	publicKey, exists := fm.validators[validatorID]
	if !exists {
		return FinalizedBlock{}, errors.New("validator not registered")
	}

	timestamp := time.Now()
	data := blockHash + timestamp.String() + validatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := crypto.SignData(publicKey, hash[:])
	if err != nil {
		return FinalizedBlock{}, err
	}

	finalizedBlock := FinalizedBlock{
		BlockHash:   blockHash,
		Timestamp:   timestamp,
		ValidatorID: validatorID,
		Signature:   hex.EncodeToString(signature),
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

// PeriodicallyCreateCheckpoints creates checkpoints at regular intervals.
func (fm *FinalityManager) PeriodicallyCreateCheckpoints() {
	ticker := time.NewTicker(time.Duration(60) * time.Second) // Example interval, can be adjusted
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			latestBlockHash := fm.consensusEngine.GetLatestBlockHash()
			validatorID := fm.consensusEngine.GetCurrentValidator()
			_, err := fm.CreateCheckpoint(latestBlockHash, validatorID)
			if err != nil {
				fmt.Printf("Failed to create checkpoint: %v\n", err)
			} else {
				fmt.Printf("Checkpoint created for block hash: %s by validator: %s\n", latestBlockHash, validatorID)
			}
		}
	}
}

// MonitorFinality continuously monitors and reports the finality status.
func (fm *FinalityManager) MonitorFinality() {
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

// GetFinalityMetrics provides real-time finality metrics.
func (fm *FinalityManager) GetFinalityMetrics() map[string]interface{} {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	metrics := make(map[string]interface{})
	finalizedCount := len(fm.finalizedBlocks)
	checkpointCount := len(fm.checkpoints)

	metrics["finalized_blocks"] = finalizedCount
	metrics["checkpoints"] = checkpointCount
	metrics["validators"] = len(fm.validators)
	metrics["last_checkpoint_time"] = time.Now() // Example placeholder

	return metrics
}

// NewFinalizedBlockManager creates a new FinalizedBlockManager.
func NewFinalizedBlockManager(consensusEngine *consensus.Engine) *FinalizedBlockManager {
	return &FinalizedBlockManager{
		finalizedBlocks: make(map[string]FinalizedBlock),
		validators:      make(map[string]string),
		consensusEngine: consensusEngine,
	}
}

// RegisterValidator registers a new validator for the network.
func (fbm *FinalizedBlockManager) RegisterValidator(validatorID, publicKey string) {
	fbm.mutex.Lock()
	defer fbm.mutex.Unlock()
	fbm.validators[validatorID] = publicKey
}

// CreateFinalizedBlock marks a block as finalized.
func (fbm *FinalizedBlockManager) CreateFinalizedBlock(blockHash, validatorID string) (FinalizedBlock, error) {
	fbm.mutex.Lock()
	defer fbm.mutex.Unlock()

	publicKey, exists := fbm.validators[validatorID]
	if !exists {
		return FinalizedBlock{}, errors.New("validator not registered")
	}

	timestamp := time.Now()
	data := blockHash + timestamp.String() + validatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := crypto.SignData(publicKey, hash[:])
	if err != nil {
		return FinalizedBlock{}, err
	}

	finalizedBlock := FinalizedBlock{
		BlockHash:   blockHash,
		Timestamp:   timestamp,
		ValidatorID: validatorID,
		Signature:   hex.EncodeToString(signature),
	}
	fbm.finalizedBlocks[blockHash] = finalizedBlock
	return finalizedBlock, nil
}

// IsBlockFinalized checks if a block is finalized.
func (fbm *FinalizedBlockManager) IsBlockFinalized(blockHash string) (bool, error) {
	fbm.mutex.RLock()
	defer fbm.mutex.RUnlock()

	_, exists := fbm.finalizedBlocks[blockHash]
	return exists, nil
}

// ValidateFinalizedBlock validates a given finalized block.
func (fbm *FinalizedBlockManager) ValidateFinalizedBlock(finalizedBlock FinalizedBlock) (bool, error) {
	fbm.mutex.RLock()
	defer fbm.mutex.RUnlock()

	publicKey, exists := fbm.validators[finalizedBlock.ValidatorID]
	if !exists {
		return false, errors.New("validator not registered")
	}

	data := finalizedBlock.BlockHash + finalizedBlock.Timestamp.String() + finalizedBlock.ValidatorID
	hash := sha256.Sum256([]byte(data))
	signature, err := hex.DecodeString(finalizedBlock.Signature)
	if err != nil {
		return false, err
	}

	return crypto.VerifySignature(publicKey, hash[:], signature)
}

// PeriodicallyCreateFinalizedBlocks creates finalized blocks at regular intervals.
func (fbm *FinalizedBlockManager) PeriodicallyCreateFinalizedBlocks() {
	ticker := time.NewTicker(time.Duration(60) * time.Second) // Example interval, can be adjusted
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			latestBlockHash := fbm.consensusEngine.GetLatestBlockHash()
			validatorID := fbm.consensusEngine.GetCurrentValidator()
			_, err := fbm.CreateFinalizedBlock(latestBlockHash, validatorID)
			if err != nil {
				fmt.Printf("Failed to create finalized block: %v\n", err)
			} else {
				fmt.Printf("Finalized block created for block hash: %s by validator: %s\n", latestBlockHash, validatorID)
			}
		}
	}
}

// MonitorFinalizedBlocks continuously monitors and reports the finalization status.
func (fbm *FinalizedBlockManager) MonitorFinalizedBlocks() {
	for {
		time.Sleep(10 * time.Second) // Adjust monitoring interval as needed
		for blockHash := range fbm.finalizedBlocks {
			finalized, err := fbm.IsBlockFinalized(blockHash)
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
func (fbm *FinalizedBlockManager) GetFinalizedBlockMetrics() map[string]interface{} {
	fbm.mutex.RLock()
	defer fbm.mutex.RUnlock()

	metrics := make(map[string]interface{})
	finalizedCount := len(fbm.finalizedBlocks)

	metrics["finalized_blocks"] = finalizedCount
	metrics["validators"] = len(fbm.validators)
	metrics["last_finalized_time"] = time.Now() // Example placeholder

	return metrics
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


// NewFinalityManager creates a new FinalityManager.
func NewFinalityManager(consensusEngine *consensus.Engine, instantFinality bool, thresholds FinalityThresholds) *FinalityManager {
	return &FinalityManager{
		finalizedBlocks:    make(map[string]FinalizedBlock),
		validators:         make(map[string]Validator),
		consensusEngine:    consensusEngine,
		instantFinality:    instantFinality,
		finalityThresholds: thresholds,
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

// ApplyDynamicThresholds applies dynamic finality thresholds based on network conditions.
func (fm *FinalityManager) ApplyDynamicThresholds(networkConditions NetworkConditions) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if fm.finalityThresholds.DynamicThresholds {
		// Adjust thresholds based on network conditions
		if networkConditions.CongestionLevel > 80 {
			fm.finalityThresholds.ConfirmationDepth += 1
		} else if networkConditions.CongestionLevel < 20 {
			fm.finalityThresholds.ConfirmationDepth -= 1
		}

		// Ensure thresholds are within reasonable limits
		if fm.finalityThresholds.ConfirmationDepth < 1 {
			fm.finalityThresholds.ConfirmationDepth = 1
		}
		if fm.finalityThresholds.ConfirmationDepth > 10 {
			fm.finalityThresholds.ConfirmationDepth = 10
		}
	}
}
