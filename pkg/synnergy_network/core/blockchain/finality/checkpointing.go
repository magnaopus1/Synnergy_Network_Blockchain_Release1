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

// Checkpoint represents a checkpoint in the blockchain
type Checkpoint struct {
    BlockHash   string
    Timestamp   time.Time
    ValidatorID string
    Signature   string
}

// CheckpointManager manages the checkpoints in the blockchain
type CheckpointManager struct {
    checkpoints      map[string]Checkpoint
    mutex            sync.RWMutex
    validators       map[string]string // ValidatorID to PublicKey mapping
    consensusEngine  *consensus.Engine
    checkpointPeriod int
}

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
