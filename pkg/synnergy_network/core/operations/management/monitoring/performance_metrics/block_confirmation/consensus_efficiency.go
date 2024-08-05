package block_confirmation

import (
    "time"
    "errors"
    "math"
    "sync"
)

// Block represents a single block in the blockchain
type Block struct {
    ID            string
    Timestamp     time.Time
    PreviousHash  string
    Hash          string
}

// ConfirmationMetrics contains metrics related to block confirmation times
type ConfirmationMetrics struct {
    mu                   sync.Mutex
    BlockConfirmations   map[string]time.Duration
    AvgConfirmationTime  time.Duration
    StdDevConfirmation   time.Duration
}

// NewConfirmationMetrics initializes and returns a ConfirmationMetrics instance
func NewConfirmationMetrics() *ConfirmationMetrics {
    return &ConfirmationMetrics{
        BlockConfirmations: make(map[string]time.Duration),
    }
}

// RecordConfirmationTime records the time taken to confirm a block
func (cm *ConfirmationMetrics) RecordConfirmationTime(blockID string, confirmationTime time.Duration) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.BlockConfirmations[blockID] = confirmationTime
    cm.calculateMetrics()
}

// calculateMetrics updates the average and standard deviation of confirmation times
func (cm *ConfirmationMetrics) calculateMetrics() {
    var total time.Duration
    var count int
    for _, duration := range cm.BlockConfirmations {
        total += duration
        count++
    }
    if count == 0 {
        cm.AvgConfirmationTime = 0
        cm.StdDevConfirmation = 0
        return
    }
    cm.AvgConfirmationTime = total / time.Duration(count)

    var varianceSum float64
    for _, duration := range cm.BlockConfirmations {
        varianceSum += math.Pow(duration.Seconds()-cm.AvgConfirmationTime.Seconds(), 2)
    }
    cm.StdDevConfirmation = time.Duration(math.Sqrt(varianceSum / float64(count))) * time.Second
}

// GetAverageConfirmationTime returns the average confirmation time
func (cm *ConfirmationMetrics) GetAverageConfirmationTime() time.Duration {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    return cm.AvgConfirmationTime
}

// GetStandardDeviation returns the standard deviation of confirmation times
func (cm *ConfirmationMetrics) GetStandardDeviation() time.Duration {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    return cm.StdDevConfirmation
}

// ValidateBlockConfirmationTime validates if a block's confirmation time is within acceptable limits
func (cm *ConfirmationMetrics) ValidateBlockConfirmationTime(blockID string, maxTimeAllowed time.Duration) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    confirmationTime, exists := cm.BlockConfirmations[blockID]
    if !exists {
        return errors.New("block confirmation time not found")
    }
    if confirmationTime > maxTimeAllowed {
        return errors.New("block confirmation time exceeds allowed limit")
    }
    return nil
}

// BlockchainManager manages blockchain operations including block confirmation times
type BlockchainManager struct {
    ConfirmationMetrics *ConfirmationMetrics
}

// NewBlockchainManager initializes and returns a BlockchainManager instance
func NewBlockchainManager() *BlockchainManager {
    return &BlockchainManager{
        ConfirmationMetrics: NewConfirmationMetrics(),
    }
}

// ConfirmBlock confirms a block and records its confirmation time
func (bm *BlockchainManager) ConfirmBlock(block Block, confirmationTime time.Duration) {
    bm.ConfirmationMetrics.RecordConfirmationTime(block.ID, confirmationTime)
}

// CheckBlockConfirmation checks if the block confirmation time is within the acceptable range
func (bm *BlockchainManager) CheckBlockConfirmation(blockID string, maxTimeAllowed time.Duration) error {
    return bm.ConfirmationMetrics.ValidateBlockConfirmationTime(blockID, maxTimeAllowed)
}

// GetMetrics provides the current average and standard deviation of block confirmation times
func (bm *BlockchainManager) GetMetrics() (time.Duration, time.Duration) {
    return bm.ConfirmationMetrics.GetAverageConfirmationTime(), bm.ConfirmationMetrics.GetStandardDeviation()
}
