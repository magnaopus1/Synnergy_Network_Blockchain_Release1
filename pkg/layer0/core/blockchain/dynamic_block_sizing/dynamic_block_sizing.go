package dynamic_block_sizing

import (
    "sync"
    "time"
)

// Metrics collects real-time data about transactions and block sizes.
type Metrics struct {
    AverageTransactionSize int
    TransactionFrequency   int
    CurrentLoad            int
}

// BlockSizeManager manages the dynamic sizing of blocks based on network load.
type BlockSizeManager struct {
    minSize     int
    maxSize     int
    currentSize int
    metrics     *Metrics
    lock        sync.RWMutex
}

// NewBlockSizeManager creates a new BlockSizeManager with initial settings.
func NewBlockSizeManager(minSize, maxSize, initialSize int) *BlockSizeManager {
    return &BlockSizeManager{
        minSize:     minSize,
        maxSize:     maxSize,
        currentSize: initialSize,
        metrics:     &Metrics{},
    }
}

// AdjustBlockSize dynamically adjusts the block size based on transaction load.
func (bsm *BlockSizeManager) AdjustBlockSize() {
    bsm.lock.Lock()
    defer bsm.lock.Unlock()

    // Simulation of dynamic adjustment logic
    if bsm.metrics.CurrentLoad > 75 {
        // Increase block size when the load is more than 75% of the current capacity
        bsm.currentSize = min(bsm.currentSize*2, bsm.maxSize)
    } else if bsm.metrics.CurrentLoad < 25 {
        // Decrease block size when the load is less than 25% of the current capacity
        bsm.currentSize = max(bsm.minSize, bsm.currentSize/2)
    }

    // Notify consensus nodes about the block size change
    bsm.notifyConsensusNodes()
}

// notifyConsensusNodes simulates the notification to consensus nodes to agree on the new block size.
func (bsm *BlockSizeManager) notifyConsensusNodes() {
    // Implementation for notifying consensus mechanism of the new block size
}

// UpdateMetrics updates the metrics that the block size adjustment depends on.
func (bsm *BlockSizeManager) UpdateMetrics(transactionSize, frequency, load int) {
    bsm.lock.Lock()
    defer bsm.lock.Unlock()

    bsm.metrics.AverageTransactionSize = transactionSize
    bsm.metrics.TransactionFrequency = frequency
    bsm.metrics.CurrentLoad = load
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// Mock function to simulate real-time updates (can be replaced with actual data hooks)
func simulateMetricsUpdate(bsm *BlockSizeManager) {
    for {
        time.Sleep(10 * time.Second) // Simulate metric update every 10 seconds
        // Simulated update logic
        bsm.UpdateMetrics(300, 50, 60) // Example values to update metrics
    }
}
