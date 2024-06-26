package dynamic_block_sizing

import (
	"sync"
	"time"
)

// DynamicBlockSizer is the structure for managing dynamic block sizing.
type DynamicBlockSizer struct {
	mu               sync.Mutex
	currentBlockSize int
	transactionLoad  chan int
	adjustInterval   time.Duration
	maxBlockSize     int
	minBlockSize     int
	consensus        ConsensusInterface
}

// ConsensusInterface defines the methods required for consensus interaction.
type ConsensusInterface interface {
	ProposeBlockSizeChange(newSize int) bool
}

// NewDynamicBlockSizer creates a new instance of DynamicBlockSizer.
func NewDynamicBlockSizer(initialBlockSize, maxBlockSize, minBlockSize int, adjustInterval time.Duration, consensus ConsensusInterface) *DynamicBlockSizer {
	return &DynamicBlockSizer{
		currentBlockSize: initialBlockSize,
		transactionLoad:  make(chan int, 1000),
		adjustInterval:   adjustInterval,
		maxBlockSize:     maxBlockSize,
		minBlockSize:     minBlockSize,
		consensus:        consensus,
	}
}

// Start initiates the dynamic block sizing process.
func (dbs *DynamicBlockSizer) Start() {
	go dbs.adjustBlockSize()
}

// adjustBlockSize periodically adjusts the block size based on transaction load.
func (dbs *DynamicBlockSizer) adjustBlockSize() {
	ticker := time.NewTicker(dbs.adjustInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dbs.calculateOptimalBlockSize()
		}
	}
}

// calculateOptimalBlockSize adjusts the block size based on recent transaction load.
func (dbs *DynamicBlockSizer) calculateOptimalBlockSize() {
	dbs.mu.Lock()
	defer dbs.mu.Unlock()

	loadSum := 0
	count := 0

	for {
		select {
		case load := <-dbs.transactionLoad:
			loadSum += load
			count++
		default:
			if count == 0 {
				return
			}
			avgLoad := loadSum / count
			newBlockSize := dbs.adaptiveBlockSize(avgLoad)
			if newBlockSize != dbs.currentBlockSize {
				if dbs.consensus.ProposeBlockSizeChange(newBlockSize) {
					dbs.currentBlockSize = newBlockSize
				}
			}
			return
		}
	}
}

// adaptiveBlockSize determines the new block size based on average transaction load.
func (dbs *DynamicBlockSizer) adaptiveBlockSize(avgLoad int) int {
	if avgLoad > 1000 {
		return min(dbs.currentBlockSize+1000, dbs.maxBlockSize)
	} else if avgLoad < 500 {
		return max(dbs.currentBlockSize-500, dbs.minBlockSize)
	}
	return dbs.currentBlockSize
}

// UpdateTransactionLoad updates the transaction load for the block sizer.
func (dbs *DynamicBlockSizer) UpdateTransactionLoad(load int) {
	dbs.transactionLoad <- load
}

// GetCurrentBlockSize returns the current block size.
func (dbs *DynamicBlockSizer) GetCurrentBlockSize() int {
	dbs.mu.Lock()
	defer dbs.mu.Unlock()
	return dbs.currentBlockSize
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
