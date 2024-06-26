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
}

// NewDynamicBlockSizer creates a new instance of DynamicBlockSizer.
func NewDynamicBlockSizer(initialBlockSize int, adjustInterval time.Duration) *DynamicBlockSizer {
	return &DynamicBlockSizer{
		currentBlockSize: initialBlockSize,
		transactionLoad:  make(chan int, 1000),
		adjustInterval:   adjustInterval,
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
			dbs.currentBlockSize = dbs.adaptiveBlockSize(avgLoad)
			return
		}
	}
}

// adaptiveBlockSize determines the new block size based on average transaction load.
func (dbs *DynamicBlockSizer) adaptiveBlockSize(avgLoad int) int {
	// Example logic: if avgLoad is high, increase the block size, otherwise decrease.
	if avgLoad > 1000 {
		return dbs.currentBlockSize + 1000
	} else if avgLoad < 500 {
		return dbs.currentBlockSize - 500
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
