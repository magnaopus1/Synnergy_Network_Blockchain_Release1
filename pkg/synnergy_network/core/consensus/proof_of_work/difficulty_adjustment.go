package proof_of_work

import (
	"time"
	"sync"
	"math"
)

// DifficultyAdjustmentManager handles the calculation and adjustment of mining difficulty.
type DifficultyAdjustmentManager struct {
	CurrentDifficulty  float64
	TargetBlockTime    time.Duration
	AdjustmentInterval int
	mutex              sync.Mutex
	lastAdjustmentBlock int
}

// NewDifficultyAdjustmentManager initializes a new manager with default values.
func NewDifficultyAdjustmentManager() *DifficultyAdjustmentManager {
	return &DifficultyAdjustmentManager{
		CurrentDifficulty:  1.0,  // Initial difficulty
		TargetBlockTime:    10 * time.Minute,
		AdjustmentInterval: 2016,
		lastAdjustmentBlock: 0,
	}
}

// CalculateDifficulty adjusts the difficulty based on the actual time to mine the last set of blocks.
func (d *DifficultyAdjustmentManager) CalculateDifficulty(actualTime time.Duration, blockNumber int) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if blockNumber - d.lastAdjustmentBlock < d.AdjustmentInterval {
		return
	}

	expectedTime := time.Duration(d.AdjustmentInterval) * d.TargetBlockTime
	ratio := float64(actualTime) / float64(expectedTime)

	if ratio < 1 {
		d.CurrentDifficulty /= ratio  // Decrease difficulty if blocks were mined too quickly
	} else {
		d.CurrentDifficulty *= ratio  // Increase difficulty if blocks were mined too slowly
	}

	// Smoothing the difficulty adjustment to prevent drastic changes
	d.CurrentDifficulty = math.Max(1, d.CurrentDifficulty)  // Ensure the difficulty never goes below 1

	d.lastAdjustmentBlock = blockNumber
}

// GetDifficulty returns the current difficulty level.
func (d *DifficultyAdjustmentManager) GetDifficulty() float64 {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.CurrentDifficulty
}

// Implementation of the difficulty adjustment would typically be triggered by a block event,
// where the time taken to mine the last 2016 blocks is compared to the expected mining time.
