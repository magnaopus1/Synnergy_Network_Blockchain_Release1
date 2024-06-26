package proof_of_work

import (
	"math"
	"sync"
	"time"
)

// FormulasAndCalculations encapsulates the calculations for block rewards and difficulty adjustments.
type FormulasAndCalculations struct {
	initialReward      float64
	rewardReductionHalvings int
	blockRewardHalvingInterval int
	currentBlockHeight int
	mutex              sync.Mutex
}

// NewFormulasAndCalculations creates an instance to handle reward and difficulty calculations.
func NewFormulasAndCalculations() *FormulasAndCalculations {
	return &FormulasAndCalculations{
		initialReward:      1252.0, // The initial reward for mining a block
		rewardReductionHalvings: 0,
		blockRewardHalvingInterval: 200000, // Interval at which the reward is halved
		currentBlockHeight: 0,
	}
}

// CalculateReward computes the current block reward based on the halving schedule.
func (f *FormulasAndCalculations) CalculateReward(currentHeight int) float64 {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	halvings := currentHeight / f.blockRewardHalvingInterval
	if halvings > 64 {
		halvings = 64 // Reward becomes zero after 64 halvings
	}

	reward := f.initialReward
	for i := 0; i < halvings; i++ {
		reward /= 2
	}

	return reward
}

// UpdateBlockHeight updates the current block height for reward calculations.
func (f *FormulasAndCalculations) UpdateBlockHeight(height int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.currentBlockHeight = height
	f.rewardReductionHalvings = height / f.blockRewardHalvingInterval
}

// DifficultyAdjustment represents the dynamic difficulty adjustment logic.
type DifficultyAdjustment struct {
	currentDifficulty float64
	targetBlockTime   time.Duration
	adjustmentFactor  float64
	mutex             sync.Mutex
}

// NewDifficultyAdjustment initializes a new difficulty adjustment mechanism.
func NewDifficultyAdjustment() *DifficultyAdjustment {
	return &DifficultyAdjustment{
		currentDifficulty: 1.0, // Initial difficulty
		targetBlockTime:   10 * time.Minute,
		adjustmentFactor:  0.25, // Adjustment sensitivity
	}
}

// AdjustDifficulty dynamically adjusts the difficulty based on actual and target mining times.
func (d *DifficultyAdjustment) AdjustDifficulty(actualTime, targetTime time.Duration) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	ratio := float64(actualTime) / float64(targetTime)
	if ratio < 1 {
		d.currentDifficulty -= d.adjustmentFactor * (1 - ratio) // Decrease difficulty
	} else {
		d.currentDifficulty += d.adjustmentFactor * (ratio - 1) // Increase difficulty
	}

	// Ensure difficulty does not fall below a reasonable limit
	d.currentDifficulty = math.Max(0.1, d.currentDifficulty)
}

// GetCurrentDifficulty retrieves the current mining difficulty.
func (d *DifficultyAdjustment) GetCurrentDifficulty() float64 {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.currentDifficulty
}

// Implementation details are generally handled within the blockchain's core system,
// where block validations and mining operations interact with these components to
// maintain the blockchain's integrity and economic model.
