package synthron_coin

import (
	"math"
	"sync"
	"time"
)

// SupplyAdjustmentManager manages the mechanisms for supply adjustment such as halving, burning, and dynamic inflation control.
type SupplyAdjustmentManager struct {
	TotalSupply       float64
	CirculatingSupply float64
	HalvingInterval   int
	NextHalvingBlock  int
	mutex             sync.Mutex
}

// NewSupplyAdjustmentManager initializes a new manager with the total and circulating supply.
func NewSupplyAdjustmentManager(total, circulating float64, halvingInterval, startBlock int) *SupplyAdjustmentManager {
	return &SupplyAdjustmentManager{
		TotalSupply:       total,
		CirculatingSupply: circulating,
		HalvingInterval:   halvingInterval,
		NextHalvingBlock:  startBlock + halvingInterval,
	}
}

// HalveRewards decreases rewards per block based on the halving interval.
func (sam *SupplyAdjustmentManager) HalveRewards(currentBlock int) {
	sam.mutex.Lock()
	defer sam.mutex.Unlock()

	if currentBlock >= sam.NextHalvingBlock {
		sam.TotalSupply /= 2  // Halve the total supply limit for emission
		sam.NextHalvingBlock += sam.HalvingInterval
	}
}

// BurnCoins removes coins from circulation permanently to control inflation.
func (sam *SupplyAdjustmentManager) BurnCoins(amount float64) {
	sam.mutex.Lock()
	defer sam.mutex.Unlock()

	if amount <= sam.CirculatingSupply {
		sam.CirculatingSupply -= amount
	}
}

// AdjustSupplyBasedOnPerformance dynamically adjusts the supply based on network performance metrics.
func (sam *SupplyAdjustmentManager) AdjustSupplyBasedOnPerformance(networkPerformanceIndex float64) {
	sam.mutex.Lock()
	defer sam.mutex.Unlock()

	// Simple example: Decrease supply if performance is below threshold
	if networkPerformanceIndex < 0.5 {
		sam.TotalSupply *= 0.99 // Reduce supply by 1%
	}
}


