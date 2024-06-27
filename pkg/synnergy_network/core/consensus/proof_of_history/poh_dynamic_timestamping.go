package consensus

import (
	"time"
	"sync"
	"errors"
	"synnergy_network/pkg/synnergy_network/core/common"
)

// DynamicTimestampManager manages the dynamic adjustment of timestamp intervals based on network conditions.
type DynamicTimestampManager struct {
	CurrentInterval time.Duration
	MinInterval     time.Duration
	MaxInterval     time.Duration
	AdjustmentFactor float64
	lock            sync.Mutex
	NetworkStats    *NetworkStatistics
}

// NetworkStatistics gathers and analyzes data necessary for dynamic adjustments.
type NetworkStatistics struct {
	RecentTransactionVolumes []int
	AverageLatency           time.Duration
}

// NewDynamicTimestampManager creates a new manager with predefined settings.
func NewDynamicTimestampManager(minInterval, maxInterval time.Duration, factor float64) *DynamicTimestampManager {
	return &DynamicTimestampManager{
		CurrentInterval: maxInterval,
		MinInterval:     minInterval,
		MaxInterval:     maxInterval,
		AdjustmentFactor: factor,
		NetworkStats:    new(NetworkStatistics),
	}
}

// MonitorAndAdjust watches network conditions and adjusts the timestamping interval dynamically.
func (dtm *DynamicTimestampManager) MonitorAndAdjust() {
	for {
		time.Sleep(dtm.CurrentInterval) // Sleep for the duration of the current interval
		dtm.lock.Lock()
		adjusted := dtm.adjustTimestampingInterval()
		dtm.lock.Unlock()
		if adjusted {
			// Log or handle the interval adjustment
		}
	}
}

// adjustTimestampingInterval calculates the new interval based on recent transaction volume and latency.
func (dtm *DynamicTimestampManager) adjustTimestampingInterval() bool {
	averageVolume := dtm.calculateAverageVolume()
	if averageVolume < 0 {
		return false
	}

	// Increase or decrease the interval based on the load.
	if averageVolume > 1000 { // Example threshold
		dtm.CurrentInterval = time.Duration(float64(dtm.CurrentInterval) * (1 - dtm.AdjustmentFactor))
		if dtm.CurrentInterval < dtm.MinInterval {
			dtm.CurrentInterval = dtm.MinInterval
		}
	} else {
		dtm.CurrentInterval = time.Duration(float64(dtm.CurrentInterval) * (1 + dtm.AdjustmentFactor))
		if dtm.CurrentInterval > dtm.MaxInterval {
			dtm.CurrentInterval = dtm.MaxInterval
		}
	}
	return true
}

// calculateAverageVolume computes the average transaction volume.
func (dtm *DynamicTimestampManager) calculateAverageVolume() int {
	if len(dtm.NetworkStats.RecentTransactionVolumes) == 0 {
		return -1 // No data available
	}

	total := 0
	for _, volume := range dtm.NetworkStats.RecentTransactionVolumes {
		total += volume
	}
	return total / len(dtm.NetworkStats.RecentTransactionVolumes)
}

// UpdateNetworkStats updates the statistics used to determine adjustments.
func (dtm *DynamicTimestampManager) UpdateNetworkStats(volume int, latency time.Duration) {
	dtm.lock.Lock()
	defer dtm.lock.Unlock()
	dtm.NetworkStats.RecentTransactionVolumes = append(dtm.NetworkStats.RecentTransactionVolumes, volume)
	dtm.NetworkStats.AverageLatency = latency
}

// GetCurrentInterval returns the current dynamic interval for timestamping.
func (dtm *DynamicTimestampManager) GetCurrentInterval() time.Duration {
	dtm.lock.Lock()
	defer dtm.lock.Unlock()
	return dtm.CurrentInterval
}
