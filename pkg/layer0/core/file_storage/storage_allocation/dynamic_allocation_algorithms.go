// Package storage_allocation provides a dynamic system for managing and allocating storage resources within the Synnergy Network blockchain.
package storage_allocation

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/synthron/synthron_blockchain/smartcontract"
)

// DynamicAllocator handles the intelligent distribution of storage resources.
type DynamicAllocator struct {
	NodeCapacities   map[string]int64 // Storage capacity for each node
	CurrentAllocations map[string]int64 // Current storage allocation per node
	DemandForecast   map[string]int64 // Predicted demand for storage
	PriceModel       *DynamicPricing // Pricing model for storage allocation
	mu               sync.RWMutex    // Mutex for concurrent map access
}

// NewDynamicAllocator initializes a new instance of DynamicAllocator.
func NewDynamicAllocator() *DynamicAllocator {
	return &DynamicAllocator{
		NodeCapacities:   make(map[string]int64),
		CurrentAllocations: make(map[string]int64),
		DemandForecast:   make(map[string]int64),
		PriceModel:       NewDynamicPricing(),
	}
}

// SetNodeCapacity sets the capacity for a given node.
func (da *DynamicAllocator) SetNodeCapacity(nodeID string, capacity int64) {
	da.mu.Lock()
	defer da.mu.Unlock()
	da.NodeCapacities[nodeID] = capacity
}

// AllocateStorage dynamically allocates storage based on network demand and node capacity.
func (da *DynamicAllocator) AllocateStorage(nodeID string, requestBytes int64) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	if _, exists := da.NodeCapacities[nodeID]; !exists {
		return errors.New("node ID does not exist")
	}

	if da.CurrentAllocations[nodeID]+requestBytes > da.NodeCapacities[nodeID] {
		return errors.New("exceeding node capacity")
	}

	// Adjust the current allocation and update pricing
	da.CurrentAllocations[nodeID] += requestBytes
	da.PriceModel.AdjustPrice(da.calculateUtilization(nodeID))

	return nil
}

// calculateUtilization calculates the storage utilization percentage for a node.
func (da *DynamicAllocator) calculateUtilization(nodeID string) float64 {
	return float64(da.CurrentAllocations[nodeID]) / float64(da.NodeCapacities[nodeID])
}

// DynamicPricing manages the dynamic pricing model for storage resources.
type DynamicPricing struct {
	BasePrice float64 // Base price per byte
}

// NewDynamicPricing creates a new DynamicPricing model.
func NewDynamicPricing() *DynamicPricing {
	return &DynamicPricing{
		BasePrice: 0.01, // Set a default base price
	}
}

// AdjustPrice adjusts the price based on current utilization.
func (dp *DynamicPricing) AdjustPrice(utilization float64) {
	if utilization > 0.8 {
		dp.BasePrice *= 1.05 // Increase price by 5%
	} else if utilization < 0.2 {
		dp.BasePrice *= 0.95 // Decrease price by 5%
	}
}

// PredictiveScaling uses machine learning to predict future storage needs.
func PredictiveScaling(da *DynamicAllocator, historyData map[string][]int64) {
	// Simulated prediction logic based on historical data
	for nodeID, dataPoints := range historyData {
		// Example: Calculate average usage to predict future needs
		var sum int64
		for _, v := range dataPoints {
			sum += v
		}
		average := sum / int64(len(dataPoints))
		da.DemandForecast[nodeID] = average * 2 // Assuming double growth
	}
}

// Example of usage
func main() {
	allocator := NewDynamicAllocator()
	allocator.SetNodeCapacity("node1", 10000)

	err := allocator.AllocateStorage("node1", 5000)
	if err != nil {
		panic(err)
	}

	// Simulate predictive scaling
	history := map[string][]int64{
		"node1": {1000, 1500, 2000},
	}
	PredictiveScaling(allocator, history)
}
