// Package storage_allocation implements automated data redundancy management for the Synnergy Network blockchain.
package storage_allocation

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/synthron/synthron_crypto"
)

// RedundancyManager manages the data redundancy across the network nodes.
type RedundancyManager struct {
	NodeCapacities map[string]int64 // Storage capacity per node
	DataRedundancy map[string]int   // Redundancy level per data item
	mu             sync.Mutex       // Mutex to ensure concurrency control
}

// NewRedundancyManager initializes a new RedundancyManager with default settings.
func NewRedundancyManager() *RedundancyManager {
	return &RedundancyManager{
		NodeCapacities: make(map[string]int64),
		DataRedundancy: make(map[string]int),
	}
}

// SetNodeCapacity sets the storage capacity for a node.
func (rm *RedundancyManager) SetNodeCapacity(nodeID string, capacity int64) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.NodeCapacities[nodeID] = capacity
}

// UpdateDataRedundancy adjusts the redundancy level of data based on current network conditions.
func (rm *RedundancyManager) UpdateDataRedundancy(dataID string, desiredRedundancy int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.DataRedundancy[dataID]; !exists {
		return errors.New("data ID does not exist")
	}

	// Simulate adjustment logic based on network demand and node capacities
	rm.DataRedundancy[dataID] = desiredRedundancy
	return nil
}

// AutoAdjustRedundancy periodically adjusts redundancy levels based on network status.
func (rm *RedundancyManager) AutoAdjustRedundancy() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.mu.Lock()
			for dataID, redundancy := range rm.DataRedundancy {
				// Simulated logic to increase or decrease redundancy based on pseudo-random factors
				if rand.Intn(10) < 5 {
					redundancy++
				} else {
					redundancy = max(1, redundancy-1)
				}
				rm.DataRedundancy[dataID] = redundancy
			}
			rm.mu.Unlock()
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Example usage
func main() {
	manager := NewRedundancyManager()

	// Setting node capacities
	manager.SetNodeCapacity("node1", 1000)
	manager.SetNodeCapacity("node2", 1500)

	// Initializing data redundancy
	manager.DataRedundancy["data1"] = 2
	manager.DataRedundancy["data2"] = 3

	// Updating redundancy based on a simulated condition change
	if err := manager.UpdateDataRedundancy("data1", 4); err != nil {
		panic(err)
	}

	// Start auto-adjustment in a goroutine
	go manager.AutoAdjustRedundancy()

	// Run the service
	select {}
}
