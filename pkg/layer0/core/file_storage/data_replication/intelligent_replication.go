// Package data_replication is dedicated to the intelligent replication of data across the Synnergy Network blockchain.
// This file implements intelligent replication strategies using machine learning to optimize data distribution based on network conditions.
package data_replication

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"synthron_blockchain/pkg/machine_learning"
)

// IntelligentReplicator manages the dynamic adjustment of replication factors across the blockchain network.
type IntelligentReplicator struct {
	NodeReliabilityMap map[string]float64 // Node ID to reliability score
	DataReplicationMap map[string]int     // Data ID to current replication factor
	mu                 sync.Mutex
}

// NewIntelligentReplicator initializes an IntelligentReplicator with default values.
func NewIntelligentReplicator() *IntelligentReplicator {
	return &IntelligentReplicator{
		NodeReliabilityMap: make(map[string]float64),
		DataReplicationMap: make(map[string]int),
	}
}

// AdjustReplicationFactors dynamically adjusts the replication factors for data based on node reliability and network usage.
func (ir *IntelligentReplicator) AdjustReplicationFactors() error {
	ir.mu.Lock()
	defer ir.mu.Unlock()

	for dataID, currentFactor := range ir.DataReplicationMap {
		reliabilityScores := ir.collectNodeReliabilities()
		newFactor := machine_learning.PredictReplicationFactor(reliabilityScores, currentFactor)
		ir.DataReplicationMap[dataID] = newFactor
		fmt.Printf("Adjusted replication factor for %s: from %d to %d\n", dataID, currentFactor, newFactor)
	}

	return nil
}

// collectNodeReliabilities aggregates reliability scores from available nodes.
func (ir *IntelligentReplicator) collectNodeReliabilities() []float64 {
	var scores []float64
	for _, score := range ir.NodeReliabilityMap {
		scores = append(scores, score)
	}
	return scores
}

// simulateDataChanges periodically updates the node reliability scores to simulate changing network conditions.
func (ir *IntelligentReplicator) simulateDataChanges() {
	rand.Seed(time.Now().UnixNano())
	for nodeID := range ir.NodeReliabilityMap {
		change := rand.Float64()*0.1 - 0.05 // Random change between -0.05 and 0.05
		ir.NodeReliabilityMap[nodeID] += change
	}
}

// Example usage of IntelligentReplicator
func main() {
	replicator := NewIntelligentReplicator()
	replicator.NodeReliabilityMap["node1"] = 0.9
	replicator.NodeReliabilityMap["node2"] = 0.85
	replicator.DataReplicationMap["data1"] = 3

	// Simulate periodic adjustments
	for i := 0; i < 10; i++ {
		err := replicator.AdjustReplicationFactors()
		if err != nil {
			fmt.Println("Error adjusting replication factors:", err)
			return
		}
		replicator.simulateDataChanges()
		time.Sleep(1 * time.Second)
	}
}

