package partitioning

import (
	"errors"
	"math"
	"sync"
	"time"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID        string
	Load      float64
	Partition string
}

// Partition represents a partition in the blockchain network.
type Partition struct {
	ID    string
	Nodes []Node
	Load  float64
}

// DynamicPartitioner manages dynamic partitioning of nodes across partitions.
type DynamicPartitioner struct {
	partitions map[string]*Partition
	nodes      map[string]*Node
	mu         sync.RWMutex
}

// NewDynamicPartitioner initializes a new DynamicPartitioner.
func NewDynamicPartitioner() *DynamicPartitioner {
	return &DynamicPartitioner{
		partitions: make(map[string]*Partition),
		nodes:      make(map[string]*Node),
	}
}

// AddPartition adds a new partition to the partitioner.
func (dp *DynamicPartitioner) AddPartition(id string) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	dp.partitions[id] = &Partition{ID: id, Nodes: []Node{}, Load: 0}
}

// RemovePartition removes a partition from the partitioner.
func (dp *DynamicPartitioner) RemovePartition(id string) error {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if _, exists := dp.partitions[id]; !exists {
		return errors.New("partition not found")
	}

	delete(dp.partitions, id)
	return nil
}

// AddNode adds a new node to the partitioner and assigns it to the least loaded partition.
func (dp *DynamicPartitioner) AddNode(id string, load float64) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	node := &Node{ID: id, Load: load}
	dp.nodes[id] = node

	dp.assignNodeToPartition(node)
}

// RemoveNode removes a node from the partitioner.
func (dp *DynamicPartitioner) RemoveNode(id string) error {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	node, exists := dp.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	partition := dp.partitions[node.Partition]
	for i, n := range partition.Nodes {
		if n.ID == id {
			partition.Nodes = append(partition.Nodes[:i], partition.Nodes[i+1:]...)
			break
		}
	}
	partition.Load -= node.Load

	delete(dp.nodes, id)
	return nil
}

// Rebalance initiates the rebalancing process.
func (dp *DynamicPartitioner) Rebalance() {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	for _, partition := range dp.partitions {
		for i := len(partition.Nodes) - 1; i >= 0; i-- {
			node := &partition.Nodes[i]
			dp.reassignNode(node)
		}
	}
}

// MonitorAndRebalance monitors the load and periodically triggers rebalancing.
func (dp *DynamicPartitioner) MonitorAndRebalance(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dp.Rebalance()
		}
	}
}

// assignNodeToPartition assigns a node to the least loaded partition.
func (dp *DynamicPartitioner) assignNodeToPartition(node *Node) {
	var minLoadPartition *Partition
	for _, partition := range dp.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// reassignNode reassigns a node to the most appropriate partition based on load.
func (dp *DynamicPartitioner) reassignNode(node *Node) {
	oldPartition := dp.partitions[node.Partition]
	oldPartition.Load -= node.Load

	var minLoadPartition *Partition
	for _, partition := range dp.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// GetPartitionLoad returns the load of a specific partition.
func (dp *DynamicPartitioner) GetPartitionLoad(id string) (float64, error) {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	partition, exists := dp.partitions[id]
	if !exists {
		return 0, errors.New("partition not found")
	}

	return partition.Load, nil
}

// GetNodePartition returns the partition ID of a specific node.
func (dp *DynamicPartitioner) GetNodePartition(id string) (string, error) {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	node, exists := dp.nodes[id]
	if !exists {
		return "", errors.New("node not found")
	}

	return node.Partition, nil
}

// BalanceFactor calculates the balance factor of the partitioner.
func (dp *DynamicPartitioner) BalanceFactor() float64 {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	var totalLoad float64
	var loadSquareSum float64
	var partitionCount float64

	for _, partition := range dp.partitions {
		totalLoad += partition.Load
		loadSquareSum += partition.Load * partition.Load
		partitionCount++
	}

	if partitionCount == 0 {
		return 0
	}

	averageLoad := totalLoad / partitionCount
	variance := loadSquareSum/partitionCount - averageLoad*averageLoad
	return math.Sqrt(variance) / averageLoad
}

// printState prints the current state of partitions and nodes for debugging.
func (dp *DynamicPartitioner) printState() {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	fmt.Println("Current state of partitions and nodes:")
	for _, partition := range dp.partitions {
		fmt.Printf("Partition %s: Load %.2f\n", partition.ID, partition.Load)
		for _, node := range partition.Nodes {
			fmt.Printf("  Node %s: Load %.2f\n", node.ID, node.Load)
		}
	}
}
