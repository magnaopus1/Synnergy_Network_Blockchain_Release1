package partitioning

import (
	"errors"
	"math"
	"sync"
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

// HorizontalPartitioner manages horizontal partitioning of nodes across partitions.
type HorizontalPartitioner struct {
	partitions map[string]*Partition
	nodes      map[string]*Node
	mu         sync.RWMutex
}

// NewHorizontalPartitioner initializes a new HorizontalPartitioner.
func NewHorizontalPartitioner() *HorizontalPartitioner {
	return &HorizontalPartitioner{
		partitions: make(map[string]*Partition),
		nodes:      make(map[string]*Node),
	}
}

// AddPartition adds a new partition to the partitioner.
func (hp *HorizontalPartitioner) AddPartition(id string) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.partitions[id] = &Partition{ID: id, Nodes: []Node{}, Load: 0}
}

// RemovePartition removes a partition from the partitioner.
func (hp *HorizontalPartitioner) RemovePartition(id string) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if _, exists := hp.partitions[id]; !exists {
		return errors.New("partition not found")
	}

	delete(hp.partitions, id)
	return nil
}

// AddNode adds a new node to the partitioner and assigns it to the least loaded partition.
func (hp *HorizontalPartitioner) AddNode(id string, load float64) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	node := &Node{ID: id, Load: load}
	hp.nodes[id] = node

	hp.assignNodeToPartition(node)
}

// RemoveNode removes a node from the partitioner.
func (hp *HorizontalPartitioner) RemoveNode(id string) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	node, exists := hp.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	partition := hp.partitions[node.Partition]
	for i, n := range partition.Nodes {
		if n.ID == id {
			partition.Nodes = append(partition.Nodes[:i], partition.Nodes[i+1:]...)
			break
		}
	}
	partition.Load -= node.Load

	delete(hp.nodes, id)
	return nil
}

// Rebalance initiates the rebalancing process.
func (hp *HorizontalPartitioner) Rebalance() {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	for _, partition := range hp.partitions {
		for i := len(partition.Nodes) - 1; i >= 0; i-- {
			node := &partition.Nodes[i]
			hp.reassignNode(node)
		}
	}
}

// assignNodeToPartition assigns a node to the least loaded partition.
func (hp *HorizontalPartitioner) assignNodeToPartition(node *Node) {
	var minLoadPartition *Partition
	for _, partition := range hp.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// reassignNode reassigns a node to the most appropriate partition based on load.
func (hp *HorizontalPartitioner) reassignNode(node *Node) {
	oldPartition := hp.partitions[node.Partition]
	oldPartition.Load -= node.Load

	var minLoadPartition *Partition
	for _, partition := range hp.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// GetPartitionLoad returns the load of a specific partition.
func (hp *HorizontalPartitioner) GetPartitionLoad(id string) (float64, error) {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	partition, exists := hp.partitions[id]
	if !exists {
		return 0, errors.New("partition not found")
	}

	return partition.Load, nil
}

// GetNodePartition returns the partition ID of a specific node.
func (hp *HorizontalPartitioner) GetNodePartition(id string) (string, error) {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	node, exists := hp.nodes[id]
	if !exists {
		return "", errors.New("node not found")
	}

	return node.Partition, nil
}

// BalanceFactor calculates the balance factor of the partitioner.
func (hp *HorizontalPartitioner) BalanceFactor() float64 {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	var totalLoad float64
	var loadSquareSum float64
	var partitionCount float64

	for _, partition := range hp.partitions {
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
func (hp *HorizontalPartitioner) printState() {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	fmt.Println("Current state of partitions and nodes:")
	for _, partition := range hp.partitions {
		fmt.Printf("Partition %s: Load %.2f\n", partition.ID, partition.Load)
		for _, node := range partition.Nodes {
			fmt.Printf("  Node %s: Load %.2f\n", node.ID, node.Load)
		}
	}
}

// Helper function to validate the state of the partitioning system
func (hp *HorizontalPartitioner) validateState() error {
	hp.mu.RLock()
	defer hp.mu.RUnlock()

	for _, partition := range hp.partitions {
		if partition.Load < 0 {
			return errors.New("partition load cannot be negative")
		}
	}

	return nil
}
