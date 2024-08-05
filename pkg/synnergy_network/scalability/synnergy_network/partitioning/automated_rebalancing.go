package partitioning

import (
	"errors"
	"fmt"
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

// Rebalancer manages the rebalancing of nodes across partitions.
type Rebalancer struct {
	partitions map[string]*Partition
	nodes      map[string]*Node
	mu         sync.RWMutex
}

// NewRebalancer initializes a new Rebalancer.
func NewRebalancer() *Rebalancer {
	return &Rebalancer{
		partitions: make(map[string]*Partition),
		nodes:      make(map[string]*Node),
	}
}

// AddPartition adds a new partition to the rebalancer.
func (r *Rebalancer) AddPartition(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.partitions[id] = &Partition{ID: id, Nodes: []Node{}, Load: 0}
}

// RemovePartition removes a partition from the rebalancer.
func (r *Rebalancer) RemovePartition(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.partitions[id]; !exists {
		return errors.New("partition not found")
	}

	delete(r.partitions, id)
	return nil
}

// AddNode adds a new node to the rebalancer and assigns it to the least loaded partition.
func (r *Rebalancer) AddNode(id string, load float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	node := &Node{ID: id, Load: load}
	r.nodes[id] = node

	r.assignNodeToPartition(node)
}

// RemoveNode removes a node from the rebalancer.
func (r *Rebalancer) RemoveNode(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, exists := r.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	partition := r.partitions[node.Partition]
	for i, n := range partition.Nodes {
		if n.ID == id {
			partition.Nodes = append(partition.Nodes[:i], partition.Nodes[i+1:]...)
			break
		}
	}
	partition.Load -= node.Load

	delete(r.nodes, id)
	return nil
}

// Rebalance initiates the rebalancing process.
func (r *Rebalancer) Rebalance() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, partition := range r.partitions {
		for i := len(partition.Nodes) - 1; i >= 0; i-- {
			node := &partition.Nodes[i]
			r.reassignNode(node)
		}
	}
}

// MonitorAndRebalance monitors the load and periodically triggers rebalancing.
func (r *Rebalancer) MonitorAndRebalance(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.Rebalance()
		}
	}
}

// assignNodeToPartition assigns a node to the least loaded partition.
func (r *Rebalancer) assignNodeToPartition(node *Node) {
	var minLoadPartition *Partition
	for _, partition := range r.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// reassignNode reassigns a node to the most appropriate partition based on load.
func (r *Rebalancer) reassignNode(node *Node) {
	oldPartition := r.partitions[node.Partition]
	oldPartition.Load -= node.Load

	var minLoadPartition *Partition
	for _, partition := range r.partitions {
		if minLoadPartition == nil || partition.Load < minLoadPartition.Load {
			minLoadPartition = partition
		}
	}

	node.Partition = minLoadPartition.ID
	minLoadPartition.Nodes = append(minLoadPartition.Nodes, *node)
	minLoadPartition.Load += node.Load
}

// GetPartitionLoad returns the load of a specific partition.
func (r *Rebalancer) GetPartitionLoad(id string) (float64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	partition, exists := r.partitions[id]
	if !exists {
		return 0, errors.New("partition not found")
	}

	return partition.Load, nil
}

// GetNodePartition returns the partition ID of a specific node.
func (r *Rebalancer) GetNodePartition(id string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	node, exists := r.nodes[id]
	if !exists {
		return "", errors.New("node not found")
	}

	return node.Partition, nil
}

// BalanceFactor calculates the balance factor of the rebalancer.
func (r *Rebalancer) BalanceFactor() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var totalLoad float64
	var loadSquareSum float64
	var partitionCount float64

	for _, partition := range r.partitions {
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
func (r *Rebalancer) printState() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fmt.Println("Current state of partitions and nodes:")
	for _, partition := range r.partitions {
		fmt.Printf("Partition %s: Load %.2f\n", partition.ID, partition.Load)
		for _, node := range partition.Nodes {
			fmt.Printf("  Node %s: Load %.2f\n", node.ID, node.Load)
		}
	}
}
