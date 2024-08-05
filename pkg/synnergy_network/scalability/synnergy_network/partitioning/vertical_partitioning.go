package partitioning

import (
	"errors"
	"fmt"
	"sync"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID         string
	DataFields map[string]interface{}
	Partition  string
}

// Partition represents a vertical partition in the blockchain network.
type Partition struct {
	ID         string
	DataFields map[string]struct{}
	Nodes      []Node
}

// VerticalPartitioner manages vertical partitioning of nodes across partitions.
type VerticalPartitioner struct {
	partitions map[string]*Partition
	nodes      map[string]*Node
	mu         sync.RWMutex
}

// NewVerticalPartitioner initializes a new VerticalPartitioner.
func NewVerticalPartitioner() *VerticalPartitioner {
	return &VerticalPartitioner{
		partitions: make(map[string]*Partition),
		nodes:      make(map[string]*Node),
	}
}

// AddPartition adds a new partition to the partitioner.
func (vp *VerticalPartitioner) AddPartition(id string, dataFields []string) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	dfMap := make(map[string]struct{})
	for _, field := range dataFields {
		dfMap[field] = struct{}{}
	}

	vp.partitions[id] = &Partition{ID: id, DataFields: dfMap, Nodes: []Node{}}
}

// RemovePartition removes a partition from the partitioner.
func (vp *VerticalPartitioner) RemovePartition(id string) error {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if _, exists := vp.partitions[id]; !exists {
		return errors.New("partition not found")
	}

	delete(vp.partitions, id)
	return nil
}

// AddNode adds a new node to the partitioner and assigns it to the appropriate partition based on data fields.
func (vp *VerticalPartitioner) AddNode(id string, dataFields map[string]interface{}) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	node := &Node{ID: id, DataFields: dataFields}
	vp.nodes[id] = node

	vp.assignNodeToPartition(node)
}

// RemoveNode removes a node from the partitioner.
func (vp *VerticalPartitioner) RemoveNode(id string) error {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	node, exists := vp.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	partition := vp.partitions[node.Partition]
	for i, n := range partition.Nodes {
		if n.ID == id {
			partition.Nodes = append(partition.Nodes[:i], partition.Nodes[i+1:]...)
			break
		}
	}

	delete(vp.nodes, id)
	return nil
}

// Rebalance initiates the rebalancing process.
func (vp *VerticalPartitioner) Rebalance() {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	for _, partition := range vp.partitions {
		for i := len(partition.Nodes) - 1; i >= 0; i-- {
			node := &partition.Nodes[i]
			vp.reassignNode(node)
		}
	}
}

// assignNodeToPartition assigns a node to the appropriate partition based on data fields.
func (vp *VerticalPartitioner) assignNodeToPartition(node *Node) {
	var bestPartition *Partition
	bestMatchCount := 0

	for _, partition := range vp.partitions {
		matchCount := 0
		for field := range node.DataFields {
			if _, exists := partition.DataFields[field]; exists {
				matchCount++
			}
		}
		if matchCount > bestMatchCount {
			bestMatchCount = matchCount
			bestPartition = partition
		}
	}

	if bestPartition != nil {
		node.Partition = bestPartition.ID
		bestPartition.Nodes = append(bestPartition.Nodes, *node)
	}
}

// reassignNode reassigns a node to the most appropriate partition based on data fields.
func (vp *VerticalPartitioner) reassignNode(node *Node) {
	oldPartition := vp.partitions[node.Partition]
	for i, n := range oldPartition.Nodes {
		if n.ID == node.ID {
			oldPartition.Nodes = append(oldPartition.Nodes[:i], oldPartition.Nodes[i+1:]...)
			break
		}
	}

	vp.assignNodeToPartition(node)
}

// GetPartitionNodes returns the nodes of a specific partition.
func (vp *VerticalPartitioner) GetPartitionNodes(id string) ([]Node, error) {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	partition, exists := vp.partitions[id]
	if !exists {
		return nil, errors.New("partition not found")
	}

	return partition.Nodes, nil
}

// GetNodePartition returns the partition ID of a specific node.
func (vp *VerticalPartitioner) GetNodePartition(id string) (string, error) {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	node, exists := vp.nodes[id]
	if !exists {
		return "", errors.New("node not found")
	}

	return node.Partition, nil
}

// printState prints the current state of partitions and nodes for debugging.
func (vp *VerticalPartitioner) printState() {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	fmt.Println("Current state of partitions and nodes:")
	for _, partition := range vp.partitions {
		fmt.Printf("Partition %s:\n", partition.ID)
		for _, node := range partition.Nodes {
			fmt.Printf("  Node %s: DataFields %v\n", node.ID, node.DataFields)
		}
	}
}

// Helper function to validate the state of the partitioning system
func (vp *VerticalPartitioner) validateState() error {
	vp.mu.RLock()
	defer vp.mu.RUnlock()

	for _, partition := range vp.partitions {
		for _, node := range partition.Nodes {
			for field := range node.DataFields {
				if _, exists := partition.DataFields[field]; !exists {
					return errors.New("node has data field not present in partition")
				}
			}
		}
	}

	return nil
}
