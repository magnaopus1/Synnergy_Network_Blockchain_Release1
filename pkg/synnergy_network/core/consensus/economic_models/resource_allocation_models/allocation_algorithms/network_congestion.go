package allocation_algorithms

import (
	"errors"
	"sync"
)

// Node represents a node in the network
type Node struct {
	ID       string
	Capacity int
	Load     int
}

// Network represents the entire network state
type Network struct {
	mu     sync.Mutex
	Nodes  map[string]*Node
	Active int
	TotalTransactions int
}

// NewNetwork initializes a new Network
func NewNetwork() *Network {
	return &Network{
		Nodes: make(map[string]*Node),
	}
}

// AddNode adds a node to the network
func (n *Network) AddNode(id string, capacity int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[id] = &Node{
		ID:       id,
		Capacity: capacity,
		Load:     0,
	}
	n.Active++
}

// RemoveNode removes a node from the network
func (n *Network) RemoveNode(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.Nodes[id]; !exists {
		return errors.New("node not found")
	}
	delete(n.Nodes, id)
	n.Active--
	return nil
}

// IncrementTransaction increments the total transaction count and updates node loads
func (n *Network) IncrementTransaction(nodeID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}
	node.Load++
	n.TotalTransactions++
	return nil
}

// CalculateCongestion calculates the network congestion level
func (n *Network) CalculateCongestion() float64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Active == 0 {
		return 0
	}
	return float64(n.TotalTransactions) / float64(n.Active)
}

// AdjustAllocation adjusts the allocation based on network congestion
func (n *Network) AdjustAllocation() (map[string]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Active == 0 {
		return nil, errors.New("no active nodes")
	}

	congestionLevel := n.CalculateCongestion()
	allocation := make(map[string]int)

	for id, node := range n.Nodes {
		if node.Capacity == 0 {
			return nil, errors.New("node capacity cannot be zero")
		}
		adjustment := int(float64(node.Capacity) * (1.0 - (congestionLevel / float64(node.Capacity))))
		if adjustment < 0 {
			adjustment = 0
		}
		allocation[id] = adjustment
	}

	return allocation, nil
}

// GetNodeLoad returns the current load of a node
func (n *Network) GetNodeLoad(nodeID string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[nodeID]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Load, nil
}

// ListNodes lists all nodes in the network
func (n *Network) ListNodes() []*Node {
	n.mu.Lock()
	defer n.mu.Unlock()
	nodes := []*Node{}
	for _, node := range n.Nodes {
		nodes = append(nodes, node)
	}
	return nodes
}
