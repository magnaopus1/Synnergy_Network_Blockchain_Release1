package allocation_algorithms

import (
	"errors"
	"sync"
)

// Node represents a network participant
type Node struct {
	ID     string
	Stake  int
	Weight int
}

// Network represents the entire network state
type Network struct {
	mu     sync.Mutex
	Nodes  map[string]*Node
	TotalStake int
}

// NewNetwork initializes a new Network
func NewNetwork() *Network {
	return &Network{
		Nodes: make(map[string]*Node),
	}
}

// AddNode adds a node to the network with a given stake
func (n *Network) AddNode(id string, stake int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[id] = &Node{
		ID:     id,
		Stake:  stake,
		Weight: 0,
	}
	n.TotalStake += stake
	n.updateWeights()
}

// RemoveNode removes a node from the network
func (n *Network) RemoveNode(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	n.TotalStake -= node.Stake
	delete(n.Nodes, id)
	n.updateWeights()
	return nil
}

// UpdateNodeStake updates the stake of an existing node
func (n *Network) UpdateNodeStake(id string, stake int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	n.TotalStake -= node.Stake
	node.Stake = stake
	n.TotalStake += stake
	n.updateWeights()
	return nil
}

// updateWeights recalculates the weights of all nodes based on their stakes
func (n *Network) updateWeights() {
	for _, node := range n.Nodes {
		node.Weight = n.calculateWeight(node.Stake)
	}
}

// calculateWeight calculates the weight of a node based on its stake
func (n *Network) calculateWeight(stake int) int {
	if n.TotalStake == 0 {
		return 0
	}
	return int(float64(stake) / float64(n.TotalStake) * 100)
}

// GetNodeWeight returns the current weight of a node
func (n *Network) GetNodeWeight(id string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Weight, nil
}

// GetNodeStake returns the current stake of a node
func (n *Network) GetNodeStake(id string) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node, exists := n.Nodes[id]
	if !exists {
		return 0, errors.New("node not found")
	}
	return node.Stake, nil
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

// AllocateResources allocates resources to nodes based on their weights
func (n *Network) AllocateResources(totalResources int) map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	allocation := make(map[string]int)
	for id, node := range n.Nodes {
		allocation[id] = int(float64(node.Weight) / 100 * float64(totalResources))
	}
	return allocation
}
