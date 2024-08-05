package adaptive

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Node represents a node in the elastic infrastructure.
type Node struct {
	ID       string
	Capacity int
	Load     int
}

// ElasticInfrastructure manages a dynamically scalable set of nodes.
type ElasticInfrastructure struct {
	mu      sync.Mutex
	nodes   map[string]*Node
	maxLoad int
}

// NewElasticInfrastructure initializes a new ElasticInfrastructure instance.
func NewElasticInfrastructure(maxLoad int) *ElasticInfrastructure {
	return &ElasticInfrastructure{
		nodes:   make(map[string]*Node),
		maxLoad: maxLoad,
	}
}

// AddNode adds a new node to the infrastructure.
func (ei *ElasticInfrastructure) AddNode(id string, capacity int) error {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	if _, exists := ei.nodes[id]; exists {
		return errors.New("node already exists")
	}

	ei.nodes[id] = &Node{
		ID:       id,
		Capacity: capacity,
		Load:     0,
	}

	fmt.Printf("Node %s added with capacity %d.\n", id, capacity)
	return nil
}

// RemoveNode removes a node from the infrastructure.
func (ei *ElasticInfrastructure) RemoveNode(id string) error {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	if _, exists := ei.nodes[id]; !exists {
		return errors.New("node not found")
	}

	delete(ei.nodes, id)
	fmt.Printf("Node %s removed.\n", id)
	return nil
}

// GetNode retrieves a node by its ID.
func (ei *ElasticInfrastructure) GetNode(id string) (*Node, error) {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	node, exists := ei.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}

	return node, nil
}

// ListNodes lists all nodes in the infrastructure.
func (ei *ElasticInfrastructure) ListNodes() []*Node {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	nodes := []*Node{}
	for _, node := range ei.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// AllocateLoad allocates a specified load to a node, scaling if necessary.
func (ei *ElasticInfrastructure) AllocateLoad(load int) error {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	node, err := ei.findNodeWithCapacity(load)
	if err != nil {
		return ei.scaleUp(load)
	}

	node.Load += load
	fmt.Printf("Allocated %d load to node %s. Current load: %d/%d.\n", load, node.ID, node.Load, node.Capacity)
	return nil
}

// DeallocateLoad deallocates a specified load from a node.
func (ei *ElasticInfrastructure) DeallocateLoad(id string, load int) error {
	ei.mu.Lock()
	defer ei.mu.Unlock()

	node, exists := ei.nodes[id]
	if !exists {
		return errors.New("node not found")
	}

	if node.Load < load {
		return errors.New("insufficient load to deallocate")
	}

	node.Load -= load
	fmt.Printf("Deallocated %d load from node %s. Current load: %d/%d.\n", load, node.ID, node.Load, node.Capacity)
	return nil
}

// findNodeWithCapacity finds a node with sufficient capacity for the given load.
func (ei *ElasticInfrastructure) findNodeWithCapacity(load int) (*Node, error) {
	for _, node := range ei.nodes {
		if node.Capacity-node.Load >= load {
			return node, nil
		}
	}
	return nil, errors.New("no node with sufficient capacity found")
}

// scaleUp scales up the infrastructure by adding a new node to accommodate the load.
func (ei *ElasticInfrastructure) scaleUp(load int) error {
	newNodeID := fmt.Sprintf("node-%d", len(ei.nodes)+1)
	newNodeCapacity := ei.maxLoad

	err := ei.AddNode(newNodeID, newNodeCapacity)
	if err != nil {
		return err
	}

	node, err := ei.GetNode(newNodeID)
	if err != nil {
		return err
	}

	node.Load += load
	fmt.Printf("Scaled up and allocated %d load to new node %s. Current load: %d/%d.\n", load, node.ID, node.Load, node.Capacity)
	return nil
}

// MonitorLoad continuously monitors the load and scales the infrastructure as needed.
func (ei *ElasticInfrastructure) MonitorLoad(interval time.Duration) {
	for {
		ei.mu.Lock()
		totalLoad := 0
		totalCapacity := 0

		for _, node := range ei.nodes {
			totalLoad += node.Load
			totalCapacity += node.Capacity
		}

		if totalLoad > totalCapacity {
			fmt.Println("Total load exceeds capacity. Scaling up...")
			ei.scaleUp(totalLoad - totalCapacity)
		} else if totalCapacity-totalLoad > ei.maxLoad {
			fmt.Println("Total capacity significantly exceeds load. Scaling down...")
			ei.scaleDown()
		}

		ei.mu.Unlock()
		time.Sleep(interval)
	}
}

// scaleDown scales down the infrastructure by removing underutilized nodes.
func (ei *ElasticInfrastructure) scaleDown() {
	for id, node := range ei.nodes {
		if node.Load == 0 {
			ei.RemoveNode(id)
			fmt.Printf("Node %s removed due to underutilization.\n", id)
			return
		}
	}
}
