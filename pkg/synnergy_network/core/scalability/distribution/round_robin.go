package distribution

import (
	"sync"
	"sync/atomic"
)

// Node represents a single node in the blockchain network, capable of handling tasks.
type Node struct {
	ID       string
	Capacity int32 // The maximum number of tasks the node can handle concurrently.
}

// RoundRobinBalancer manages the task distribution across multiple nodes using a round-robin approach.
type RoundRobinBalancer struct {
	Nodes []Node
	index uint64
	lock  sync.Mutex
}

// NewRoundRobinBalancer initializes a new RoundRobinBalancer with given nodes.
func NewRoundRobinBalancer(nodes []Node) *RoundRobinBalancer {
	return &RoundRobinBalancer{
		Nodes: nodes,
		index: 0,
	}
}

// getNextIndex provides a thread-safe way to get the next index for round-robin scheduling.
func (rr *RoundRobinBalancer) getNextIndex() int {
	return int(atomic.AddUint64(&rr.index, 1) % uint64(len(rr.Nodes)))
}

// AssignTask attempts to assign a task to a node based on round-robin scheduling.
func (rr *RoundRobinBalancer) AssignTask(taskID string) bool {
	rr.lock.Lock()
	defer rr.lock.Unlock()

	// Attempt to find a node with available capacity
	for i := 0; i < len(rr.Nodes); i++ {
		idx := rr.getNextIndex()
		node := &rr.Nodes[idx]
		if atomic.LoadInt32(&node.Capacity) > 0 {
			atomic.AddInt32(&node.Capacity, -1)
			// Log the task assignment (or more sophisticated task handling)
			go rr.handleTask(node, taskID)
			return true
		}
	}
	return false // No available node with capacity found
}

// handleTask simulates task processing on a node.
func (rr *RoundRobinBalancer) handleTask(node *Node, taskID string) {
	// Simulate task processing
	// Process task here...

	// After processing, free up capacity
	atomic.AddInt32(&node.Capacity, 1)
}

func main() {
	nodes := []Node{
		{ID: "Node1", Capacity: 10},
		{ID: "Node2", Capacity: 15},
		{ID: "Node3", Capacity: 20},
	}

	rr := NewRoundRobinBalancer(nodes)
	// Example of assigning 100 tasks
	for i := 0; i < 100; i++ {
		taskAssigned := rr.AssignTask("Task" + string(i))
		if !taskAssigned {
			// Handle case where no nodes have available capacity
		}
	}
}
