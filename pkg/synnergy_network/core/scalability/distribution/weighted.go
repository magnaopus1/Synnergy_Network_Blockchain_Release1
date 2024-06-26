package distribution

import (
	"sync"
	"sync/atomic"
	"math/rand"
	"time"
)

// Node represents a single node in the blockchain network with specific capabilities.
type Node struct {
	ID          string
	Capacity    int32 // Total capacity of the node to handle tasks
	CurrentLoad int32 // Current number of tasks the node is handling
}

// WeightedBalancer manages the distribution of tasks across nodes based on their weight.
type WeightedBalancer struct {
	Nodes []Node
	mutex sync.Mutex
}

// NewWeightedBalancer initializes a WeightedBalancer with a list of nodes.
func NewWeightedBalancer(nodes []Node) *WeightedBalancer {
	return &WeightedBalancer{
		Nodes: nodes,
	}
}

// AssignTask distributes a task to a node based on weighted load balancing.
func (wb *WeightedBalancer) AssignTask(taskID string) {
	wb.mutex.Lock()
	defer wb.mutex.Unlock()

	// Calculate total weight
	var totalWeight int32
	for _, node := range wb.Nodes {
		totalWeight += node.Capacity - atomic.LoadInt32(&node.CurrentLoad)
	}

	if totalWeight > 0 {
		// Determine which node to assign the task based on weight
		randWeight := rand.Int31n(totalWeight)
		for i, node := range wb.Nodes {
			nodeWeight := node.Capacity - atomic.LoadInt32(&node.CurrentLoad)
			if randWeight < nodeWeight {
				// Assign the task to the node
				atomic.AddInt32(&wb.Nodes[i].CurrentLoad, 1)
				go wb.processTask(&wb.Nodes[i], taskID)
				break
			}
			randWeight -= nodeWeight
		}
	} else {
		// Handle the scenario where no nodes have available capacity
		// Possibly queue the task or reject it based on your system's requirements
	}
}

// processTask simulates task processing on the node.
func (wb *WeightedBalancer) processTask(node *Node, taskID string) {
	// Task processing logic here
	time.Sleep(10 * time.Millisecond) // Simulate task duration

	// Once done, decrease the load
	atomic.AddInt32(&node.CurrentLoad, -1)
}

// PredictiveLoadAdjustment uses predictive analytics to adjust node weights before peak periods.
func (wb *WeightedBalancer) PredictiveLoadAdjustment() {
	// Implement logic to predict load and adjust node capacities or weights preemptively
}

func main() {
	nodes := []Node{
		{ID: "Node1", Capacity: 100},
		{ID: "Node2", Capacity: 150},
	}

	wb := NewWeightedBalancer(nodes)
	// Simulating task assignment
	for i := 0; i < 1000; i++ {
		wb.AssignTask("Task" + string(i))
	}
}
