package distribution

import (
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/cortexlabs/cortex/pkg/lib/maths"
)

// PredictiveLoadManager manages the prediction and adjustment of load across nodes.
type PredictiveLoadManager struct {
	Nodes       []Node
	loadHistory map[string][]int // Historical load data for each node
	lock        sync.Mutex
}

// NewPredictiveLoadManager initializes a new PredictiveLoadManager with node setup.
func NewPredictiveLoadManager(nodes []Node) *PredictiveLoadManager {
	plm := &PredictiveLoadManager{
		Nodes:       nodes,
		loadHistory: make(map[string][]int),
	}
	for _, node := range nodes {
		plm.loadHistory[node.ID] = make([]int, 0)
	}
	return plm
}

// UpdateLoadHistory updates the load history for each node with the current load.
func (plm *PredictiveLoadManager) UpdateLoadHistory() {
	plm.lock.Lock()
	defer plm.lock.Unlock()

	for i, node := range plm.Nodes {
		plm.loadHistory[node.ID] = append(plm.loadHistory[node.ID], node.CurrentLoad)
		if len(plm.loadHistory[node.ID]) > 100 { // Keep only the most recent 100 entries
			plm.loadHistory[node.ID] = plm.loadHistory[node.ID][1:]
		}
	}
}

// PredictAndManageLoad uses historical data to predict future load and manage resource allocation proactively.
func (plm *PredictiveLoadManager) PredictAndManageLoad() {
	plm.lock.Lock()
	defer plm.lock.Unlock()

	for i, node := range plm.Nodes {
		if len(plm.loadHistory[node.ID]) < 10 {
			continue // Need at least 10 data points to predict
		}

		// Simple moving average prediction for demonstration; replace with more sophisticated ML model
		predictedLoad := maths.MeanInt(plm.loadHistory[node.ID])
		if predictedLoad > int(float64(node.Capacity)*0.8) { // Threshold of 80%
			log.Printf("Node %s is predicted to be overloaded. Current Load: %d, Predicted Load: %d\n", node.ID, node.CurrentLoad, predictedLoad)
			// Implement load redistribution logic
			plm.redistributeLoad(node.ID)
		}
	}
}

// redistributeLoad redistributes load from an overloaded node to less loaded nodes.
func (plm *PredictiveLoadManager) redistributeLoad(overloadedNodeID string) {
	// Find node with minimum load to transfer tasks
	var minLoadNode *Node
	minLoad := 1000000 // Arbitrary large number
	for i := range plm.Nodes {
		if plm.Nodes[i].ID != overloadedNodeID && plm.Nodes[i].CurrentLoad < minLoad {
			minLoad = plm.Nodes[i].CurrentLoad
			minLoadNode = &plm.Nodes[i]
		}
	}

	if minLoadNode != nil {
		// Example of redistributing a single unit of load
		for idx := range plm.Nodes {
			if plm.Nodes[idx].ID == overloadedNodeID {
				plm.Nodes[idx].CurrentLoad--
			}
		}
		minLoadNode.CurrentLoad++
		log.Printf("Load redistributed from Node %s to Node %s", overloadedNodeID, minLoadNode.ID)
	}
}

func main() {
	nodes := []Node{
		{ID: "Node1", Capacity: 100, CurrentLoad: 10},
		{ID: "Node2", Capacity: 150, CurrentLoad: 20},
	}

	plm := NewPredictiveLoadManager(nodes)
	go func() {
		for {
			plm.UpdateLoadHistory()
			plm.PredictAndManageLoad()
			time.Sleep(1 * time.Minute) // Adjust the cycle time as necessary
		}
	}()

	// Simulate random load changes
	for i := 0; i < 100; i++ {
		nodeIndex := rand.Intn(len(nodes))
		nodes[nodeIndex].CurrentLoad += rand.Intn(10) - 5 // Random increase or decrease in load
		time.Sleep(10 * time.Second)
	}
}
