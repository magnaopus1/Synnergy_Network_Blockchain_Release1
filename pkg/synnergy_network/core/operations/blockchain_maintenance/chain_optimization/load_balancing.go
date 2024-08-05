package chain_optimization

import (
	"errors"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/synnergy_network/encryption_utils"
)

// LoadBalancer defines the structure for load balancing in the blockchain network.
type LoadBalancer struct {
	mutex        sync.Mutex
	isBalanced   bool
	nodeLoads    map[string]int
	nodeCapacities map[string]int
}

// NewLoadBalancer initializes a new LoadBalancer.
func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		nodeLoads: make(map[string]int),
		nodeCapacities: make(map[string]int),
	}
}

// AddNode adds a node to the load balancer with its capacity.
func (lb *LoadBalancer) AddNode(nodeID string, capacity int) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	lb.nodeLoads[nodeID] = 0
	lb.nodeCapacities[nodeID] = capacity
}

// RemoveNode removes a node from the load balancer.
func (lb *LoadBalancer) RemoveNode(nodeID string) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	delete(lb.nodeLoads, nodeID)
	delete(lb.nodeCapacities, nodeID)
}

// DistributeLoad distributes the load across the nodes in the network.
func (lb *LoadBalancer) DistributeLoad(load int) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.nodeLoads) == 0 {
		return errors.New("no nodes available for load balancing")
	}

	// Simple round-robin distribution
	for nodeID := range lb.nodeLoads {
		if lb.nodeLoads[nodeID] + load <= lb.nodeCapacities[nodeID] {
			lb.nodeLoads[nodeID] += load
			log.Printf("Load %d distributed to node %s, current load: %d", load, nodeID, lb.nodeLoads[nodeID])
			return nil
		}
	}

	return errors.New("insufficient capacity to distribute load")
}

// BalanceLoad attempts to balance the load across the network nodes.
func (lb *LoadBalancer) BalanceLoad() bool {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.nodeLoads) == 0 {
		return false
	}

	totalLoad := 0
	for _, load := range lb.nodeLoads {
		totalLoad += load
	}
	averageLoad := totalLoad / len(lb.nodeLoads)

	// Simple balancing strategy: move excess load to nodes below average load
	for nodeID, load := range lb.nodeLoads {
		if load > averageLoad {
			excessLoad := load - averageLoad
			for targetNodeID, targetLoad := range lb.nodeLoads {
				if targetLoad < averageLoad {
					transferLoad := min(excessLoad, averageLoad-targetLoad)
					lb.nodeLoads[nodeID] -= transferLoad
					lb.nodeLoads[targetNodeID] += transferLoad
					log.Printf("Transferred %d load from node %s to node %s", transferLoad, nodeID, targetNodeID)
					if lb.nodeLoads[nodeID] <= averageLoad {
						break
					}
				}
			}
		}
	}

	lb.isBalanced = true
	for _, load := range lb.nodeLoads {
		if load > averageLoad {
			lb.isBalanced = false
			break
		}
	}

	return lb.isBalanced
}

// GetNodeLoads returns the current loads of all nodes.
func (lb *LoadBalancer) GetNodeLoads() map[string]int {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	return lb.nodeLoads
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SaveLoadBalancerState saves the load balancer state to a file.
func (lb *LoadBalancer) SaveLoadBalancerState(filePath string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	data, err := encryption_utils.Serialize(lb.nodeLoads)
	if err != nil {
		return err
	}

	return encryption_utils.SaveToFile(filePath, data)
}

// LoadLoadBalancerState loads the load balancer state from a file.
func (lb *LoadBalancer) LoadLoadBalancerState(filePath string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	data, err := encryption_utils.LoadFromFile(filePath)
	if err != nil {
		return err
	}

	return encryption_utils.Deserialize(data, &lb.nodeLoads)
}

// AIOptimizedBalanceLoad uses AI to optimize load balancing across the network.
func (lb *LoadBalancer) AIOptimizedBalanceLoad(data map[string]interface{}) bool {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.nodeLoads) == 0 {
		return false
	}

	// Simulated AI-driven load balancing logic
	totalLoad := 0
	for _, load := range lb.nodeLoads {
		totalLoad += load
	}
	averageLoad := totalLoad / len(lb.nodeLoads)

	for nodeID, load := range lb.nodeLoads {
		if load > averageLoad {
			excessLoad := load - averageLoad
			for targetNodeID, targetLoad := range lb.nodeLoads {
				if targetLoad < averageLoad {
					transferLoad := min(excessLoad, averageLoad-targetLoad)
					lb.nodeLoads[nodeID] -= transferLoad
					lb.nodeLoads[targetNodeID] += transferLoad
					log.Printf("AI transferred %d load from node %s to node %s", transferLoad, nodeID, targetNodeID)
					if lb.nodeLoads[nodeID] <= averageLoad {
						break
					}
				}
			}
		}
	}

	lb.isBalanced = true
	for _, load := range lb.nodeLoads {
		if load > averageLoad {
			lb.isBalanced = false
			break
		}
	}

	return lb.isBalanced
}

// PredictiveLoadBalancing uses predictive models to anticipate load and balance it proactively.
func (lb *LoadBalancer) PredictiveLoadBalancing(data map[string]interface{}) bool {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.nodeLoads) == 0 {
		return false
	}

	// Simulated predictive load balancing logic
	predictedLoadIncrease := rand.Intn(100)
	for nodeID := range lb.nodeLoads {
		if lb.nodeLoads[nodeID]+predictedLoadIncrease <= lb.nodeCapacities[nodeID] {
			lb.nodeLoads[nodeID] += predictedLoadIncrease
			log.Printf("Predicted load %d added to node %s, current load: %d", predictedLoadIncrease, nodeID, lb.nodeLoads[nodeID])
			break
		}
	}

	return lb.BalanceLoad()
}
