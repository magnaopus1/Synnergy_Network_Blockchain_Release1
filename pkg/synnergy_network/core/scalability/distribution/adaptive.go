package distribution

import (
	"log"
	"sync"
	"time"
	"math/rand"
)

// Node represents a single node in the blockchain network with its capacity and other performance metrics.
type Node struct {
	ID          string
	Capacity    int
	CurrentLoad int
	HealthScore float64 // Represents node's health based on error rates, response times, etc.
}

// LoadBalancer manages the distribution of load across multiple nodes, including advanced predictive and adaptive strategies.
type LoadBalancer struct {
	Nodes      []Node
	lock       sync.Mutex
	loadFactor map[string]float64
}

// NewLoadBalancer initializes a new LoadBalancer with predefined nodes.
func NewLoadBalancer(nodes []Node) *LoadBalancer {
	lb := &LoadBalancer{
		Nodes:      nodes,
		loadFactor: make(map[string]float64),
	}
	lb.calculateLoadFactor()
	return lb
}

// calculateLoadFactor updates the load factor for each node based on its capacity, current load, and health score.
func (lb *LoadBalancer) calculateLoadFactor() {
	lb.lock.Lock()
	defer lb.lock.Unlock()
	totalCapacity := 0
	for _, node := range lb.Nodes {
		totalCapacity += node.Capacity
	}

	for i := range lb.Nodes {
		if lb.Nodes[i].Capacity > 0 {
			loadRatio := float64(lb.Nodes[i].CurrentLoad) / float64(lb.Nodes[i].Capacity)
			healthAdjustment := 1 - lb.Nodes[i].HealthScore // Assuming HealthScore is 0 (worst) to 1 (best)
			lb.loadFactor[lb.Nodes[i].ID] = loadRatio * (1 + healthAdjustment)
		}
	}
}

// AssignTask distributes tasks to nodes based on their calculated load factor, ensuring a balanced workload.
func (lb *LoadBalancer) AssignTask(taskID string) {
	lb.lock.Lock()
	defer lb.lock.Unlock()

	minLoadNode := lb.selectNodeForAssignment()
	if minLoadNode != nil {
		minLoadNode.CurrentLoad++
		log.Printf("Task %s assigned to Node %s", taskID, minLoadNode.ID)
		lb.calculateLoadFactor()
	}
}

// selectNodeForAssignment selects the most suitable node based on the load factor.
func (lb *LoadBalancer) selectNodeForAssignment() *Node {
	var minLoadNode *Node
	minLoadFactor := float64(1.1) // More than the max possible load factor 1.0
	for i := range lb.Nodes {
		if lb.loadFactor[lb.Nodes[i].ID] < minLoadFactor && lb.Nodes[i].HealthScore > 0.5 {
			minLoadNode = &lb.Nodes[i]
			minLoadFactor = lb.loadFactor[lb.Nodes[i].ID]
		}
	}
	return minLoadNode
}

// MonitorAndOptimize continuously optimizes the distribution strategy based on real-time network performance.
func (lb *LoadBalancer) MonitorAndOptimize() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		lb.optimizeLoadDistribution()
		lb.logStatus()
	}
}

// optimizeLoadDistribution dynamically adjusts the nodes' load based on performance metrics.
func (lb *LoadBalancer) optimizeLoadDistribution() {
	lb.calculateLoadFactor()
	log.Println("Load distribution optimized based on current node performance.")
}

// logStatus logs the current status of nodes and their load factors.
func (lb *LoadBalancer) logStatus() {
	lb.lock.Lock()
	defer lb.lock.Unlock()
	for id, load := range lb.loadFactor {
		log.Printf("Node %s: Load Factor: %f", id, load)
	}
}

// PredictiveLoadManagement adjusts system resources in anticipation of load spikes.
func (lb *LoadBalancer) PredictiveLoadManagement() {
	// Implement machine learning or statistical analysis to predict load
	log.Println("Predictive load management not yet implemented.")
}

func main() {
	// Example nodes setup with initial health scores
	nodes := []Node{
		{ID: "Node1", Capacity: 100, CurrentLoad: 10, HealthScore: 0.9},
		{ID: "Node2", Capacity: 150, CurrentLoad: 20, HealthScore: 0.95},
	}

	lb := NewLoadBalancer(nodes)
	go lb.MonitorAndOptimize()

	// Simulate task assignments
	for i := 0; i < 100; i++ {
		lb.AssignTask("Task" + string(rand.Int()))
		time.Sleep(100 * time.Millisecond) // simulate real-world task timing
	}
}
